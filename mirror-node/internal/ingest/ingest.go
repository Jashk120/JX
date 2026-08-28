// Package ingest watches a consensus streams directory and feeds verified
// files into a Store. It is intentionally simple: poll + verify + store.
package ingest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
	"google.golang.org/protobuf/proto"
)

// Config controls the ingester.
type Config struct {
	StreamsDir        string
	PollInterval      time.Duration
	PubKey            ed25519.PublicKey
	TrustedRosterHash []byte
	BlockNodeURL      string
}

// Ingester polls the streams directory and ingests new files. It tracks the
// stream files it has already stored and skips them on later polls, so each
// file is read and verified once regardless of how many ticks it remains in
// the directory.
type Ingester struct {
	cfg   Config
	store store.Store
	log   *slog.Logger

	mu              sync.Mutex
	seenRecords     map[uint64]struct{} // ingested .rsf rounds
	seenEvents      map[uint64]struct{} // ingested .esf indexes
	inFlightRecords map[uint64]struct{} // reserved while a .rsf is being ingested
	inFlightEvents  map[uint64]struct{} // reserved while an .esf is being ingested
	lastRecordEnd   *[32]byte           // last accepted .rsf end hash (M-5)
	lastEventEnd    *[32]byte           // last accepted .esf end hash (M-5)
	expectedPrev    *[32]byte           // expected prev_checkpoint_hash for next record (nil => genesis zeros)

	runMu sync.Mutex // serializes concurrent RunOnce calls
}

func New(cfg Config, st store.Store, log *slog.Logger) *Ingester {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	ing := &Ingester{
		cfg:             cfg,
		store:           st,
		log:             log,
		seenRecords:     make(map[uint64]struct{}),
		seenEvents:      make(map[uint64]struct{}),
		inFlightRecords: make(map[uint64]struct{}),
		inFlightEvents:  make(map[uint64]struct{}),
	}
	ing.seedFromStore()
	return ing
}

func (ing *Ingester) seedFromStore() {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	if len(ing.seenRecords) != 0 {
		return
	}
	if ing.store == nil {
		return
	}
	recs := ing.store.ListRecords()
	if recs == nil {
		return
	}
	var highest *pb.RecordStreamFile
	for _, f := range recs {
		if f == nil {
			continue
		}
		ing.seenRecords[f.Round] = struct{}{}
		if highest == nil || f.Round > highest.Round {
			highest = f
		}
	}
	if highest == nil {
		return
	}
	if end, err := hashFromPB(highest.EndRunningHash); err == nil {
		ing.lastRecordEnd = &end
	}
	if highest.Checkpoint != nil {
		h := stream.CheckpointSigningBytesHash(highest.Checkpoint)
		ing.expectedPrev = &h
	}
}

// RunOnce scans the streams directory and ingests any new files. Already
// ingested files are skipped; a file is only marked ingested after it was
// verified and stored, so files that failed are retried on the next poll.
// Store-level deduplication guards against double ingestion anyway.
//
// RunOnce is serialized with a dedicated mutex so concurrent callers do not
// race between the pre-ingest hasSeen check and the post-store markSeen.
func (ing *Ingester) RunOnce(ctx context.Context) error {
	ing.runMu.Lock()
	defer ing.runMu.Unlock()
	if ing.cfg.BlockNodeURL != "" {
		return ing.runOnceRemote(ctx)
	}
	dir := ing.cfg.StreamsDir

	// Record files.
	rsfPaths, err := stream.ListRecordFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			ing.log.Info("streams dir not yet present", "dir", dir)
			return nil
		}
		return fmt.Errorf("list record files: %w", err)
	}
	for _, p := range rsfPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ing.ingestRecord(p); err != nil {
			ing.log.Warn("record ingest failed", "path", p, "err", err)
		}
	}

	// Event files.
	esfPaths, err := stream.ListEventFiles(dir)
	if err != nil {
		return fmt.Errorf("list event files: %w", err)
	}
	for _, p := range esfPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ing.ingestEvent(p); err != nil {
			ing.log.Warn("event ingest failed", "path", p, "err", err)
		}
	}
	return nil
}

func (ing *Ingester) runOnceRemote(ctx context.Context) error {
	remote := &stream.RemoteSource{BaseURL: ing.cfg.BlockNodeURL}
	names, err := remote.List(ctx)
	if err != nil {
		return fmt.Errorf("list remote blocks: %w", err)
	}
	listed := make(map[string]struct{}, len(names))
	var filtered []string
	for _, n := range names {
		trimmed := strings.TrimSpace(n)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, stream.EventFileSuffix) || strings.HasSuffix(trimmed, stream.RecordFileSuffix) || strings.HasSuffix(trimmed, stream.EventSigSuffix) || strings.HasSuffix(trimmed, stream.RecordSigSuffix) || strings.HasSuffix(trimmed, stream.CkptFileSuffix) || strings.HasSuffix(trimmed, stream.RecordProofSuffix) {
			filtered = append(filtered, trimmed)
			listed[trimmed] = struct{}{}
		}
	}
	type indexed struct {
		index uint64
		name  string
	}
	var recs []indexed
	var evts []indexed
	for _, n := range filtered {
		if idx, ok := stream.RecordFileRound(n); ok {
			recs = append(recs, indexed{idx, n})
			continue
		}
		if idx, ok := stream.EventFileIndex(n); ok {
			evts = append(evts, indexed{idx, n})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].index < recs[j].index })
	sort.Slice(evts, func(i, j int) bool { return evts[i].index < evts[j].index })

	for _, r := range recs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ckptName := stream.CkptFileName(r.index)
		if _, ok := listed[ckptName]; ok {
			ckptBytes, cErr := remote.Fetch(ctx, ckptName)
			if cErr == nil {
				if vErr := stream.VerifyCheckpointFile(ckptBytes, ing.cfg.TrustedRosterHash); vErr != nil {
					ing.log.Warn("ckpt verification failed", "name", ckptName, "err", vErr)
					continue
				}
			}
		}
		if err := ing.ingestRecordRemote(ctx, r.name, listed, remote); err != nil {
			ing.log.Warn("record ingest failed", "name", r.name, "err", err)
		}
	}
	for _, e := range evts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ing.ingestEventRemote(ctx, e.name, listed, remote); err != nil {
			ing.log.Warn("event ingest failed", "name", e.name, "err", err)
		}
	}
	return nil
}

// Run polls until ctx is cancelled.
func (ing *Ingester) Run(ctx context.Context) error {
	ticker := time.NewTicker(ing.cfg.PollInterval)
	defer ticker.Stop()
	if err := ing.RunOnce(ctx); err != nil {
		ing.log.Error("initial ingest failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ing.RunOnce(ctx); err != nil {
				ing.log.Error("ingest tick failed", "err", err)
			}
		}
	}
}

func (ing *Ingester) loadSig(path string) (*pb.SignatureFile, error) {
	sigPath := filepath.Join(filepath.Dir(path), stream.SignatureFileName(filepath.Base(path)))
	sig, err := stream.ReadSignatureFile(sigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sig %s: %w", sigPath, err)
	}
	return sig, nil
}

func hashFromPB(h *pb.HashObject) ([32]byte, error) {
	var out [32]byte
	if h == nil {
		return out, fmt.Errorf("missing running hash")
	}
	if h.Algorithm != 0 || h.Length != 32 || len(h.Hash) != 32 {
		return out, fmt.Errorf("invalid running hash object: algorithm=%d length=%d hashLen=%d", h.Algorithm, h.Length, len(h.Hash))
	}
	copy(out[:], h.Hash)
	return out, nil
}

// checkPrev validates cp's prev_checkpoint_hash commitment against the
// ingester's expected value. A record must carry exactly 32 bytes: the
// genesis round commits [32]byte{} (never an empty slice), and every later
// round must commit SHA256(prev_signing_bytes) of the previously accepted
// checkpoint. With commit=true the expectation is advanced in the same
// critical section, so a concurrent ingest can never observe a torn
// check-then-advance state.
func (ing *Ingester) checkPrev(cp *pb.SignedCheckpoint, commit bool) error {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	var expected [32]byte
	if ing.expectedPrev != nil {
		expected = *ing.expectedPrev
	}
	if len(cp.PrevCheckpointHash) != 32 {
		return fmt.Errorf("prev_checkpoint_hash is %d bytes, want 32 (genesis is 32 zero bytes, not empty)", len(cp.PrevCheckpointHash))
	}
	var got [32]byte
	copy(got[:], cp.PrevCheckpointHash)
	if got != expected {
		return fmt.Errorf("prev_checkpoint_hash mismatch: expected %x got %x", expected, got)
	}
	if commit {
		h := stream.CheckpointSigningBytesHash(cp)
		ing.expectedPrev = &h
	}
	return nil
}

func verifyProofSidecarLocal(dir string, f *pb.RecordStreamFile) error {
	proofPath := filepath.Join(dir, stream.RecordProofFileName(f.Round))
	b, err := os.ReadFile(proofPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read proof sidecar: %w", err)
	}
	return stream.VerifyRecordsProofFileBytes(b, f.Items, f.Checkpoint.RecordsRoot, f.Round)
}

func (ing *Ingester) verifyProofSidecarRemote(ctx context.Context, listed map[string]struct{}, remote *stream.RemoteSource, f *pb.RecordStreamFile) error {
	name := stream.RecordProofFileName(f.Round)
	if _, ok := listed[name]; !ok {
		return nil
	}
	b, err := remote.Fetch(ctx, name)
	if err != nil {
		if errors.Is(err, stream.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("fetch proof sidecar %s: %w", name, err)
	}
	return stream.VerifyRecordsProofFileBytes(b, f.Items, f.Checkpoint.RecordsRoot, f.Round)
}

// markSeen records an ingested stream file by its numeric index. Callers
// must only call it after the file was stored successfully.
func (ing *Ingester) markSeen(seen map[uint64]struct{}, index uint64) {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	seen[index] = struct{}{}
}

// hasSeen reports whether a stream file index was already ingested.
func (ing *Ingester) hasSeen(seen map[uint64]struct{}, index uint64) bool {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	_, ok := seen[index]
	return ok
}

// tryClaim atomically reserves a file index for ingestion. It returns false
// if the file was already seen or is currently in-flight, allowing the
// caller to skip it. A successful claim must be followed by exactly one of
// confirmClaim (on success) or releaseClaim (on failure).
func (ing *Ingester) tryClaim(seen, inFlight map[uint64]struct{}, index uint64) bool {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	if _, ok := seen[index]; ok {
		return false
	}
	if _, ok := inFlight[index]; ok {
		return false
	}
	inFlight[index] = struct{}{}
	return true
}

// confirmClaim moves an in-flight reservation to the seen set.
func (ing *Ingester) confirmClaim(seen, inFlight map[uint64]struct{}, index uint64) {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	delete(inFlight, index)
	seen[index] = struct{}{}
}

// releaseClaim removes an in-flight reservation after a failure so the file
// can be retried on a later poll.
func (ing *Ingester) releaseClaim(inFlight map[uint64]struct{}, index uint64) {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	delete(inFlight, index)
}

func (ing *Ingester) ingestRecord(path string) error {
	index, ok := stream.RecordFileRound(filepath.Base(path))
	if ok {
		if !ing.tryClaim(ing.seenRecords, ing.inFlightRecords, index) {
			return nil
		}
		claimed := true
		succeeded := false
		defer func() {
			if claimed && !succeeded {
				ing.releaseClaim(ing.inFlightRecords, index)
			}
		}()
		f, raw, err := stream.ReadRecordFile(path)
		if err != nil {
			return err
		}
		start, err := hashFromPB(f.StartRunningHash)
		if err != nil {
			return fmt.Errorf("record %s start hash: %w", path, err)
		}
		end, err := hashFromPB(f.EndRunningHash)
		if err != nil {
			return fmt.Errorf("record %s end hash: %w", path, err)
		}
		ing.mu.Lock()
		var expected [32]byte
		hasAnchor := ing.lastRecordEnd != nil
		if !hasAnchor {
			expected = stream.ChainSeed
		} else {
			expected = *ing.lastRecordEnd
		}
		ing.mu.Unlock()
		if start != expected {
			if !hasAnchor {
				return fmt.Errorf("no record chain anchor for %s: start %x has no anchor; start from genesis or restore a store with accepted records", path, start)
			}
			ing.log.Warn("record chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
			return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", path, expected, start)
		}
		if err := stream.VerifyRecordFile(raw, nil, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
			return fmt.Errorf("verify record %s: %w", path, err)
		}
		if f.Checkpoint != nil {
			if err := ing.checkPrev(f.Checkpoint, false); err != nil {
				return fmt.Errorf("prev chain %s: %w", path, err)
			}
		}
		if err := stream.ValidateStateDiffs(f.StateDiffs); err != nil {
			return fmt.Errorf("state_diffs %s: %w", path, err)
		}
		if err := verifyProofSidecarLocal(filepath.Dir(path), f); err != nil {
			return fmt.Errorf("proof sidecar %s: %w", path, err)
		}
		if err := ing.store.PutRecord(f); err != nil {
			return err
		}
		if f.Checkpoint != nil {
			if err := ing.checkPrev(f.Checkpoint, true); err != nil {
				return fmt.Errorf("prev chain %s: %w", path, err)
			}
		}
		ing.mu.Lock()
		ing.lastRecordEnd = &end
		ing.mu.Unlock()
		ing.confirmClaim(ing.seenRecords, ing.inFlightRecords, index)
		succeeded = true
		ing.log.Info("ingested record file", "path", path, "round", f.Round, "items", len(f.Items))
		return nil
	}
	f, raw, err := stream.ReadRecordFile(path)
	if err != nil {
		return err
	}
	start, err := hashFromPB(f.StartRunningHash)
	if err != nil {
		return fmt.Errorf("record %s start hash: %w", path, err)
	}
	end, err := hashFromPB(f.EndRunningHash)
	if err != nil {
		return fmt.Errorf("record %s end hash: %w", path, err)
	}
	ing.mu.Lock()
	var expected [32]byte
	hasAnchor := ing.lastRecordEnd != nil
	if !hasAnchor {
		expected = stream.ChainSeed
	} else {
		expected = *ing.lastRecordEnd
	}
	ing.mu.Unlock()
	if start != expected {
		if !hasAnchor {
			return fmt.Errorf("no record chain anchor for %s: start %x has no anchor; start from genesis or restore a store with accepted records", path, start)
		}
		ing.log.Warn("record chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
		return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", path, expected, start)
	}
	if err := stream.VerifyRecordFile(raw, nil, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
		return fmt.Errorf("verify record %s: %w", path, err)
	}
	if f.Checkpoint != nil {
		if err := ing.checkPrev(f.Checkpoint, false); err != nil {
			return fmt.Errorf("prev chain %s: %w", path, err)
		}
	}
	if err := stream.ValidateStateDiffs(f.StateDiffs); err != nil {
		return fmt.Errorf("state_diffs %s: %w", path, err)
	}
	if err := verifyProofSidecarLocal(filepath.Dir(path), f); err != nil {
		return fmt.Errorf("proof sidecar %s: %w", path, err)
	}
	if err := ing.store.PutRecord(f); err != nil {
		return err
	}
	if f.Checkpoint != nil {
		if err := ing.checkPrev(f.Checkpoint, true); err != nil {
			return fmt.Errorf("prev chain %s: %w", path, err)
		}
	}
	ing.mu.Lock()
	ing.lastRecordEnd = &end
	ing.mu.Unlock()
	ing.log.Info("ingested record file", "path", path, "round", f.Round, "items", len(f.Items))
	return nil
}

func (ing *Ingester) ingestEvent(path string) error {
	index, ok := stream.EventFileIndex(filepath.Base(path))
	if ok {
		if !ing.tryClaim(ing.seenEvents, ing.inFlightEvents, index) {
			return nil
		}
		claimed := true
		succeeded := false
		defer func() {
			if claimed && !succeeded {
				ing.releaseClaim(ing.inFlightEvents, index)
			}
		}()
		f, raw, err := stream.ReadEventFile(path)
		if err != nil {
			return err
		}
		sig, err := ing.loadSig(path)
		if err != nil {
			return err
		}
		if sig == nil {
			ing.log.Warn("missing signature file, deferring event ingestion", "path", path)
			return fmt.Errorf("missing signature file for %s: deferring until sig arrives", path)
		}
		start, err := hashFromPB(f.StartRunningHash)
		if err != nil {
			return fmt.Errorf("event %s start hash: %w", path, err)
		}
		end, err := hashFromPB(f.EndRunningHash)
		if err != nil {
			return fmt.Errorf("event %s end hash: %w", path, err)
		}
		ing.mu.Lock()
		var expected [32]byte
		if ing.lastEventEnd == nil {
			expected = stream.ChainSeed
		} else {
			expected = *ing.lastEventEnd
		}
		ing.mu.Unlock()
		if start != expected {
			ing.log.Warn("event chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
			return fmt.Errorf("event chain continuity violation for %s: expected start %x got %x", path, expected, start)
		}
		if err := stream.VerifyEventFile(raw, sig, ing.cfg.PubKey); err != nil {
			return fmt.Errorf("verify event %s: %w", path, err)
		}
		if err := ing.store.PutEvents(f); err != nil {
			return err
		}
		ing.mu.Lock()
		ing.lastEventEnd = &end
		ing.mu.Unlock()
		ing.confirmClaim(ing.seenEvents, ing.inFlightEvents, index)
		succeeded = true
		ing.log.Info("ingested event file", "path", path, "events", len(f.Events))
		return nil
	}
	f, raw, err := stream.ReadEventFile(path)
	if err != nil {
		return err
	}
	sig, err := ing.loadSig(path)
	if err != nil {
		return err
	}
	if sig == nil {
		ing.log.Warn("missing signature file, deferring event ingestion", "path", path)
		return fmt.Errorf("missing signature file for %s: deferring until sig arrives", path)
	}
	start, err := hashFromPB(f.StartRunningHash)
	if err != nil {
		return fmt.Errorf("event %s start hash: %w", path, err)
	}
	end, err := hashFromPB(f.EndRunningHash)
	if err != nil {
		return fmt.Errorf("event %s end hash: %w", path, err)
	}
	ing.mu.Lock()
	var expected [32]byte
	if ing.lastEventEnd == nil {
		expected = stream.ChainSeed
	} else {
		expected = *ing.lastEventEnd
	}
	ing.mu.Unlock()
	if start != expected {
		ing.log.Warn("event chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
		return fmt.Errorf("event chain continuity violation for %s: expected start %x got %x", path, expected, start)
	}
	if err := stream.VerifyEventFile(raw, sig, ing.cfg.PubKey); err != nil {
		return fmt.Errorf("verify event %s: %w", path, err)
	}
	if err := ing.store.PutEvents(f); err != nil {
		return err
	}
	ing.mu.Lock()
	ing.lastEventEnd = &end
	ing.mu.Unlock()
	ing.log.Info("ingested event file", "path", path, "events", len(f.Events))
	return nil
}

func unmarshalStrictRemote(b []byte, m proto.Message) error {
	opts := proto.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(b, m); err != nil {
		return err
	}
	if proto.Size(m) != len(b) {
		return fmt.Errorf("message has %d trailing or unknown bytes (%d decoded)", len(b)-proto.Size(m), proto.Size(m))
	}
	return nil
}

func parseRemoteSig(b []byte, name string) (*pb.SignatureFile, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("signature file %s is empty", name)
	}
	if b[0] != stream.SigFileVersion {
		return nil, fmt.Errorf("unsupported signature file version %d in %s", b[0], name)
	}
	var sf pb.SignatureFile
	if err := unmarshalStrictRemote(b[1:], &sf); err != nil {
		return nil, fmt.Errorf("unmarshal sig %s: %w", name, err)
	}
	if sf.FileSignature == nil || sf.FileSignature.HashObject == nil || sf.MetadataSignature == nil || sf.MetadataSignature.HashObject == nil {
		return nil, fmt.Errorf("signature file %s is missing a signature or its hash object", name)
	}
	return &sf, nil
}

func (ing *Ingester) fetchRemoteSig(ctx context.Context, name string, listed map[string]struct{}, remote *stream.RemoteSource) (*pb.SignatureFile, error) {
	sigName := stream.SignatureFileName(name)
	if _, ok := listed[sigName]; !ok {
		return nil, nil
	}
	b, err := remote.Fetch(ctx, sigName)
	if err != nil {
		if errors.Is(err, stream.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch sig %s: %w", sigName, err)
	}
	sf, err := parseRemoteSig(b, sigName)
	if err != nil {
		return nil, err
	}
	return sf, nil
}

func (ing *Ingester) ingestRecordRemote(ctx context.Context, name string, listed map[string]struct{}, remote *stream.RemoteSource) error {
	index, ok := stream.RecordFileRound(name)
	if ok {
		if !ing.tryClaim(ing.seenRecords, ing.inFlightRecords, index) {
			return nil
		}
		claimed := true
		succeeded := false
		defer func() {
			if claimed && !succeeded {
				ing.releaseClaim(ing.inFlightRecords, index)
			}
		}()
		raw, err := remote.Fetch(ctx, name)
		if err != nil {
			return err
		}
		var f pb.RecordStreamFile
		if err := unmarshalStrictRemote(raw, &f); err != nil {
			return fmt.Errorf("unmarshal %s: %w", name, err)
		}
		start, err := hashFromPB(f.StartRunningHash)
		if err != nil {
			return fmt.Errorf("record %s start hash: %w", name, err)
		}
		end, err := hashFromPB(f.EndRunningHash)
		if err != nil {
			return fmt.Errorf("record %s end hash: %w", name, err)
		}
		ing.mu.Lock()
		var expected [32]byte
		hasAnchor := ing.lastRecordEnd != nil
		if !hasAnchor {
			expected = stream.ChainSeed
		} else {
			expected = *ing.lastRecordEnd
		}
		ing.mu.Unlock()
		if start != expected {
			if !hasAnchor {
				return fmt.Errorf("no record chain anchor for %s: start %x has no anchor; start from genesis or restore a store with accepted records", name, start)
			}
			ing.log.Warn("record chain continuity violation", "name", name, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
			return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", name, expected, start)
		}
		if err := stream.VerifyRecordFile(raw, nil, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
			return fmt.Errorf("verify record %s: %w", name, err)
		}
		if f.Checkpoint != nil {
			if err := ing.checkPrev(f.Checkpoint, false); err != nil {
				return fmt.Errorf("prev chain %s: %w", name, err)
			}
		}
		if err := stream.ValidateStateDiffs(f.StateDiffs); err != nil {
			return fmt.Errorf("state_diffs %s: %w", name, err)
		}
		if err := ing.verifyProofSidecarRemote(ctx, listed, remote, &f); err != nil {
			return fmt.Errorf("proof sidecar %s: %w", name, err)
		}
		if err := ing.store.PutRecord(&f); err != nil {
			return err
		}
		if f.Checkpoint != nil {
			if err := ing.checkPrev(f.Checkpoint, true); err != nil {
				return fmt.Errorf("prev chain %s: %w", name, err)
			}
		}
		ing.mu.Lock()
		ing.lastRecordEnd = &end
		ing.mu.Unlock()
		ing.confirmClaim(ing.seenRecords, ing.inFlightRecords, index)
		succeeded = true
		ing.log.Info("ingested record file", "name", name, "round", f.Round, "items", len(f.Items))
		return nil
	}
	raw, err := remote.Fetch(ctx, name)
	if err != nil {
		return err
	}
	var f pb.RecordStreamFile
	if err := unmarshalStrictRemote(raw, &f); err != nil {
		return fmt.Errorf("unmarshal %s: %w", name, err)
	}
	start, err := hashFromPB(f.StartRunningHash)
	if err != nil {
		return fmt.Errorf("record %s start hash: %w", name, err)
	}
	end, err := hashFromPB(f.EndRunningHash)
	if err != nil {
		return fmt.Errorf("record %s end hash: %w", name, err)
	}
	ing.mu.Lock()
	var expected [32]byte
	hasAnchor := ing.lastRecordEnd != nil
	if !hasAnchor {
		expected = stream.ChainSeed
	} else {
		expected = *ing.lastRecordEnd
	}
	ing.mu.Unlock()
	if start != expected {
		if !hasAnchor {
			return fmt.Errorf("no record chain anchor for %s: start %x has no anchor; start from genesis or restore a store with accepted records", name, start)
		}
		ing.log.Warn("record chain continuity violation", "name", name, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
		return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", name, expected, start)
	}
	if err := stream.VerifyRecordFile(raw, nil, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
		return fmt.Errorf("verify record %s: %w", name, err)
	}
	if f.Checkpoint != nil {
		if err := ing.checkPrev(f.Checkpoint, false); err != nil {
			return fmt.Errorf("prev chain %s: %w", name, err)
		}
	}
	if err := stream.ValidateStateDiffs(f.StateDiffs); err != nil {
		return fmt.Errorf("state_diffs %s: %w", name, err)
	}
	if err := ing.verifyProofSidecarRemote(ctx, listed, remote, &f); err != nil {
		return fmt.Errorf("proof sidecar %s: %w", name, err)
	}
	if err := ing.store.PutRecord(&f); err != nil {
		return err
	}
	if f.Checkpoint != nil {
		if err := ing.checkPrev(f.Checkpoint, true); err != nil {
			return fmt.Errorf("prev chain %s: %w", name, err)
		}
	}
	ing.mu.Lock()
	ing.lastRecordEnd = &end
	ing.mu.Unlock()
	ing.log.Info("ingested record file", "name", name, "round", f.Round, "items", len(f.Items))
	return nil
}

func (ing *Ingester) ingestEventRemote(ctx context.Context, name string, listed map[string]struct{}, remote *stream.RemoteSource) error {
	index, ok := stream.EventFileIndex(name)
	if ok {
		if !ing.tryClaim(ing.seenEvents, ing.inFlightEvents, index) {
			return nil
		}
		claimed := true
		succeeded := false
		defer func() {
			if claimed && !succeeded {
				ing.releaseClaim(ing.inFlightEvents, index)
			}
		}()
		raw, err := remote.Fetch(ctx, name)
		if err != nil {
			return err
		}
		sig, err := ing.fetchRemoteSig(ctx, name, listed, remote)
		if err != nil {
			return err
		}
		if sig == nil {
			ing.log.Warn("missing signature file, deferring event ingestion", "name", name)
			return fmt.Errorf("missing signature file for %s: deferring until sig arrives", name)
		}
		var f pb.EventStreamFile
		if err := unmarshalStrictRemote(raw, &f); err != nil {
			return fmt.Errorf("unmarshal %s: %w", name, err)
		}
		start, err := hashFromPB(f.StartRunningHash)
		if err != nil {
			return fmt.Errorf("event %s start hash: %w", name, err)
		}
		end, err := hashFromPB(f.EndRunningHash)
		if err != nil {
			return fmt.Errorf("event %s end hash: %w", name, err)
		}
		ing.mu.Lock()
		var expected [32]byte
		if ing.lastEventEnd == nil {
			expected = stream.ChainSeed
		} else {
			expected = *ing.lastEventEnd
		}
		ing.mu.Unlock()
		if start != expected {
			ing.log.Warn("event chain continuity violation", "name", name, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
			return fmt.Errorf("event chain continuity violation for %s: expected start %x got %x", name, expected, start)
		}
		if err := stream.VerifyEventFile(raw, sig, ing.cfg.PubKey); err != nil {
			return fmt.Errorf("verify event %s: %w", name, err)
		}
		if err := ing.store.PutEvents(&f); err != nil {
			return err
		}
		ing.mu.Lock()
		ing.lastEventEnd = &end
		ing.mu.Unlock()
		ing.confirmClaim(ing.seenEvents, ing.inFlightEvents, index)
		succeeded = true
		ing.log.Info("ingested event file", "name", name, "events", len(f.Events))
		return nil
	}
	raw, err := remote.Fetch(ctx, name)
	if err != nil {
		return err
	}
	sig, err := ing.fetchRemoteSig(ctx, name, listed, remote)
	if err != nil {
		return err
	}
	if sig == nil {
		ing.log.Warn("missing signature file, deferring event ingestion", "name", name)
		return fmt.Errorf("missing signature file for %s: deferring until sig arrives", name)
	}
	var f pb.EventStreamFile
	if err := unmarshalStrictRemote(raw, &f); err != nil {
		return fmt.Errorf("unmarshal %s: %w", name, err)
	}
	start, err := hashFromPB(f.StartRunningHash)
	if err != nil {
		return fmt.Errorf("event %s start hash: %w", name, err)
	}
	end, err := hashFromPB(f.EndRunningHash)
	if err != nil {
		return fmt.Errorf("event %s end hash: %w", name, err)
	}
	ing.mu.Lock()
	var expected [32]byte
	if ing.lastEventEnd == nil {
		expected = stream.ChainSeed
	} else {
		expected = *ing.lastEventEnd
	}
	ing.mu.Unlock()
	if start != expected {
		ing.log.Warn("event chain continuity violation", "name", name, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
		return fmt.Errorf("event chain continuity violation for %s: expected start %x got %x", name, expected, start)
	}
	if err := stream.VerifyEventFile(raw, sig, ing.cfg.PubKey); err != nil {
		return fmt.Errorf("verify event %s: %w", name, err)
	}
	if err := ing.store.PutEvents(&f); err != nil {
		return err
	}
	ing.mu.Lock()
	ing.lastEventEnd = &end
	ing.mu.Unlock()
	ing.log.Info("ingested event file", "name", name, "events", len(f.Events))
	return nil
}
