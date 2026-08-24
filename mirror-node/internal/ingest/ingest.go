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
	"sync"
	"time"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// Config controls the ingester.
type Config struct {
	StreamsDir        string
	PollInterval      time.Duration
	PubKey            ed25519.PublicKey
	TrustedRosterHash []byte
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

	runMu sync.Mutex // serializes concurrent RunOnce calls
}

func New(cfg Config, st store.Store, log *slog.Logger) *Ingester {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	return &Ingester{
		cfg:             cfg,
		store:           st,
		log:             log,
		seenRecords:     make(map[uint64]struct{}),
		seenEvents:      make(map[uint64]struct{}),
		inFlightRecords: make(map[uint64]struct{}),
		inFlightEvents:  make(map[uint64]struct{}),
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
		sig, err := ing.loadSig(path)
		if err != nil {
			return err
		}
		if sig == nil {
			ing.log.Warn("missing signature file, deferring record ingestion", "path", path)
			return fmt.Errorf("missing signature file for %s: deferring until sig arrives", path)
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
		if ing.lastRecordEnd == nil {
			expected = stream.ChainSeed
		} else {
			expected = *ing.lastRecordEnd
		}
		ing.mu.Unlock()
		if start != expected {
			ing.log.Warn("record chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
			return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", path, expected, start)
		}
		if err := stream.VerifyRecordFile(raw, sig, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
			return fmt.Errorf("verify record %s: %w", path, err)
		}
		if err := ing.store.PutRecord(f); err != nil {
			return err
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
	sig, err := ing.loadSig(path)
	if err != nil {
		return err
	}
	if sig == nil {
		ing.log.Warn("missing signature file, deferring record ingestion", "path", path)
		return fmt.Errorf("missing signature file for %s: deferring until sig arrives", path)
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
	if ing.lastRecordEnd == nil {
		expected = stream.ChainSeed
	} else {
		expected = *ing.lastRecordEnd
	}
	ing.mu.Unlock()
	if start != expected {
		ing.log.Warn("record chain continuity violation", "path", path, "expected", fmt.Sprintf("%x", expected), "got", fmt.Sprintf("%x", start))
		return fmt.Errorf("record chain continuity violation for %s: expected start %x got %x", path, expected, start)
	}
	if err := stream.VerifyRecordFile(raw, sig, ing.cfg.PubKey, ing.cfg.TrustedRosterHash); err != nil {
		return fmt.Errorf("verify record %s: %w", path, err)
	}
	if err := ing.store.PutRecord(f); err != nil {
		return err
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
