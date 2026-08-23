package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func hashObj(h [32]byte) *pb.HashObject {
	return &pb.HashObject{Algorithm: 0, Length: 32, Hash: h[:]}
}

// writeEventFile writes a valid .esf at dir holding one event per (creator,
// seq) pair, chained from the seed so it passes VerifyEventFile without a
// signature file.
func writeEventFile(t *testing.T, dir string, index uint64, pairs [][2]uint64) {
	t.Helper()
	events := make([]*pb.Event, len(pairs))
	serialized := make([][]byte, len(pairs))
	for i, p := range pairs {
		ev := &pb.Event{Creator: p[0], Seq: p[1]}
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		events[i], serialized[i] = ev, b
	}
	end := stream.RunningHash(stream.ChainSeed, serialized)
	esf := &pb.EventStreamFile{
		Version:          stream.Version,
		StartRunningHash: hashObj(stream.ChainSeed),
		Events:           events,
		EndRunningHash:   hashObj(end),
	}
	raw, err := proto.Marshal(esf)
	if err != nil {
		t.Fatalf("marshal esf: %v", err)
	}
	path := filepath.Join(dir, stream.EventFileName(index))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeCorruptEventFile writes an .esf whose end running hash does not match
// its events, i.e. one that must fail verification.
func writeCorruptEventFile(t *testing.T, dir string, index uint64) {
	t.Helper()
	ev := &pb.Event{Creator: 1, Seq: 99}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	end := stream.RunningHash(stream.ChainSeed, [][]byte{b})
	end[0] ^= 0xff
	esf := &pb.EventStreamFile{
		Version:          stream.Version,
		StartRunningHash: hashObj(stream.ChainSeed),
		Events:           []*pb.Event{ev},
		EndRunningHash:   hashObj(end),
	}
	raw, err := proto.Marshal(esf)
	if err != nil {
		t.Fatalf("marshal esf: %v", err)
	}
	path := filepath.Join(dir, stream.EventFileName(index))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeRecordFile writes a valid .rsf for round at dir, carrying one record
// item and a single-member threshold-signed checkpoint.
func writeRecordFile(t *testing.T, dir string, round uint64, priv ed25519.PrivateKey) {
	t.Helper()
	item := &pb.RecordItem{
		EventHash: make([]byte, 32),
		TxIndex:   0,
		TxPayload: []byte("put"),
	}
	serialized := make([][]byte, 1)
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	serialized[0] = b
	pub := priv.Public().(ed25519.PublicKey)

	var rosterBuf [40]byte
	binary.BigEndian.PutUint64(rosterBuf[:8], 0)
	copy(rosterBuf[8:], pub)
	rosterHash := sha256.Sum256(rosterBuf[:])
	stateHash := sha256.Sum256([]byte("state"))

	signing := make([]byte, 0, 72)
	var roundBE [8]byte
	binary.BigEndian.PutUint64(roundBE[:], round)
	signing = append(signing, roundBE[:]...)
	signing = append(signing, stateHash[:]...)
	signing = append(signing, rosterHash[:]...)

	cp := &pb.SignedCheckpoint{
		Round:      round,
		StateHash:  stateHash[:],
		RosterHash: rosterHash[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub},
		},
		Sigs: []*pb.CheckpointSig{
			{Round: round, Signer: 0, Sig: ed25519.Sign(priv, signing)},
		},
	}
	rsf := &pb.RecordStreamFile{
		Version:          stream.Version,
		Round:            round,
		StartRunningHash: hashObj(stream.ChainSeed),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObj(stream.RunningHash(stream.ChainSeed, serialized)),
		Checkpoint:       cp,
	}
	raw, err := proto.Marshal(rsf)
	if err != nil {
		t.Fatalf("marshal rsf: %v", err)
	}
	path := filepath.Join(dir, stream.RecordFileName(round))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertCounts(t *testing.T, st *store.MemStore, wantEvents, wantRecords int) {
	t.Helper()
	if n := len(st.ListEvents()); n != wantEvents {
		t.Errorf("store holds %d events, want %d", n, wantEvents)
	}
	if n := len(st.ListRecords()); n != wantRecords {
		t.Errorf("store holds %d record files, want %d", n, wantRecords)
	}
}

func TestRunOnceDoesNotReingestOnLaterPolls(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writeEventFile(t, dir, 0, [][2]uint64{{1, 0}, {1, 1}})
	writeRecordFile(t, dir, 0, priv)

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir}, st, quietLogger())
	ctx := context.Background()

	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)

	// Re-polling the unchanged directory must be a no-op.
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)

	// New files appear; exactly they get ingested.
	writeEventFile(t, dir, 1, [][2]uint64{{2, 0}})
	writeRecordFile(t, dir, 1, priv)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("third RunOnce: %v", err)
	}
	assertCounts(t, st, 3, 2)
}

func TestReingestIntoPopulatedStoreIsNoop(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writeEventFile(t, dir, 0, [][2]uint64{{1, 0}})
	writeRecordFile(t, dir, 0, priv)

	st := store.NewMemStore()
	ctx := context.Background()

	first := New(Config{StreamsDir: dir}, st, quietLogger())
	if err := first.RunOnce(ctx); err != nil {
		t.Fatalf("first ingester RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)

	// A fresh Ingester (e.g. after restart) against the same populated store:
	// store-level dedup must keep the data single-copy.
	second := New(Config{StreamsDir: dir}, st, quietLogger())
	if err := second.RunOnce(ctx); err != nil {
		t.Fatalf("second ingester RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)
}

func TestFailedFileIsNotMarkedSeen(t *testing.T) {
	dir := t.TempDir()
	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir}, st, quietLogger())
	ctx := context.Background()

	writeCorruptEventFile(t, dir, 0)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce with corrupt file: %v", err)
	}
	assertCounts(t, st, 0, 0)

	// The same file name now holds valid content; it must be retried and
	// stored rather than skipped as already seen.
	writeEventFile(t, dir, 0, [][2]uint64{{3, 0}})
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after fix: %v", err)
	}
	assertCounts(t, st, 1, 0)
}
