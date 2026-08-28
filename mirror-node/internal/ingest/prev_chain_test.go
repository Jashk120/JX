package ingest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// TestCheckPrevStrict32Bytes is the direct B1 regression: the pre-fix
// checkPrevContinuity returned nil for a len-0 prev_checkpoint_hash and
// advancePrev still advanced the expectation, so a post-genesis record with
// an empty prev spliced the chain. checkPrev must reject len-0 at any round
// (genesis is 32 zero bytes, never an empty slice), reject wrong 32-byte
// prevs, and advance only on a correct commit.
func TestCheckPrevStrict32Bytes(t *testing.T) {
	ing := New(Config{}, store.NewMemStore(), quietLogger())

	genesis := &pb.SignedCheckpoint{PrevCheckpointHash: make([]byte, 32)}
	if err := ing.checkPrev(genesis, false); err != nil {
		t.Fatalf("genesis zeros (32B) must be accepted: %v", err)
	}
	// THE B1 BYPASS: len-0 prev must be rejected even at genesis.
	empty := &pb.SignedCheckpoint{PrevCheckpointHash: nil}
	if err := ing.checkPrev(empty, false); err == nil {
		t.Fatal("empty prev_checkpoint_hash must be rejected (B1 bypass)")
	}
	short := &pb.SignedCheckpoint{PrevCheckpointHash: make([]byte, 16)}
	if err := ing.checkPrev(short, false); err == nil {
		t.Fatal("16-byte prev_checkpoint_hash must be rejected")
	}
	// Commit advances the expectation exactly once.
	if err := ing.checkPrev(genesis, true); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	want := stream.CheckpointSigningBytesHash(genesis)
	if ing.expectedPrev == nil || *ing.expectedPrev != want {
		t.Fatalf("expectedPrev = %x, want %x", ing.expectedPrev, want)
	}
	// Wrong 32-byte prev rejected; expectation unchanged.
	wrong := &pb.SignedCheckpoint{PrevCheckpointHash: bytes.Repeat([]byte{0xEE}, 32)}
	if err := ing.checkPrev(wrong, false); err == nil {
		t.Fatal("wrong 32-byte prev must be rejected")
	}
	if ing.expectedPrev == nil || *ing.expectedPrev != want {
		t.Fatalf("rejected round must not move expectedPrev")
	}
	// Correct chained prev accepted.
	good := &pb.SignedCheckpoint{PrevCheckpointHash: want[:]}
	if err := ing.checkPrev(good, false); err != nil {
		t.Fatalf("chained prev must be accepted: %v", err)
	}
	// A read-only check (commit=false) must not advance.
	after := *ing.expectedPrev
	if err := ing.checkPrev(good, false); err != nil {
		t.Fatalf("re-check chained prev: %v", err)
	}
	if *ing.expectedPrev != after {
		t.Fatal("commit=false must not advance expectedPrev")
	}
}

// TestIngestPrevChainEndToEnd drives the full ingest path: files on disk,
// RunOnce, store contents. It covers the B1 splice protection on record
// files (the running-hash chain and the checkpoint prev chain are separate
// mechanisms; these tests exercise the latter).
func TestIngestPrevChainEndToEnd(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ctx := context.Background()

	t.Run("empty_prev_post_genesis_rejected", func(t *testing.T) {
		dir := t.TempDir()
		end0, _ := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
		// Round 1 BLS-consistent (signed over a zero prev tail), then the
		// committed field is stripped — the exact pre-fix attack shape.
		writeRecordFileWithSig(t, dir, 1, priv, end0, [32]byte{})
		stripPrevFromRecordFile(t, dir, 1)

		st := store.NewMemStore()
		ing := New(Config{StreamsDir: dir}, st, quietLogger())
		_ = ing.RunOnce(ctx)
		assertCounts(t, st, 0, 1)
	})

	t.Run("wrong_prev_rejected", func(t *testing.T) {
		dir := t.TempDir()
		end0, _ := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
		// Round 1 is fully BLS-valid and correctly running-hash chained but
		// commits genesis zeros instead of SHA256(cp0): per-file verification
		// passes, the prev chain must reject.
		writeRecordFileWithSig(t, dir, 1, priv, end0, [32]byte{})

		st := store.NewMemStore()
		ing := New(Config{StreamsDir: dir}, st, quietLogger())
		_ = ing.RunOnce(ctx)
		assertCounts(t, st, 0, 1)
	})

	t.Run("chained_rounds_accepted", func(t *testing.T) {
		dir := t.TempDir()
		end0, cp0 := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
		end1, cp1 := writeRecordFileWithSig(t, dir, 1, priv, end0, stream.CheckpointSigningBytesHash(cp0))
		writeRecordFileWithSig(t, dir, 2, priv, end1, stream.CheckpointSigningBytesHash(cp1))

		st := store.NewMemStore()
		ing := New(Config{StreamsDir: dir}, st, quietLogger())
		_ = ing.RunOnce(ctx)
		assertCounts(t, st, 0, 3)
	})

	t.Run("failed_round_does_not_advance_expectation", func(t *testing.T) {
		dir := t.TempDir()
		end0, cp0 := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
		writeRecordFileWithSig(t, dir, 1, priv, end0, [32]byte{})

		st := store.NewMemStore()
		ing := New(Config{StreamsDir: dir}, st, quietLogger())
		_ = ing.RunOnce(ctx)
		assertCounts(t, st, 0, 1)

		// Rebuild round 1 correctly (re-signed over the chained prev). The
		// rejected file was NOT marked seen, so the next poll retries it and
		// the expectation was not corrupted by the failed round.
		writeRecordFileWithSig(t, dir, 1, priv, end0, stream.CheckpointSigningBytesHash(cp0))
		_ = ing.RunOnce(ctx)
		assertCounts(t, st, 0, 2)
	})
}

// stripPrevFromRecordFile rewrites round's file with an empty
// prev_checkpoint_hash, keeping the BLS signature over the zero tail valid.
func stripPrevFromRecordFile(t *testing.T, dir string, round uint64) {
	t.Helper()
	path := filepath.Join(dir, stream.RecordFileName(round))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var rsf pb.RecordStreamFile
	if err := proto.Unmarshal(raw, &rsf); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	rsf.Checkpoint.PrevCheckpointHash = nil
	out, err := proto.Marshal(&rsf)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
