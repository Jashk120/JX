package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
)

func TestRestartMidHistory(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	end0, cp0 := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
	end1, cp1 := writeRecordFileWithSig(t, dir, 1, priv, end0, stream.CheckpointSigningBytesHash(cp0))
	end2, cp2 := writeRecordFileWithSig(t, dir, 2, priv, end1, stream.CheckpointSigningBytesHash(cp1))

	st := store.NewMemStore()
	ingA := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ingA.RunOnce(context.Background()); err != nil {
		t.Fatalf("ingester A RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 3)

	if err := os.Remove(filepath.Join(dir, stream.RecordFileName(0))); err != nil {
		t.Fatalf("remove round 0: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, stream.RecordFileName(1))); err != nil {
		t.Fatalf("remove round 1: %v", err)
	}

	writeRecordFileWithSig(t, dir, 3, priv, end2, stream.CheckpointSigningBytesHash(cp2))

	ingB := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ingB.RunOnce(context.Background()); err != nil {
		t.Fatalf("ingester B RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 4)

	// round 2 is in seenRecords via seed; ensure it was not rejected as chain violation
	// by checking that ingB's lastRecordEnd progressed to round 3
	if ingB.lastRecordEnd == nil {
		t.Fatal("expected lastRecordEnd to be set after ingesting round 3")
	}
	// verify round 2 file still exists and ingestRecord on it would be skipped (no error, no re-store)
	path2 := filepath.Join(dir, stream.RecordFileName(2))
	if err := ingB.ingestRecord(path2); err != nil {
		t.Fatalf("ingestRecord round 2 after restart should be skipped via seenRecords, got err: %v", err)
	}
	assertCounts(t, st, 0, 4)
}

func TestRestartFullDir(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	end0, cp0 := writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed, [32]byte{})
	end1, cp1 := writeRecordFileWithSig(t, dir, 1, priv, end0, stream.CheckpointSigningBytesHash(cp0))
	writeRecordFileWithSig(t, dir, 2, priv, end1, stream.CheckpointSigningBytesHash(cp1))

	st := store.NewMemStore()
	ingA := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ingA.RunOnce(context.Background()); err != nil {
		t.Fatalf("ingester A RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 3)

	ingB := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ingB.RunOnce(context.Background()); err != nil {
		t.Fatalf("ingester B RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 3)
}

func TestFailClosedNoAnchor(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	badStart := sha256.Sum256([]byte("not-genesis"))
	writeRecordFileWithSig(t, dir, 5, priv, badStart, [32]byte{})

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())

	path := filepath.Join(dir, stream.RecordFileName(5))
	err := ing.ingestRecord(path)
	if err == nil {
		t.Fatal("expected no record chain anchor error, got nil")
	}
	if !strings.Contains(err.Error(), "no record chain anchor") {
		t.Fatalf("expected error to contain 'no record chain anchor', got %q", err.Error())
	}
	if !strings.Contains(err.Error(), stream.RecordFileName(5)) {
		t.Fatalf("error should contain path/name, got %q", err.Error())
	}
	if !strings.Contains(strings.ToLower(err.Error()), "start from genesis or restore a store with accepted records") {
		t.Fatalf("error should contain hint, got %q", err.Error())
	}
	if !strings.Contains(strings.ToLower(err.Error()), fmt.Sprintf("%x", badStart)) {
		t.Fatalf("error should contain actual start hash %x, got %q", badStart, err.Error())
	}
	// Verify store still empty
	assertCounts(t, st, 0, 0)

	// Also ensure that with an anchor, the same file yields continuity violation not no-anchor
	// Anchor via a genesis record in store: create a proper chain seed record in store, then retry
	dir2 := t.TempDir()
	end0, cp0 := writeRecordFileWithSig(t, dir2, 0, priv, stream.ChainSeed, [32]byte{})
	_ = end0
	_ = cp0
	// Use separate store with genesis
	st2 := store.NewMemStore()
	ing2 := New(Config{StreamsDir: dir2, PubKey: pub, TrustedRosterHash: trusted[:]}, st2, quietLogger())
	if err := ing2.RunOnce(context.Background()); err != nil {
		t.Fatalf("ing2 RunOnce genesis: %v", err)
	}
	// Now ing2 has anchor end0; try to ingest the bad round 5 file (start != end0)
	pathBad := filepath.Join(dir, stream.RecordFileName(5))
	// Copy file to dir2 to have some context? Just call ingestRecordRemote-like? Use ingestRecord directly with ing2 which has anchor.
	err2 := ing2.ingestRecord(pathBad)
	if err2 == nil {
		t.Fatal("expected continuity violation with anchor")
	}
	if strings.Contains(err2.Error(), "no record chain anchor") {
		t.Fatalf("with anchor, should not be no-anchor error, got %q", err2.Error())
	}
	if !strings.Contains(err2.Error(), "record chain continuity violation") {
		t.Fatalf("expected continuity violation, got %q", err2.Error())
	}
}
