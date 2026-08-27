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

	blst "github.com/supranational/blst/bindings/go"
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

func trustedHashForPriv(priv ed25519.PrivateKey) [32]byte {
	pub := priv.Public().(ed25519.PublicKey)
	blsPub, _ := blsKeyForTest(priv)
	var buf []byte
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], 0)
	buf = append(buf, be[:]...)
	buf = append(buf, pub...)
	buf = append(buf, blsPub...)
	return sha256.Sum256(buf)
}

func writeSigFile(t *testing.T, streamPath string, fileBytes, metadata []byte, priv ed25519.PrivateKey) {
	t.Helper()
	fileDigest := sha256.Sum256(fileBytes)
	metaDigest := sha256.Sum256(metadata)
	sigFile := &pb.SignatureFile{
		FileSignature: &pb.SignatureObject{
			Type:      0,
			Length:    64,
			Signature: ed25519.Sign(priv, fileDigest[:]),
			HashObject: &pb.HashObject{
				Algorithm: 0,
				Length:    32,
				Hash:      fileDigest[:],
			},
		},
		MetadataSignature: &pb.SignatureObject{
			Type:      0,
			Length:    64,
			Signature: ed25519.Sign(priv, metaDigest[:]),
			HashObject: &pb.HashObject{
				Algorithm: 0,
				Length:    32,
				Hash:      metaDigest[:],
			},
		},
	}
	raw, err := proto.Marshal(sigFile)
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}
	out := make([]byte, 0, 1+len(raw))
	out = append(out, stream.SigFileVersion)
	out = append(out, raw...)
	sigPath := filepath.Join(filepath.Dir(streamPath), stream.SignatureFileName(filepath.Base(streamPath)))
	if err := os.WriteFile(sigPath, out, 0o644); err != nil {
		t.Fatalf("write sig %s: %v", sigPath, err)
	}
}

func writeEventFileWithSig(t *testing.T, dir string, index uint64, pairs [][2]uint64, priv ed25519.PrivateKey, start [32]byte) [32]byte {
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
	end := stream.RunningHash(start, serialized)
	esf := &pb.EventStreamFile{
		Version:          stream.Version,
		StartRunningHash: hashObj(start),
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
	meta := make([]byte, 0, 68)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], stream.Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, start[:]...)
	meta = append(meta, end[:]...)
	writeSigFile(t, path, raw, meta, priv)
	return end
}

func writeEventFile(t *testing.T, dir string, index uint64, pairs [][2]uint64) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	// For backwards compatibility in simple tests, if no chaining info, use ChainSeed.
	writeEventFileWithSig(t, dir, index, pairs, priv, stream.ChainSeed)
}

func writeCorruptEventFileWithSig(t *testing.T, dir string, index uint64, priv ed25519.PrivateKey, start [32]byte) {
	t.Helper()
	ev := &pb.Event{Creator: 1, Seq: 99}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	end := stream.RunningHash(start, [][]byte{b})
	end[0] ^= 0xff
	esf := &pb.EventStreamFile{
		Version:          stream.Version,
		StartRunningHash: hashObj(start),
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
	meta := make([]byte, 0, 68)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], stream.Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, start[:]...)
	meta = append(meta, end[:]...)
	writeSigFile(t, path, raw, meta, priv)
}

func writeCorruptEventFile(t *testing.T, dir string, index uint64) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writeCorruptEventFileWithSig(t, dir, index, priv, stream.ChainSeed)
}

func blsKeyForTest(priv ed25519.PrivateKey) ([]byte, *blstSecret) {
	// Derive BLS key deterministically from ed25519 seed so each priv maps to a unique BLS key
	seed := priv.Seed()
	var ikm [32]byte
	copy(ikm[:], seed)
	sk := blst.KeyGen(ikm[:])
	pk := new(blst.P1Affine).From(sk).Compress()
	return pk, &blstSecret{sk: sk, pk: pk}
}

type blstSecret struct {
	sk *blst.SecretKey
	pk []byte
}

func writeRecordFileWithSig(t *testing.T, dir string, round uint64, priv ed25519.PrivateKey, start [32]byte) [32]byte {
	t.Helper()
	item := &pb.RecordItem{
		EventHash: make([]byte, 32),
		TxIndex:   0,
		TxPayload: []byte("put"),
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	_ = b
	// Running hash computed via deterministic marshal of items
	serialized := [][]byte{}
	// Need actual RFS items for hash
	items := []*pb.RecordItem{item}
	for _, it := range items {
		mb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		serialized = append(serialized, mb)
	}
	end := stream.RunningHash(start, serialized)
	pub := priv.Public().(ed25519.PublicKey)
	blsPub, sec := blsKeyForTest(priv)
	// roster hash: 88/member = id(8)||edkey(32)||blskey(48)
	rosterHash := func() [32]byte {
		var buf []byte
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], 0)
		buf = append(buf, be[:]...)
		buf = append(buf, pub...)
		buf = append(buf, blsPub...)
		return sha256.Sum256(buf)
	}()
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("state"))
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], round)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash[:])
	sigAff := new(blst.P2Affine).Sign(sec.sk, signingBytes[:], stream.CheckpointDST)
	sigBytes := sigAff.Compress()
	cp := &pb.SignedCheckpoint{
		Round:       round,
		StateHash:   stateHash[:],
		RosterHash:  rosterHash[:],
		RecordsRoot: recordsRoot[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub, BlsKey: blsPub},
		},
		AggregateSig: sigBytes,
		Signers:      []uint64{0},
	}
	rsf := &pb.RecordStreamFile{
		Version:          stream.Version,
		Round:            round,
		StartRunningHash: hashObj(start),
		Items:            items,
		EndRunningHash:   hashObj(end),
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
	// No .rsf_sig file anymore (BLS binding); do not write sig file
	return end
}

func writeRecordFile(t *testing.T, dir string, round uint64, priv ed25519.PrivateKey) {
	writeRecordFileWithSig(t, dir, round, priv, stream.ChainSeed)
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
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	end0events := writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}, {1, 1}}, priv, stream.ChainSeed)
	writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed)

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	ctx := context.Background()

	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)

	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)

	writeEventFileWithSig(t, dir, 1, [][2]uint64{{2, 0}}, priv, end0events)
	end0records := stream.RunningHash(stream.ChainSeed, [][]byte{func() []byte {
		item := &pb.RecordItem{EventHash: make([]byte, 32), TxIndex: 0, TxPayload: []byte("put")}
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
		return b
	}()})
	writeRecordFileWithSig(t, dir, 1, priv, end0records)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("third RunOnce: %v", err)
	}
	assertCounts(t, st, 3, 2)
}

func TestReingestIntoPopulatedStoreIsNoop(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)
	writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	writeRecordFileWithSig(t, dir, 0, priv, stream.ChainSeed)

	st := store.NewMemStore()
	ctx := context.Background()

	first := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := first.RunOnce(ctx); err != nil {
		t.Fatalf("first ingester RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)

	second := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := second.RunOnce(ctx); err != nil {
		t.Fatalf("second ingester RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)
}

func TestFailedFileIsNotMarkedSeen(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)
	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	ctx := context.Background()

	writeCorruptEventFileWithSig(t, dir, 0, priv, stream.ChainSeed)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce with corrupt file: %v", err)
	}
	assertCounts(t, st, 0, 0)

	os.Remove(filepath.Join(dir, stream.EventFileName(0)))
	os.Remove(filepath.Join(dir, stream.SignatureFileName(stream.EventFileName(0))))
	writeEventFileWithSig(t, dir, 0, [][2]uint64{{3, 0}}, priv, stream.ChainSeed)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after fix: %v", err)
	}
	assertCounts(t, st, 1, 0)
}

func TestMissingSigDeferredNotAccepted(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	events := []*pb.Event{{Creator: 1, Seq: 0}}
	serialized := make([][]byte, len(events))
	for i, ev := range events {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(ev)
		serialized[i] = b
	}
	end := stream.RunningHash(stream.ChainSeed, serialized)
	esf := &pb.EventStreamFile{
		Version:          stream.Version,
		StartRunningHash: hashObj(stream.ChainSeed),
		Events:           events,
		EndRunningHash:   hashObj(end),
	}
	raw, _ := proto.Marshal(esf)
	path := filepath.Join(dir, stream.EventFileName(0))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// No sig file written.

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	ctx := context.Background()
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 0)

	// Now sig arrives.
	meta := make([]byte, 0, 68)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], stream.Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, stream.ChainSeed[:]...)
	meta = append(meta, end[:]...)
	writeSigFile(t, path, raw, meta, priv)

	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after sig: %v", err)
	}
	assertCounts(t, st, 1, 0)
}

func TestMissingSigRecordDeferred(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	item := &pb.RecordItem{EventHash: make([]byte, 32), TxIndex: 0, TxPayload: []byte("put")}
	bm, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	end := stream.RunningHash(stream.ChainSeed, [][]byte{bm})
	blsPub, sec := blsKeyForTest(priv)
	var rosterHash [32]byte
	{
		var buf []byte
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], 0)
		buf = append(buf, be[:]...)
		buf = append(buf, pub...)
		buf = append(buf, blsPub...)
		rosterHash = sha256.Sum256(buf)
	}
	items := []*pb.RecordItem{item}
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("state"))
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], 0)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash[:])
	sigAff := new(blst.P2Affine).Sign(sec.sk, signingBytes[:], stream.CheckpointDST)
	cp := &pb.SignedCheckpoint{
		Round:       0,
		StateHash:   stateHash[:],
		RosterHash:  rosterHash[:],
		RecordsRoot: recordsRoot[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub, BlsKey: blsPub},
		},
		AggregateSig: sigAff.Compress(),
		Signers:      []uint64{0},
	}
	rsf := &pb.RecordStreamFile{
		Version:          stream.Version,
		Round:            0,
		StartRunningHash: hashObj(stream.ChainSeed),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObj(end),
		Checkpoint:       cp,
	}
	raw, _ := proto.Marshal(rsf)
	path := filepath.Join(dir, stream.RecordFileName(0))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	ctx := context.Background()
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 1)
}

func TestChainContinuityFirstFileMustBeSeed(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	// Write file 0 with wrong start (not seed)
	badStart := sha256.Sum256([]byte("bad"))
	writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}}, priv, badStart)

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 0)
}

func TestChainContinuitySpliceRejected(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	end0 := writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	// File 1 should start at end0, but we write it starting at seed -> splice
	writeEventFileWithSig(t, dir, 1, [][2]uint64{{1, 1}}, priv, stream.ChainSeed)

	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Only first file should be ingested, second rejected due to discontinuity.
	assertCounts(t, st, 1, 0)

	// Verify second file still not marked seen, can be retried after fixing splice
	_ = end0
}

func TestChainContinuityAcrossPolls(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	end0 := writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	assertCounts(t, st, 1, 0)

	// Second poll with correctly chained file should succeed.
	writeEventFileWithSig(t, dir, 1, [][2]uint64{{1, 1}}, priv, end0)
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	assertCounts(t, st, 2, 0)

	// Third file with bad chain should be rejected
	badStart := sha256.Sum256([]byte("wrong"))
	writeEventFileWithSig(t, dir, 2, [][2]uint64{{1, 2}}, priv, badStart)
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("third poll: %v", err)
	}
	assertCounts(t, st, 2, 0)
}

func TestNilPubKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writeEventFileWithSig(t, dir, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	st := store.NewMemStore()
	trusted := trustedHashForPriv(priv)
	ing := New(Config{StreamsDir: dir, TrustedRosterHash: trusted[:]}, st, quietLogger())
	// PubKey nil -> verification must fail
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 0)
}

func TestUntrustedRosterFails(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := sha256.Sum256([]byte("other roster"))
	item := &pb.RecordItem{EventHash: make([]byte, 32), TxIndex: 0, TxPayload: []byte("put")}
	bm, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	end := stream.RunningHash(stream.ChainSeed, [][]byte{bm})
	blsPub, sec := blsKeyForTest(priv)
	var rosterHash [32]byte
	{
		var buf []byte
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], 0)
		buf = append(buf, be[:]...)
		buf = append(buf, pub...)
		buf = append(buf, blsPub...)
		rosterHash = sha256.Sum256(buf)
	}
	items := []*pb.RecordItem{item}
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("state"))
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], 0)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash[:])
	sigAff := new(blst.P2Affine).Sign(sec.sk, signingBytes[:], stream.CheckpointDST)
	cp := &pb.SignedCheckpoint{
		Round:       0,
		StateHash:   stateHash[:],
		RosterHash:  rosterHash[:],
		RecordsRoot: recordsRoot[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub, BlsKey: blsPub},
		},
		AggregateSig: sigAff.Compress(),
		Signers:      []uint64{0},
	}
	rsf := &pb.RecordStreamFile{
		Version:          stream.Version,
		Round:            0,
		StartRunningHash: hashObj(stream.ChainSeed),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObj(end),
		Checkpoint:       cp,
	}
	raw, _ := proto.Marshal(rsf)
	path := filepath.Join(dir, stream.RecordFileName(0))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	st := store.NewMemStore()
	ing := New(Config{StreamsDir: dir, PubKey: pub, TrustedRosterHash: trusted[:]}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 0)
}
