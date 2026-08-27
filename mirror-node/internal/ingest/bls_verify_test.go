package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

func buildThreeMemberRoster(t *testing.T) ([]*pb.CheckpointRosterMember, []*blst.SecretKey) {
	t.Helper()
	var members []*pb.CheckpointRosterMember
	var sks []*blst.SecretKey
	for i := 0; i < 3; i++ {
		seed := make([]byte, 32)
		for j := range seed {
			seed[j] = byte(i + 1)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		var ikm [32]byte
		copy(ikm[:], seed)
		sk := blst.KeyGen(ikm[:])
		pk := new(blst.P1Affine).From(sk).Compress()
		members = append(members, &pb.CheckpointRosterMember{NodeId: uint64(i), Key: pub, BlsKey: pk})
		sks = append(sks, sk)
	}
	return members, sks
}

func buildBLSPayload(t *testing.T, round uint64, items []*pb.RecordItem, members []*pb.CheckpointRosterMember, sks []*blst.SecretKey) (*pb.SignedCheckpoint, [32]byte) {
	t.Helper()
	var buf []byte
	for _, m := range members {
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], m.NodeId)
		buf = append(buf, be[:]...)
		buf = append(buf, m.Key...)
		buf = append(buf, m.BlsKey...)
	}
	rosterHash := sha256.Sum256(buf)
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("state-for-bls-tests"))
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], round)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash[:])
	var sigs []*blst.P2Affine
	for _, sk := range sks {
		sig := new(blst.P2Affine).Sign(sk, signingBytes[:], stream.CheckpointDST)
		sigs = append(sigs, sig)
	}
	agg := new(blst.P2Aggregate)
	agg.Aggregate(sigs, false)
	ckpt := &pb.SignedCheckpoint{
		Round: round, StateHash: stateHash[:], RosterHash: rosterHash[:], RecordsRoot: recordsRoot[:],
		PrevCheckpointHash: make([]byte, 32),
		RosterSnapshot: members, AggregateSig: agg.ToAffine().Compress(),
		Signers: []uint64{0, 1, 2},
	}
	return ckpt, rosterHash
}

func TestBLSRecordsRootTamperedItemFails(t *testing.T) {
	members, sks := buildThreeMemberRoster(t)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put:a=b")},
		{EventHash: bytesRepeat(0xBB, 32), TxIndex: 1, TxPayload: []byte("put:c=d")},
	}
	ckpt, rosterHash := buildBLSPayload(t, 5, items, members, sks)
	// Tamper second item payload
	tamperedItems := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put:a=b")},
		{EventHash: bytesRepeat(0xBB, 32), TxIndex: 1, TxPayload: []byte("put:c=EVIL")},
	}
	var ser [][]byte
	for _, it := range tamperedItems {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		ser = append(ser, b)
	}
	end := stream.RunningHash(stream.ChainSeed, ser)
	// But checkpoint's records_root is for original items, so verification should fail via records_root mismatch
	// Use non-tampered ckpt but tampered items in file
	rsf := &pb.RecordStreamFile{
		Version: stream.Version, Round: 5,
		StartRunningHash: hashObj(stream.ChainSeed),
		EndRunningHash:   hashObj(end),
		Items:            tamperedItems, Checkpoint: ckpt,
	}
	raw, _ := proto.Marshal(rsf)
	if err := stream.VerifyRecordFile(raw, nil, nil, rosterHash[:]); err == nil {
		t.Fatal("expected records_root mismatch failure, got nil")
	}
	// Also the raw's end hash mismatches if we recomputed correctly? The test focuses on records_root mismatch path.
	// Direct checkpoint binding should still detect records_root mismatch even if running hash matches.
}

func TestBLSWrongAggregateFails(t *testing.T) {
	members, sks := buildThreeMemberRoster(t)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put")},
	}
	ckpt, rosterHash := buildBLSPayload(t, 7, items, members, sks)
	// Flip a byte in aggregate sig
	ckpt.AggregateSig[0] ^= 0xFF
	var ser [][]byte
	for _, it := range items {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		ser = append(ser, b)
	}
	end := stream.RunningHash(stream.ChainSeed, ser)
	rsf := &pb.RecordStreamFile{
		Version: stream.Version, Round: 7,
		StartRunningHash: hashObj(stream.ChainSeed),
		EndRunningHash:   hashObj(end),
		Items:            items, Checkpoint: ckpt,
	}
	raw, _ := proto.Marshal(rsf)
	if err := stream.VerifyRecordFile(raw, nil, nil, rosterHash[:]); err == nil {
		t.Fatal("expected BLS aggregate failure, got nil")
	}
}

func TestBLSUnanchoredRosterRejectedWhenTrustedSet(t *testing.T) {
	members, sks := buildThreeMemberRoster(t)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put")},
	}
	ckpt, _ := buildBLSPayload(t, 9, items, members, sks)
	wrongTrusted := sha256.Sum256([]byte("wrong-roster-hash-anchor"))
	var ser [][]byte
	for _, it := range items {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		ser = append(ser, b)
	}
	end := stream.RunningHash(stream.ChainSeed, ser)
	rsf := &pb.RecordStreamFile{
		Version: stream.Version, Round: 9,
		StartRunningHash: hashObj(stream.ChainSeed),
		EndRunningHash:   hashObj(end),
		Items:            items, Checkpoint: ckpt,
	}
	raw, _ := proto.Marshal(rsf)
	if err := stream.VerifyRecordFile(raw, nil, nil, wrongTrusted[:]); err == nil {
		t.Fatal("expected roster_hash anchor mismatch, got nil")
	}
	// Empty trusted should pass (embedded accepted)
	if err := stream.VerifyRecordFile(raw, nil, nil, nil); err != nil {
		t.Fatalf("empty trusted should accept embedded: %v", err)
	}
}

func TestBLSQuorumRequiresTwoThirds(t *testing.T) {
	members, sks := buildThreeMemberRoster(t)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put")},
	}
	// Only 1 signer of 3 (need 3 for 3 total: 3*? 1*3=3 <=3*2=6 false -> need 3*? actually 3 members need 3 signers for >2/3)
	ckpt, rosterHash := buildBLSPayload(t, 11, items, members, sks[:1])
	ckpt.Signers = []uint64{0}
	// Rebuild aggregate with just 1 sig
	var buf []byte
	for _, m := range members {
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], m.NodeId)
		buf = append(buf, be[:]...)
		buf = append(buf, m.Key...)
		buf = append(buf, m.BlsKey...)
	}
	rosterHash2 := sha256.Sum256(buf)
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("state-for-bls-tests"))
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], 11)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash2[:])
	sig := new(blst.P2Affine).Sign(sks[0], signingBytes[:], stream.CheckpointDST)
	ckpt.AggregateSig = sig.Compress()
	ckpt.RecordsRoot = recordsRoot[:]
	ckpt.RosterHash = rosterHash2[:]
	ckpt.PrevCheckpointHash = make([]byte, 32)
	var ser [][]byte
	for _, it := range items {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		ser = append(ser, b)
	}
	end := stream.RunningHash(stream.ChainSeed, ser)
	rsf := &pb.RecordStreamFile{
		Version: stream.Version, Round: 11,
		StartRunningHash: hashObj(stream.ChainSeed),
		EndRunningHash:   hashObj(end),
		Items:            items, Checkpoint: ckpt,
	}
	raw, _ := proto.Marshal(rsf)
	if err := stream.VerifyRecordFile(raw, nil, nil, rosterHash[:]); err == nil {
		t.Fatal("expected quorum failure (1 of 3), got nil")
	}
	// Ensure the re-built case with 1 signer also fails even with correct trusted
	if err := stream.VerifyRecordFile(raw, nil, nil, rosterHash2[:]); err == nil {
		t.Fatal("expected quorum failure even with matching trusted")
	}
}

func TestRemoteBLSHappyPathAgainstHttptestServingFixtures(t *testing.T) {
	members, sks := buildThreeMemberRoster(t)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put:key=value")},
	}
	ckpt, rosterHash := buildBLSPayload(t, 20, items, members, sks)
	var ser [][]byte
	for _, it := range items {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		ser = append(ser, b)
	}
	end := stream.RunningHash(stream.ChainSeed, ser)
	rsf := &pb.RecordStreamFile{
		Version: stream.Version, Round: 20,
		StartRunningHash: hashObj(stream.ChainSeed),
		EndRunningHash:   hashObj(end),
		Items:            items, Checkpoint: ckpt,
	}
	rsfBytes, _ := proto.Marshal(rsf)
	// Also serve valid.ckpt fixture bytes if needed via testdata helper? Just use rsf.
	// Event file
	priv := ed25519.NewKeyFromSeed(bytesRepeat(0x99, 32))
	event := &pb.Event{Creator: 1, Seq: 0}
	evb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	evEnd := stream.RunningHash(stream.ChainSeed, [][]byte{evb})
	esf := &pb.EventStreamFile{
		Version: stream.Version, StartRunningHash: hashObj(stream.ChainSeed),
		Events: []*pb.Event{event}, EndRunningHash: hashObj(evEnd),
	}
	esfBytes, _ := proto.Marshal(esf)
	// sig file for event
	hash := sha256.Sum256(esfBytes)
	var md []byte
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], stream.Version)
	md = append(md, ver[:]...)
	md = append(md, stream.ChainSeed[:]...)
	md = append(md, evEnd[:]...)
	mdHash := sha256.Sum256(md)
	sigFile := &pb.SignatureFile{
		FileSignature:     &pb.SignatureObject{Type: 0, Length: 64, Signature: ed25519.Sign(priv, hash[:]), HashObject: &pb.HashObject{Algorithm: 0, Length: 32, Hash: hash[:]}},
		MetadataSignature: &pb.SignatureObject{Type: 0, Length: 64, Signature: ed25519.Sign(priv, mdHash[:]), HashObject: &pb.HashObject{Algorithm: 0, Length: 32, Hash: mdHash[:]}},
	}
	sigBytes, _ := proto.Marshal(sigFile)
	esfSigBytes := append([]byte{stream.SigFileVersion}, sigBytes...)

	files := map[string][]byte{
		stream.RecordFileName(20):                         rsfBytes,
		stream.EventFileName(0):                           esfBytes,
		stream.SignatureFileName(stream.EventFileName(0)): esfSigBytes,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/blocks" {
			var sb strings.Builder
			for k := range files {
				sb.WriteString(k + "\n")
			}
			w.Write([]byte(sb.String()))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/blocks/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/blocks/")
			if b, ok := files[name]; ok {
				w.Write(b)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pub := priv.Public().(ed25519.PublicKey)
	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: rosterHash[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(st.ListRecords()) != 1 {
		t.Fatalf("expected 1 record, got %d", len(st.ListRecords()))
	}
	if len(st.ListEvents()) != 1 {
		t.Fatalf("expected 1 event, got %d", len(st.ListEvents()))
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
