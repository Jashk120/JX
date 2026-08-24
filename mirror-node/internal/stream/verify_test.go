package stream

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

func hashObjTest(h [32]byte) *pb.HashObject {
	return &pb.HashObject{Algorithm: 0, Length: 32, Hash: h[:]}
}

func sigObjectsFor(t *testing.T, fileBytes, metadata []byte, priv ed25519.PrivateKey) *pb.SignatureFile {
	t.Helper()
	fd := sha256.Sum256(fileBytes)
	md := sha256.Sum256(metadata)
	return &pb.SignatureFile{
		FileSignature: &pb.SignatureObject{
			Type:      0,
			Length:    64,
			Signature: ed25519.Sign(priv, fd[:]),
			HashObject: &pb.HashObject{
				Algorithm: 0,
				Length:    32,
				Hash:      fd[:],
			},
		},
		MetadataSignature: &pb.SignatureObject{
			Type:      0,
			Length:    64,
			Signature: ed25519.Sign(priv, md[:]),
			HashObject: &pb.HashObject{
				Algorithm: 0,
				Length:    32,
				Hash:      md[:],
			},
		},
	}
}

func TestVerifyEventFileFailsClosedWithoutPubKey(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ev := &pb.Event{Creator: 1, Seq: 0}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(ev)
	end := RunningHash(ChainSeed, [][]byte{b})
	esf := &pb.EventStreamFile{
		Version:          Version,
		StartRunningHash: hashObjTest(ChainSeed),
		Events:           []*pb.Event{ev},
		EndRunningHash:   hashObjTest(end),
	}
	raw, _ := proto.Marshal(esf)
	meta := make([]byte, 0, 68)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, ChainSeed[:]...)
	meta = append(meta, end[:]...)
	sig := sigObjectsFor(t, raw, meta, priv)

	if err := VerifyEventFile(raw, sig, nil); err == nil {
		t.Fatal("expected error with nil pubkey")
	}
	if err := VerifyEventFile(raw, nil, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("expected error with nil sig")
	}
}

func TestVerifyRecordFileFailsClosedWithoutTrustedHash(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	item := &pb.RecordItem{EventHash: make([]byte, 32), TxIndex: 0, TxPayload: []byte("put")}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	end := RunningHash(ChainSeed, [][]byte{b})
	var rosterBuf [40]byte
	binary.BigEndian.PutUint64(rosterBuf[:8], 0)
	copy(rosterBuf[8:], pub)
	rosterHash := sha256.Sum256(rosterBuf[:])
	stateHash := sha256.Sum256([]byte("state"))
	signing := make([]byte, 0, 72)
	var roundBE [8]byte
	binary.BigEndian.PutUint64(roundBE[:], 0)
	signing = append(signing, roundBE[:]...)
	signing = append(signing, stateHash[:]...)
	signing = append(signing, rosterHash[:]...)
	cp := &pb.SignedCheckpoint{
		Round:          0,
		StateHash:      stateHash[:],
		RosterHash:     rosterHash[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{{NodeId: 0, Key: pub}},
		Sigs:           []*pb.CheckpointSig{{Round: 0, Signer: 0, Sig: ed25519.Sign(priv, signing)}},
	}
	rsf := &pb.RecordStreamFile{
		Version:          Version,
		Round:            0,
		StartRunningHash: hashObjTest(ChainSeed),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObjTest(end),
		Checkpoint:       cp,
	}
	raw, _ := proto.Marshal(rsf)
	meta := make([]byte, 0, 76)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, ChainSeed[:]...)
	meta = append(meta, end[:]...)
	var rbe [8]byte
	binary.BigEndian.PutUint64(rbe[:], 0)
	meta = append(meta, rbe[:]...)
	sig := sigObjectsFor(t, raw, meta, priv)

	if err := VerifyRecordFile(raw, sig, pub, nil); err == nil {
		t.Fatal("expected error with nil trusted hash")
	}
	if err := VerifyRecordFile(raw, sig, pub, make([]byte, 0)); err == nil {
		t.Fatal("expected error with empty trusted hash")
	}
	wrong := sha256.Sum256([]byte("wrong"))
	if err := VerifyRecordFile(raw, sig, pub, wrong[:]); err == nil {
		t.Fatal("expected error with wrong trusted hash")
	}
	// correct should pass
	if err := VerifyRecordFile(raw, sig, pub, rosterHash[:]); err != nil {
		t.Fatalf("correct trusted hash should pass: %v", err)
	}
}

func TestVerifyCheckpointQuorumDuplicateDenominator(t *testing.T) {
	// Build roster with duplicate node_id entries: two entries for node 0 with same key.
	// Raw count is 2, deduped is 1. With 1 valid sig, quorum should be 1*3>1*2 true.
	// If denominator used raw count (2), 1*3>2*2 false would incorrectly reject.
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	var rosterBuf [40]byte
	binary.BigEndian.PutUint64(rosterBuf[:8], 0)
	copy(rosterBuf[8:], pub)
	rosterHash := sha256.Sum256(rosterBuf[:])
	stateHash := sha256.Sum256([]byte("state2"))
	signing := make([]byte, 0, 72)
	var roundBE [8]byte
	binary.BigEndian.PutUint64(roundBE[:], 5)
	signing = append(signing, roundBE[:]...)
	signing = append(signing, stateHash[:]...)
	signing = append(signing, rosterHash[:]...)
	cp := &pb.SignedCheckpoint{
		Round:      5,
		StateHash:  stateHash[:],
		RosterHash: rosterHash[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub},
			{NodeId: 0, Key: pub},
		},
		Sigs: []*pb.CheckpointSig{
			{Round: 5, Signer: 0, Sig: ed25519.Sign(priv, signing)},
		},
	}
	if err := verifyCheckpointQuorum(cp, rosterHash[:]); err != nil {
		t.Fatalf("duplicate roster quorum should use deduped total: %v", err)
	}
	// With raw denominator, this would have failed. Verify deduped path passes.
}

func TestVerifyRecordFileNilPubKeyFails(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	item := &pb.RecordItem{EventHash: make([]byte, 32), TxIndex: 0, TxPayload: []byte("put")}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	end := RunningHash(ChainSeed, [][]byte{b})
	var rosterBuf [40]byte
	binary.BigEndian.PutUint64(rosterBuf[:8], 0)
	copy(rosterBuf[8:], pub)
	rosterHash := sha256.Sum256(rosterBuf[:])
	stateHash := sha256.Sum256([]byte("state"))
	signing := make([]byte, 0, 72)
	var roundBE [8]byte
	binary.BigEndian.PutUint64(roundBE[:], 0)
	signing = append(signing, roundBE[:]...)
	signing = append(signing, stateHash[:]...)
	signing = append(signing, rosterHash[:]...)
	cp := &pb.SignedCheckpoint{
		Round:          0,
		StateHash:      stateHash[:],
		RosterHash:     rosterHash[:],
		RosterSnapshot: []*pb.CheckpointRosterMember{{NodeId: 0, Key: pub}},
		Sigs:           []*pb.CheckpointSig{{Round: 0, Signer: 0, Sig: ed25519.Sign(priv, signing)}},
	}
	rsf := &pb.RecordStreamFile{
		Version:          Version,
		Round:            0,
		StartRunningHash: hashObjTest(ChainSeed),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObjTest(end),
		Checkpoint:       cp,
	}
	raw, _ := proto.Marshal(rsf)
	meta := make([]byte, 0, 76)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, ChainSeed[:]...)
	meta = append(meta, end[:]...)
	var rbe [8]byte
	binary.BigEndian.PutUint64(rbe[:], 0)
	meta = append(meta, rbe[:]...)
	sig := sigObjectsFor(t, raw, meta, priv)

	if err := VerifyRecordFile(raw, sig, nil, rosterHash[:]); err == nil {
		t.Fatal("expected error with nil pubkey")
	}
}
