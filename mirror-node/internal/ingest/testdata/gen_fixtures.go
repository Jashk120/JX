//go:build ignore

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"os"

	"github.com/JKaIN/mirror-node/internal/stream"
	"github.com/JKaIN/mirror-node/internal/stream/pb"
	blst "github.com/supranational/blst/bindings/go"
	"google.golang.org/protobuf/proto"
)

func main() {
	priv0 := ed25519.NewKeyFromSeed(bytesRepeat(0x01, 32))
	priv1 := ed25519.NewKeyFromSeed(bytesRepeat(0x02, 32))
	priv2 := ed25519.NewKeyFromSeed(bytesRepeat(0x03, 32))
	privs := []ed25519.PrivateKey{priv0, priv1, priv2}
	var members []*pb.CheckpointRosterMember
	var sks []*blst.SecretKey
	for i, priv := range privs {
		pub := priv.Public().(ed25519.PublicKey)
		seed := priv.Seed()
		var ikm [32]byte
		copy(ikm[:], seed)
		sk := blst.KeyGen(ikm[:])
		pk := new(blst.P1Affine).From(sk).Compress()
		members = append(members, &pb.CheckpointRosterMember{
			NodeId: uint64(i),
			Key:    pub,
			BlsKey: pk,
		})
		sks = append(sks, sk)
	}
	var buf []byte
	for _, m := range members {
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], m.NodeId)
		buf = append(buf, be[:]...)
		buf = append(buf, m.Key...)
		buf = append(buf, m.BlsKey...)
	}
	rosterHash := sha256.Sum256(buf)
	items := []*pb.RecordItem{
		{EventHash: bytesRepeat(0xAA, 32), TxIndex: 0, TxPayload: []byte("put:key1=value1")},
		{EventHash: bytesRepeat(0xBB, 32), TxIndex: 1, TxPayload: []byte("put:key2=value2")},
		{EventHash: bytesRepeat(0xCC, 32), TxIndex: 0, TxPayload: []byte("delete:key1")},
	}
	recordsRoot := stream.ComputeRecordsRoot(items)
	stateHash := sha256.Sum256([]byte("test-state-root"))
	var signingBytes [104]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], 1)
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
	aggSig := agg.ToAffine().Compress()
	ckpt := &pb.SignedCheckpoint{
		Round: 1, StateHash: stateHash[:], RosterHash: rosterHash[:], RecordsRoot: recordsRoot[:],
		RosterSnapshot: members, AggregateSig: aggSig, Signers: []uint64{0, 1, 2},
	}
	ckptBytes, err := proto.Marshal(ckpt)
	if err != nil {
		panic(err)
	}
	_ = os.WriteFile("internal/ingest/testdata/valid.ckpt", ckptBytes, 0644)
	// Build valid .rsf with same checkpoint + chained running hashes
	start := stream.ChainSeed
	var serialized [][]byte
	for _, it := range items {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(it)
		serialized = append(serialized, b)
	}
	end := stream.RunningHash(start, serialized)
	rsf := &pb.RecordStreamFile{
		Version: 2, Round: 1,
		StartRunningHash: &pb.HashObject{Algorithm: 0, Length: 32, Hash: start[:]},
		EndRunningHash:   &pb.HashObject{Algorithm: 0, Length: 32, Hash: end[:]},
		Items:            items, Checkpoint: ckpt,
	}
	rsfBytes, _ := proto.Marshal(rsf)
	_ = os.WriteFile("internal/ingest/testdata/valid.rsf", rsfBytes, 0644)
	println("fixtures written")
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
