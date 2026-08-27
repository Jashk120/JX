package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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

func buildSigBytes(t *testing.T, fileBytes, metadata []byte, priv ed25519.PrivateKey) []byte {
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
	return out
}

func buildEventFileBytes(t *testing.T, index uint64, pairs [][2]uint64, priv ed25519.PrivateKey, start [32]byte) (fileBytes []byte, sigBytes []byte, end [32]byte) {
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
	end = stream.RunningHash(start, serialized)
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
	meta := make([]byte, 0, 68)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], stream.Version)
	meta = append(meta, ver[:]...)
	meta = append(meta, start[:]...)
	meta = append(meta, end[:]...)
	sig := buildSigBytes(t, raw, meta, priv)
	return raw, sig, end
}

func buildRecordFileBytes(t *testing.T, round uint64, priv ed25519.PrivateKey, start [32]byte) (fileBytes []byte, sigBytes []byte, end [32]byte) {
	t.Helper()
	item := &pb.RecordItem{
		EventHash: make([]byte, 32),
		TxIndex:   0,
		TxPayload: []byte("put"),
	}
	mb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	serialized := [][]byte{mb}
	end = stream.RunningHash(start, serialized)
	pub := priv.Public().(ed25519.PublicKey)
	blsPub, sec := blsKeyForTestRemote(priv)
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
	binary.BigEndian.PutUint64(signingBytes[0:8], round)
	copy(signingBytes[8:40], recordsRoot[:])
	copy(signingBytes[40:72], stateHash[:])
	copy(signingBytes[72:104], rosterHash[:])
	sigAff := new(blst.P2Affine).Sign(sec.sk, signingBytes[:], stream.CheckpointDST)
	cp := &pb.SignedCheckpoint{
		Round:       round,
		StateHash:   stateHash[:],
		RosterHash:  rosterHash[:],
		RecordsRoot: recordsRoot[:],
		PrevCheckpointHash: make([]byte, 32),
		RosterSnapshot: []*pb.CheckpointRosterMember{
			{NodeId: 0, Key: pub, BlsKey: blsPub},
		},
		AggregateSig: sigAff.Compress(),
		Signers:      []uint64{0},
	}
	rsf := &pb.RecordStreamFile{
		Version:          stream.Version,
		Round:            round,
		StartRunningHash: hashObj(start),
		Items:            []*pb.RecordItem{item},
		EndRunningHash:   hashObj(end),
		Checkpoint:       cp,
	}
	raw, err := proto.Marshal(rsf)
	if err != nil {
		t.Fatalf("marshal rsf: %v", err)
	}
	return raw, nil, end
}

func blsKeyForTestRemote(priv ed25519.PrivateKey) ([]byte, *blstSecretRemote) {
	seed := priv.Seed()
	var ikm [32]byte
	copy(ikm[:], seed)
	sk := blst.KeyGen(ikm[:])
	pk := new(blst.P1Affine).From(sk).Compress()
	return pk, &blstSecretRemote{sk: sk, pk: pk}
}

type blstSecretRemote struct {
	sk *blst.SecretKey
	pk []byte
}

func fakeBlockNode(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/blocks" {
			var sb strings.Builder
			for k := range files {
				sb.WriteString(k)
				sb.WriteString("\n")
			}
			_, _ = w.Write([]byte(sb.String()))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/blocks/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/blocks/")
			if b, ok := files[name]; ok {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(handler)
}

func fakeBlockNodeWithList(t *testing.T, files map[string][]byte, list []string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/blocks" {
			_, _ = w.Write([]byte(strings.Join(list, "\n")))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/blocks/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/blocks/")
			if b, ok := files[name]; ok {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(handler)
}

func TestRemoteHappyFirstPollIngests(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}, {1, 1}}, priv, stream.ChainSeed)
	recordRaw, _, _ := buildRecordFileBytes(t, 0, priv, stream.ChainSeed)

	files := map[string][]byte{
		stream.EventFileName(0):                           eventRaw,
		stream.SignatureFileName(stream.EventFileName(0)): eventSig,
		stream.RecordFileName(0):                          recordRaw,
	}
	srv := fakeBlockNode(t, files)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)
}

func TestRemoteSecondPollAddsNothingNew(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}, {1, 1}}, priv, stream.ChainSeed)
	recordRaw, _, _ := buildRecordFileBytes(t, 0, priv, stream.ChainSeed)

	files := map[string][]byte{
		stream.EventFileName(0):                           eventRaw,
		stream.SignatureFileName(stream.EventFileName(0)): eventSig,
		stream.RecordFileName(0):                          recordRaw,
	}
	srv := fakeBlockNode(t, files)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	ctx := context.Background()
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)
	if err := ing.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	assertCounts(t, st, 2, 1)
}

func TestRemoteUnreachableMidPollReturnsError(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("round-0.rsf\n"))
	}))
	url := srv.URL
	srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: url}, st, quietLogger())
	err := ing.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	assertCounts(t, st, 0, 0)

	// Also test list unreachable directly
	srv2 := httptest.NewServer(http.NotFoundHandler())
	srv2.Close()
	ing2 := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv2.URL}, st, quietLogger())
	err2 := ing2.RunOnce(context.Background())
	if err2 == nil {
		t.Fatal("expected error for unreachable list")
	}
}

func TestRemoteOneName404SkippedRestIngested(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	recordRaw, _, _ := buildRecordFileBytes(t, 0, priv, stream.ChainSeed)

	files := map[string][]byte{
		stream.EventFileName(0):                           eventRaw,
		stream.SignatureFileName(stream.EventFileName(0)): eventSig,
		stream.RecordFileName(0):                          recordRaw,
	}
	missingName := stream.RecordFileName(99)
	list := []string{stream.EventFileName(0), stream.SignatureFileName(stream.EventFileName(0)), stream.RecordFileName(0), missingName}
	srv := fakeBlockNodeWithList(t, files, list)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)

	// Second poll should still succeed for existing files and keep skipping missing
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)
}

func TestRemoteAbsentSigDeferred(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, _, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	// Only file, no sig in map/list
	files := map[string][]byte{
		stream.EventFileName(0): eventRaw,
	}
	list := []string{stream.EventFileName(0)}
	srv := fakeBlockNodeWithList(t, files, list)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 0, 0)

	// Now sig arrives
	_, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	files[stream.SignatureFileName(stream.EventFileName(0))] = eventSig
	list2 := []string{stream.EventFileName(0), stream.SignatureFileName(stream.EventFileName(0))}
	srv2 := fakeBlockNodeWithList(t, files, list2)
	defer srv2.Close()
	ing.cfg.BlockNodeURL = srv2.URL
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce after sig: %v", err)
	}
	assertCounts(t, st, 1, 0)
}

func TestRemoteIgnoresNonStreamSuffixes(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	files := map[string][]byte{
		stream.EventFileName(0):                           eventRaw,
		stream.SignatureFileName(stream.EventFileName(0)): eventSig,
		"random.txt": []byte("ignore me"),
		"other.ckpt": []byte("ignore"),
	}
	list := []string{stream.EventFileName(0), stream.SignatureFileName(stream.EventFileName(0)), "random.txt", "other.ckpt"}
	srv := fakeBlockNodeWithList(t, files, list)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 0)
}

func TestRemoteWhitespaceTrimming(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	trusted := trustedHashForPriv(priv)

	eventRaw, eventSig, _ := buildEventFileBytes(t, 0, [][2]uint64{{1, 0}}, priv, stream.ChainSeed)
	recordRaw, _, _ := buildRecordFileBytes(t, 0, priv, stream.ChainSeed)
	files := map[string][]byte{
		stream.EventFileName(0):                           eventRaw,
		stream.SignatureFileName(stream.EventFileName(0)): eventSig,
		stream.RecordFileName(0):                          recordRaw,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/blocks" {
			body := fmt.Sprintf("  %s  \n\n  %s \n %s\n", stream.EventFileName(0), stream.SignatureFileName(stream.EventFileName(0)), stream.RecordFileName(0))
			_, _ = w.Write([]byte(body))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/blocks/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/blocks/")
			if b, ok := files[name]; ok {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	st := store.NewMemStore()
	ing := New(Config{PubKey: pub, TrustedRosterHash: trusted[:], BlockNodeURL: srv.URL}, st, quietLogger())
	if err := ing.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	assertCounts(t, st, 1, 1)
}
