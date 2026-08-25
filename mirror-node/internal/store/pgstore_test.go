package store

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
	"google.golang.org/protobuf/proto"
)

// newTestPGStore returns a PGStore against the PostgreSQL instance pointed to
// by MIRROR_TEST_PG_DSN (e.g. postgres://postgres:dev@localhost:5432/postgres).
// Tests skip unless the variable is set, so `go test ./...` stays green
// without a database. Every test starts from truncated tables, making the
// suite order-independent and rerunnable.
func newTestPGStore(t *testing.T) *PGStore {
	t.Helper()
	dsn := os.Getenv("MIRROR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("MIRROR_TEST_PG_DSN not set; PostgreSQL store tests skipped")
	}
	st, err := NewPostgresStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.pool.Exec(context.Background(),
		"TRUNCATE record_items, record_files, checkpoint_sigs, checkpoint_roster, event_transactions, events",
	); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	return st
}

func hashFor(b byte) *pb.HashObject {
	return &pb.HashObject{Algorithm: 0, Length: 32, Hash: bytes.Repeat([]byte{b}, 32)}
}

func TestPGPutRecordDeduplicatesByRound(t *testing.T) {
	st := newTestPGStore(t)
	// Files reach the store only after ingest verification, so they always
	// carry valid running-hash objects; tests construct them accordingly.
	first := &pb.RecordStreamFile{Version: 1, Round: 7,
		StartRunningHash: hashFor(0x70), EndRunningHash: hashFor(0x71)}
	replay := &pb.RecordStreamFile{Version: 1, Round: 7,
		StartRunningHash: hashFor(0x70), EndRunningHash: hashFor(0x71)}

	for _, f := range []*pb.RecordStreamFile{first, replay} {
		if err := st.PutRecord(f); err != nil {
			t.Fatalf("PutRecord: %v", err)
		}
	}
	got := st.ListRecords()
	if len(got) != 1 {
		t.Fatalf("stored %d record files, want 1", len(got))
	}
	if got[0].Round != 7 || got[0].Version != 1 {
		t.Fatalf("stored record = (round %d, version %d), want (7, 1)", got[0].Round, got[0].Version)
	}
	if latest := st.LatestRound(); latest != 7 {
		t.Fatalf("LatestRound = %d, want 7", latest)
	}
}

func TestPGPutEventsDeduplicatesByCreatorAndSeq(t *testing.T) {
	st := newTestPGStore(t)
	event := func(creator, seq uint64) *pb.Event {
		return &pb.Event{Creator: creator, Seq: seq, Signature: []byte{}}
	}
	// replay overlaps first entirely and repeats (1,1) within itself
	first := &pb.EventStreamFile{Events: []*pb.Event{event(1, 0), event(1, 1)}}
	replay := &pb.EventStreamFile{Events: []*pb.Event{event(1, 1), event(2, 0)}}

	for _, f := range []*pb.EventStreamFile{first, replay} {
		if err := st.PutEvents(f); err != nil {
			t.Fatalf("PutEvents: %v", err)
		}
	}
	want := [][2]uint64{{1, 0}, {1, 1}, {2, 0}}

	got := st.ListEvents()
	if len(got) != len(want) {
		t.Fatalf("stored %d events, want %d", len(got), len(want))
	}
	for i, k := range want {
		if got[i].GetCreator() != k[0] || got[i].GetSeq() != k[1] {
			t.Errorf("event %d = (creator %d, seq %d), want (%d, %d)",
				i, got[i].GetCreator(), got[i].GetSeq(), k[0], k[1])
		}
	}
}

func TestPGEmptyFilesAreNoops(t *testing.T) {
	st := newTestPGStore(t)
	if err := st.PutEvents(&pb.EventStreamFile{}); err != nil {
		t.Fatalf("PutEvents: %v", err)
	}
	if n := len(st.ListEvents()); n != 0 {
		t.Fatalf("stored %d events, want 0", n)
	}
	if latest := st.LatestRound(); latest != 0 {
		t.Fatalf("LatestRound = %d, want 0 on empty store", latest)
	}
}

// TestPGRoundTripFidelity verifies that Put* followed by List* through a
// SECOND store instance (fresh pool, same database) reconstructs protobuf
// messages equal to the originals — including optional-field presence,
// repeated children and checkpoint parts.
func TestPGRoundTripFidelity(t *testing.T) {
	st := newTestPGStore(t)

	wantRecord := &pb.RecordStreamFile{
		Version:          1,
		Round:            42,
		StartRunningHash: hashFor(0xAA),
		EndRunningHash:   hashFor(0xBB),
		Items: []*pb.RecordItem{
			{EventHash: bytes.Repeat([]byte{0x01}, 32), TxIndex: 0, TxPayload: []byte("put:k=v")},
			{EventHash: bytes.Repeat([]byte{0x02}, 32), TxIndex: 3, TxPayload: []byte{}},
		},
		Checkpoint: &pb.SignedCheckpoint{
			Round:      42,
			StateHash:  bytes.Repeat([]byte{0x03}, 32),
			RosterHash: bytes.Repeat([]byte{0x04}, 32),
			RosterSnapshot: []*pb.CheckpointRosterMember{
				{NodeId: 1, Key: bytes.Repeat([]byte{0x05}, 32)},
				{NodeId: 2, Key: bytes.Repeat([]byte{0x06}, 32)},
			},
			Sigs: []*pb.CheckpointSig{
				{Round: 42, Signer: 1, Sig: bytes.Repeat([]byte{0x07}, 64)},
				{Round: 42, Signer: 2, Sig: bytes.Repeat([]byte{0x08}, 64)},
			},
		},
	}
	if err := st.PutRecord(wantRecord); err != nil {
		t.Fatalf("PutRecord: %v", err)
	}

	wantEvents := &pb.EventStreamFile{
		Version:          1,
		StartRunningHash: hashFor(0x10),
		EndRunningHash:   hashFor(0x11),
		Events: []*pb.Event{
			{
				Creator:     1,
				SelfParent:  bytes.Repeat([]byte{0x21}, 32),
				OtherParent: bytes.Repeat([]byte{0x23}, 32),
				Timestamp:   100,
				Signature:   bytes.Repeat([]byte{0x22}, 64),
				Seq:         0,
				BirthRound:  5,
			},
			{
				Creator:            2,
				Timestamp:          101,
				Signature:          []byte{},
				Seq:                9,
				BirthRound:         6,
				RoundReceived:      proto.Uint64(42),
				ConsensusTimestamp: proto.Uint64(777),
				Transactions: []*pb.Transaction{
					{Payload: []byte("tx-a")},
					{Payload: []byte{}},
					{Payload: []byte("tx-c")},
				},
			},
		},
	}
	if err := st.PutEvents(wantEvents); err != nil {
		t.Fatalf("PutEvents: %v", err)
	}

	reopened, err := NewPostgresStore(context.Background(), os.Getenv("MIRROR_TEST_PG_DSN"))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	gotRecords := reopened.ListRecords()
	if len(gotRecords) != 1 {
		t.Fatalf("reopened ListRecords = %d files, want 1", len(gotRecords))
	}
	if !proto.Equal(wantRecord, gotRecords[0]) {
		t.Fatalf("record round trip mismatch:\n got: %+v\nwant: %+v", gotRecords[0], wantRecord)
	}

	gotEvents := reopened.ListEvents()
	if len(gotEvents) != 2 {
		t.Fatalf("reopened ListEvents = %d events, want 2", len(gotEvents))
	}
	for i, want := range wantEvents.Events {
		if !proto.Equal(want, gotEvents[i]) {
			t.Fatalf("event %d round trip mismatch:\n got: %+v\nwant: %+v", i, gotEvents[i], want)
		}
	}
}
