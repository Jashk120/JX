package store

import (
	"testing"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

func TestPutRecordDeduplicatesByRound(t *testing.T) {
	st := NewMemStore()
	first := &pb.RecordStreamFile{Version: 1, Round: 7}
	replay := &pb.RecordStreamFile{Version: 1, Round: 7}

	for _, f := range []*pb.RecordStreamFile{first, replay} {
		if err := st.PutRecord(f); err != nil {
			t.Fatalf("PutRecord: %v", err)
		}
	}
	got := st.ListRecords()
	if len(got) != 1 {
		t.Fatalf("stored %d record files, want 1", len(got))
	}
	if got[0] != first {
		t.Fatal("re-ingested file must not replace the originally stored one")
	}
	if latest := st.LatestRound(); latest != 7 {
		t.Fatalf("LatestRound = %d, want 7", latest)
	}
}

func TestPutEventsDeduplicatesByCreatorAndSeq(t *testing.T) {
	st := NewMemStore()
	event := func(creator, seq uint64) *pb.Event {
		return &pb.Event{Creator: creator, Seq: seq}
	}
	// replay overlaps first entirely and repeats (1,1) within itself
	first := &pb.EventStreamFile{Events: []*pb.Event{event(1, 0), event(1, 1)}}
	replay := &pb.EventStreamFile{Events: []*pb.Event{event(1, 1), event(2, 0)}}

	for _, f := range []*pb.EventStreamFile{first, replay} {
		if err := st.PutEvents(f); err != nil {
			t.Fatalf("PutEvents: %v", err)
		}
	}
	want := [3]struct {
		creator uint64
		seq     uint64
	}{{1, 0}, {1, 1}, {2, 0}}

	got := st.ListEvents()
	if len(got) != len(want) {
		t.Fatalf("stored %d events, want %d", len(got), len(want))
	}
	for i, k := range want {
		if got[i].Creator != k.creator || got[i].Seq != k.seq {
			t.Errorf("event %d = (creator %d, seq %d), want (%d, %d)",
				i, got[i].Creator, got[i].Seq, k.creator, k.seq)
		}
	}
}

func TestEmptyFilesAreNoops(t *testing.T) {
	st := NewMemStore()
	if err := st.PutEvents(&pb.EventStreamFile{}); err != nil {
		t.Fatalf("PutEvents: %v", err)
	}
	if n := len(st.ListEvents()); n != 0 {
		t.Fatalf("stored %d events, want 0", n)
	}
}
