// Package store provides the mirror node's local persistence abstraction.
// The initial implementation is an in-memory store so the scaffold builds
// and tests run without external DB dependencies. A persistent backend
// (SQLite/Postgres) can replace it behind the same interface.
package store

import (
	"sync"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// Store is the minimal interface the ingester and API need.
type Store interface {
	PutEvents(file *pb.EventStreamFile) error
	PutRecord(file *pb.RecordStreamFile) error
	ListRecords() []*pb.RecordStreamFile
	ListEvents() []*pb.Event
	LatestRound() uint64
}

// MemStore is an in-memory Store. Put* methods are idempotent: records are
// deduplicated by round and events by (creator, seq), so re-ingesting a file
// already stored is a no-op.
type MemStore struct {
	mu         sync.RWMutex
	events     []*pb.Event
	records    []*pb.RecordStreamFile
	seenRounds map[uint64]struct{}
	seenEvents map[eventKey]struct{}
}

// eventKey identifies an event by its creator and per-creator sequence
// number — the same identity the API exposes.
type eventKey struct {
	creator uint64
	seq     uint64
}

func NewMemStore() *MemStore { return &MemStore{} }

// PutEvents appends the events not yet stored; events already present
// (including duplicates within f) are skipped.
func (m *MemStore) PutEvents(f *pb.EventStreamFile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seenEvents == nil {
		m.seenEvents = make(map[eventKey]struct{})
	}
	for _, ev := range f.Events {
		key := eventKey{creator: ev.Creator, seq: ev.Seq}
		if _, dup := m.seenEvents[key]; dup {
			continue
		}
		m.seenEvents[key] = struct{}{}
		m.events = append(m.events, ev)
	}
	return nil
}

// PutRecord appends the record file unless a file for the same round was
// already stored, in which case it is a no-op.
func (m *MemStore) PutRecord(f *pb.RecordStreamFile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seenRounds == nil {
		m.seenRounds = make(map[uint64]struct{})
	}
	if _, dup := m.seenRounds[f.Round]; dup {
		return nil
	}
	m.seenRounds[f.Round] = struct{}{}
	m.records = append(m.records, f)
	return nil
}

func (m *MemStore) ListRecords() []*pb.RecordStreamFile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*pb.RecordStreamFile, len(m.records))
	copy(out, m.records)
	return out
}

func (m *MemStore) ListEvents() []*pb.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*pb.Event, len(m.events))
	copy(out, m.events)
	return out
}

func (m *MemStore) LatestRound() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var max uint64
	for _, r := range m.records {
		if r.Round > max {
			max = r.Round
		}
	}
	return max
}
