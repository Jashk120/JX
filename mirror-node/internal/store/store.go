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

// MemStore is an in-memory Store.
type MemStore struct {
	mu      sync.RWMutex
	events  []*pb.Event
	records []*pb.RecordStreamFile
}

func NewMemStore() *MemStore { return &MemStore{} }

func (m *MemStore) PutEvents(f *pb.EventStreamFile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, f.Events...)
	return nil
}

func (m *MemStore) PutRecord(f *pb.RecordStreamFile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
