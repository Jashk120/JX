package store

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema holds the DDL from schema.sql, compiled into the binary.
// Every statement is CREATE TABLE IF NOT EXISTS, so re-applying on each
// startup is a no-op after the first run.
//
//go:embed schema.sql
var schema string

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, dsn string) (*PGStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres dsn: %w", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, cfg)

	if err != nil {
		return nil, fmt.Errorf("failed to create postgres connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &PGStore{pool: pool}, nil
}

func (s *PGStore) Close() { s.pool.Close() }

// Compile-time proof that PGStore satisfies the Store interface.
var _ Store = (*PGStore)(nil)

// The Store interface carries no context.Context (it mirrors MemStore's
// infallible API), so every database operation below runs on
// context.Background(); cancellation policy stays with the pool config.

// PutRecord stores one verified .rsf atomically: the file row plus its items
// and checkpoint children, in a single transaction. Idempotent per round — a
// repeated round is a no-op and never replaces the originally stored data
// (MemStore semantics).
func (s *PGStore) PutRecord(f *pb.RecordStreamFile) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin put_record: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	var cpRound any // nil → SQL NULL when the file carries no checkpoint
	var stateHash any
	var rosterHash any
	if cp := f.GetCheckpoint(); cp != nil {
		cpRound = int64(cp.Round)
		stateHash = cp.StateHash
		rosterHash = cp.RosterHash
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO record_files
			(round, version, start_running_hash, end_running_hash,
			 checkpoint_round, state_hash, roster_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (round) DO NOTHING`,
		int64(f.Round), int32(f.Version),
		f.GetStartRunningHash().GetHash(), f.GetEndRunningHash().GetHash(),
		cpRound, stateHash, rosterHash,
	)
	if err != nil {
		return fmt.Errorf("insert record_files round %d: %w", f.Round, err)
	}
	if tag.RowsAffected() == 0 {
		return nil // duplicate round: no-op, children untouched
	}

	for i, item := range f.Items {
		if _, err := tx.Exec(ctx,
			`INSERT INTO record_items
				(round, item_index, event_hash, tx_index, tx_payload)
			 VALUES ($1, $2, $3, $4, $5)`,
			int64(f.Round), int32(i),
			item.GetEventHash(), int32(item.TxIndex), item.GetTxPayload(),
		); err != nil {
			return fmt.Errorf("insert record_items round %d index %d: %w", f.Round, i, err)
		}
	}
	if cp := f.GetCheckpoint(); cp != nil {
		for _, sig := range cp.Sigs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO checkpoint_sigs (round, signer, sig) VALUES ($1, $2, $3)`,
				int64(cp.Round), int64(sig.Signer), sig.Sig,
			); err != nil {
				return fmt.Errorf("insert checkpoint_sigs round %d signer %d: %w", cp.Round, sig.Signer, err)
			}
		}
		for i, m := range cp.RosterSnapshot {
			if _, err := tx.Exec(ctx,
				`INSERT INTO checkpoint_roster (round, member_index, node_id, key) VALUES ($1, $2, $3, $4)`,
				int64(cp.Round), int32(i), int64(m.NodeId), m.Key,
			); err != nil {
				return fmt.Errorf("insert checkpoint_roster round %d member %d: %w", cp.Round, i, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit put_record round %d: %w", f.Round, err)
	}
	return nil
}

// u64OrNull converts an optional proto uint64 (nil = unset) into a nullable
// BIGINT argument.
func u64OrNull(p *uint64) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

// PutEvents stores events idempotently keyed by (creator, seq) — including
// duplicates within one file — in arrival order. Transactions are written
// only for newly inserted events. Empty files are a no-op.
func (s *PGStore) PutEvents(file *pb.EventStreamFile) error {
	if len(file.Events) == 0 {
		return nil
	}
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin put_events: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ev := range file.Events {
		tag, err := tx.Exec(ctx,
			`INSERT INTO events
				(creator, seq, self_parent, other_parent, timestamp,
				 signature, birth_round, round_received, consensus_timestamp)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (creator, seq) DO NOTHING`,
			int64(ev.Creator), int64(ev.Seq),
			ev.SelfParent, ev.OtherParent, // nil slice = proto absent = SQL NULL
			int64(ev.Timestamp), ev.Signature, int64(ev.BirthRound),
			u64OrNull(ev.RoundReceived), u64OrNull(ev.ConsensusTimestamp),
		)
		if err != nil {
			return fmt.Errorf("insert event (%d,%d): %w", ev.Creator, ev.Seq, err)
		}
		if tag.RowsAffected() == 0 {
			continue // duplicate event: skip its transactions too
		}
		for i, tr := range ev.Transactions {
			if _, err := tx.Exec(ctx,
				`INSERT INTO event_transactions (creator, seq, tx_index, payload)
				 VALUES ($1, $2, $3, $4)`,
				int64(ev.Creator), int64(ev.Seq), int32(i), tr.GetPayload(),
			); err != nil {
				return fmt.Errorf("insert event_transactions (%d,%d) index %d: %w", ev.Creator, ev.Seq, i, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit put_events: %w", err)
	}
	return nil
}

// ListRecords reconstructs RecordStreamFile messages from the normalized
// tables, ordered by round (which is arrival order — chain continuity makes
// rounds ascend). The Store interface cannot express read errors, so on a
// database failure these methods log and degrade to an empty result.
func (s *PGStore) ListRecords() []*pb.RecordStreamFile {
	ctx := context.Background()
	files, err := s.listRecordFiles(ctx)
	if err != nil {
		slog.Default().Error("pg ListRecords: load record_files", "err", err)
		return nil
	}
	if len(files) == 0 {
		return files
	}
	byRound := make(map[uint64]*pb.RecordStreamFile, len(files))
	for _, f := range files {
		byRound[f.Round] = f
	}
	if err := s.attachRecordItems(ctx, byRound); err != nil {
		slog.Default().Error("pg ListRecords: load record_items", "err", err)
		return nil
	}
	if err := s.attachCheckpointSigs(ctx, byRound); err != nil {
		slog.Default().Error("pg ListRecords: load checkpoint_sigs", "err", err)
		return nil
	}
	if err := s.attachRosterSnapshot(ctx, byRound); err != nil {
		slog.Default().Error("pg ListRecords: load checkpoint_roster", "err", err)
		return nil
	}
	return files
}

func (s *PGStore) listRecordFiles(ctx context.Context) ([]*pb.RecordStreamFile, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT round, version, start_running_hash, end_running_hash,
		        checkpoint_round, state_hash, roster_hash
		 FROM record_files ORDER BY round`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*pb.RecordStreamFile
	for rows.Next() {
		var (
			round      int64
			version    int32
			start, end []byte
			cpRound    *int64
			state, ros []byte // NULL → nil
		)
		if err := rows.Scan(&round, &version, &start, &end, &cpRound, &state, &ros); err != nil {
			return nil, err
		}
		f := &pb.RecordStreamFile{
			Version:          uint32(version),
			Round:            uint64(round),
			StartRunningHash: hashObject(start),
			EndRunningHash:   hashObject(end),
		}
		if cpRound != nil {
			f.Checkpoint = &pb.SignedCheckpoint{
				Round:      uint64(*cpRound),
				StateHash:  state,
				RosterHash: ros,
			}
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

func (s *PGStore) attachRecordItems(ctx context.Context, byRound map[uint64]*pb.RecordStreamFile) error {
	rows, err := s.pool.Query(ctx,
		`SELECT round, item_index, event_hash, tx_index, tx_payload
		 FROM record_items ORDER BY round, item_index`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			round     int64
			itemIndex int32
			eventHsh  []byte
			txIndex   int32
			payload   []byte
		)
		if err := rows.Scan(&round, &itemIndex, &eventHsh, &txIndex, &payload); err != nil {
			return err
		}
		f := byRound[uint64(round)]
		if f == nil {
			continue // FK guarantees the parent; defensive skip
		}
		f.Items = append(f.Items, &pb.RecordItem{
			EventHash: eventHsh,
			TxIndex:   uint32(txIndex),
			TxPayload: payload,
		})
	}
	return rows.Err()
}

func (s *PGStore) attachCheckpointSigs(ctx context.Context, byRound map[uint64]*pb.RecordStreamFile) error {
	rows, err := s.pool.Query(ctx,
		`SELECT round, signer, sig FROM checkpoint_sigs ORDER BY round, signer`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			round  int64
			signer int64
			sig    []byte
		)
		if err := rows.Scan(&round, &signer, &sig); err != nil {
			return err
		}
		f := byRound[uint64(round)]
		if f == nil || f.Checkpoint == nil {
			continue // write path keeps children consistent; defensive skip
		}
		f.Checkpoint.Sigs = append(f.Checkpoint.Sigs, &pb.CheckpointSig{
			Round:  uint64(round),
			Signer: uint64(signer),
			Sig:    sig,
		})
	}
	return rows.Err()
}

func (s *PGStore) attachRosterSnapshot(ctx context.Context, byRound map[uint64]*pb.RecordStreamFile) error {
	rows, err := s.pool.Query(ctx,
		`SELECT round, member_index, node_id, key
		 FROM checkpoint_roster ORDER BY round, member_index`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			round    int64
			memberIx int32
			nodeID   int64
			key      []byte
		)
		if err := rows.Scan(&round, &memberIx, &nodeID, &key); err != nil {
			return err
		}
		f := byRound[uint64(round)]
		if f == nil || f.Checkpoint == nil {
			continue
		}
		f.Checkpoint.RosterSnapshot = append(f.Checkpoint.RosterSnapshot, &pb.CheckpointRosterMember{
			NodeId: uint64(nodeID),
			Key:    key,
		})
	}
	return rows.Err()
}

// ListEvents reconstructs Event messages in arrival order (ingested_seq),
// mirroring MemStore's append-order semantics.
func (s *PGStore) ListEvents() []*pb.Event {
	ctx := context.Background()
	txsByEvent, err := s.eventTransactions(ctx)
	if err != nil {
		slog.Default().Error("pg ListEvents: load event_transactions", "err", err)
		return nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT creator, seq, self_parent, other_parent, timestamp,
		        signature, birth_round, round_received, consensus_timestamp
		 FROM events ORDER BY ingested_seq`)
	if err != nil {
		slog.Default().Error("pg ListEvents: load events", "err", err)
		return nil
	}
	defer rows.Close()

	events := make([]*pb.Event, 0)
	for rows.Next() {
		var (
			creator, seq, ts, birth int64
			self, other, sig        []byte // NULL → nil (= proto absent)
			rr, cts                 *int64
		)
		if err := rows.Scan(&creator, &seq, &self, &other, &ts, &sig, &birth, &rr, &cts); err != nil {
			slog.Default().Error("pg ListEvents: scan", "err", err)
			return nil
		}
		ev := &pb.Event{
			Creator:    uint64(creator),
			Seq:        uint64(seq),
			Timestamp:  uint64(ts),
			Signature:  sig,
			BirthRound: uint64(birth),
		}
		if self != nil {
			ev.SelfParent = self
		}
		if other != nil {
			ev.OtherParent = other
		}
		if rr != nil {
			v := uint64(*rr)
			ev.RoundReceived = &v
		}
		if cts != nil {
			v := uint64(*cts)
			ev.ConsensusTimestamp = &v
		}
		key := eventKey{creator: ev.Creator, seq: ev.Seq}
		ev.Transactions = txsByEvent[key] // nil when the event has none
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		slog.Default().Error("pg ListEvents: iterate", "err", err)
		return nil
	}
	return events
}

// eventTransactions loads all transaction payloads grouped by their owning
// event, preserving per-event order via tx_index.
func (s *PGStore) eventTransactions(ctx context.Context) (map[eventKey][]*pb.Transaction, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT creator, seq, tx_index, payload
		 FROM event_transactions ORDER BY creator, seq, tx_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[eventKey][]*pb.Transaction)
	for rows.Next() {
		var (
			creator int64
			seq     int64
			txIndex int32
			payload []byte
		)
		if err := rows.Scan(&creator, &seq, &txIndex, &payload); err != nil {
			return nil, err
		}
		key := eventKey{creator: uint64(creator), seq: uint64(seq)}
		out[key] = append(out[key], &pb.Transaction{Payload: payload})
	}
	return out, rows.Err()
}

// LatestRound reports the highest stored round, or 0 for an empty store.
func (s *PGStore) LatestRound() uint64 {
	var max int64
	err := s.pool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(round), 0) FROM record_files`).Scan(&max)
	if err != nil {
		slog.Default().Error("pg LatestRound", "err", err)
		return 0
	}
	return uint64(max)
}

// hashObject rebuilds a SHA-256 HashObject. The ingester validated
// algorithm==0, length==32 and len(hash)==32 before storing, so the
// constants are safe to reapply on read-back.
func hashObject(b []byte) *pb.HashObject {
	return &pb.HashObject{Algorithm: 0, Length: 32, Hash: b}
}
