# storage

Durable storage for a JKain consensus node (Phase 8).

Implements the Fjall-backed append-only event log: every verified event is
appended on insert, keyed by `EventHash`, in a two-partition layout inside
one Fjall `Database`:

- `by_seq` — a monotonically increasing `u64` BE key -> encoded
  `consensus::RetainedEvent`. The key is the log's own global insertion
  counter, so the partition preserves insertion order (which is topological
  order) for replay.
- `by_hash` — `EventHash` -> the same encoded record, for dedup, lookup,
  and pruning.

plus a `roster` keyspace holding the persisted roster history, so a restart
can verify each replayed event against the roster active at its birth round.

The log is decoupled from the checkpoint files: the checkpoint (`.cp`) commits
state and roster at a round — with the exact state bytes kept in the state
database's `snap` keyspace — while the log carries the complete retained event
set since the prune floor.

## Contents

- `EventLog` — the log: `append`, `set_round_received` (records ordering as
  events are finalized), `replay` (the whole set in insertion order),
  `prune` (mirrors an in-memory prune), roster-history persistence, and
  `flush`.
- `EventSink` — the lossy sink interface the gossip layer and daemon drive
  (errors are logged and dropped, so the consensus-hot path never fails on
  storage hiccups). `EventLog` implements it.
- `atomic` — shared atomic-write helper (`temp + sync_all + rename + dir
  fsync`) used by both `storage` checkpoint files and `stream` signature
  files so the crash-durability dance cannot drift.

## Design

- Internal writes are serialized so the `by_seq` counter and the
  two-keyspace updates stay atomic; appends are idempotent by `EventHash`.
- The value in both keyspaces is
  `[log_seq: u64 BE] || [encoded RetainedEvent]`, letting a `by_hash` lookup
  locate the corresponding `by_seq` record for pruning.
- Records are encoded with `consensus::encode_retained_event` (the same
  type the reconnect protocol uses), keeping internal Rust-to-Rust storage
  on the canonical binary encoding — not protobuf.
- `round_received` is recorded lazily by the node as ordering completes, so
  a replay reproduces the exact finalized order.

Dependencies: `primitives`, `crypto`, `consensus` (for the record type and
codec), `fjall`.
