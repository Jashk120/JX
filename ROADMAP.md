# JKain Implementation Roadmap

## Phase 0 — Project Setup

- [x] Cargo workspace
- [x] Monorepo
- [x] Git
- [x] Primitive crate
- [x] Crypto crate
- [x] Consensus crate
- [x] Gossip crate

---

## Phase 1 — Core Primitives

### Event

- [x] Event
- [x] EventHash
- [x] Tests

### Node

- [x] NodeId
- [ ] Tests

### Signature

- [x] Signature
- [ ] Tests

### Timestamp

- [x] Timestamp
- [ ] Tests

### Transaction

- [x] Transaction
- [~] Transaction model (minimal payload-only scaffold)

---

## Phase 2 — Crypto

### Hashing

- [x] Hashable trait
- [x] SHA-256 implementation
- [x] Canonical serialization
- [x] Event hashing tests

### Signatures

- [x] Ed25519
- [x] Sign event
- [x] Verify event
- [x] Signature tests

---

## Phase 3 — Hashgraph

### Storage

- [x] Hashgraph
- [x] Insert event (verified events, duplicate/missing-parent/unknown-creator errors)
- [~] Parent lookup (available through event records; dedicated helper API remains)
- [x] Children lookup

### Traversal

- [x] Ancestor
- [x] Can See
- [x] Strongly See

### Tests

- [x] Graph tests
- [x] Traversal tests (including differential/reference tests and fork cases)

### Current Implementation Notes

- The hashgraph stores events and maintains incremental per-member ancestor sequence metadata.
- Fork detection is implemented with observer-relative `see` checks and a first-seen branch policy.
- `strongly_see` is correct and tested, but still uses per-member self-chain walks; the witness-specific optimization is deferred to round-assignment work.
- Gossip/network event propagation (Phase 5), round assignment, fame voting, and final ordering (Phase 4) are now implemented. Persistent storage is not implemented yet — the hashgraph is held in memory for the life of a process.

---

## Phase 4 — Consensus

### Round Assignment

- [x] Divide rounds

### Witnesses

- [x] Witness detection

### Virtual Voting

- [x] Vote
- [x] Coin rounds
- [x] Fame

### Ordering

- [x] Round received
- [x] Consensus timestamp
- [x] Final ordering

> **Phase 4 status**: rounds, witnesses, virtual voting (fame), and order
> finalization (`roundReceived` / `consensusTimestamp` / final order) are all
> implemented and tested against fixed hand-constructed hashgraphs. Dynamic
> membership and transaction execution remain future work (Phases 6/8).

---

## Phase 5 — Gossip

### Networking

- [x] TCP
- [x] Peer manager
- [x] Message protocol

### Synchronization

- [x] Sync request
- [x] Sync response
- [x] Delta exchange

> **Phase 5 status**: the `gossip` crate implements the consensus-hot path of
> Consensus Spec §5 end to end — pinned TLS 1.3 transport over TCP, uniform-
> random peer selection, canonical length-prefixed frames, frontier-based
> delta exchange, and the per-round event-creation rule. The end-to-end suite
> in `protocol/gossip/tests/` covers the full stack on localhost: 2- and 4-node
> clusters converge and reconcile after a partition, transaction payloads
> survive gossip byte-for-byte, and every node derives an identical finalized
> consensus order. Negative coverage exercises the failure modes — wrong TLS
> pin, forged signatures, unknown creators, missing parents, malformed
> frames, dead peers, and protocol violations — all rejected without taking a
> node down.

---

## Phase 6 — Integration

- [x] Single node
- [x] Two nodes
- [x] Four nodes
- [x] VPS deployment

> **Phase 6 status**: gossip-level integration on localhost is done — a lone
> node serves syncs (single-node), and 2- and 4-node clusters exchange
> transactions, converge on identical event sets, and finalize the same
> consensus order (`protocol/gossip/tests/gossip_integration.rs` and `e2e.rs`). What
> remains is real-machine networking: manual `PeerInfo` configuration
> (address + SPKI fingerprint), firewall/open-port setup, and a VPS ↔ local
> pair. A NAT'd home node can only initiate dials, but that still converges —
> each sync round is a full bidirectional exchange over one connection.
> Full-system integration with transaction execution is Phase 8.

---

## Phase 7 — Native Services


- [x] State
- [x] Transaction execution
- [x] Deterministic execution

> **Phase 7 status**: the `state` crate implements a deterministic
> executor over a key-value `State` (opaque byte-string keys/values in a
> `BTreeMap`). `Transaction` payloads decode from a tiny explicit binary
> format (`Op::Put`/`Op::Delete`; big-endian `u32` length prefixes) and are
> applied to the state through pure, deterministic functions — no wall-clock
> reads, randomness, or I/O inside execution. `finalized_events` consumes
> `Hashgraph::consensus_order` round-by-round unchanged, so the executor
> reuses the exact ordering `order.rs` produces instead of defining its own.
> The determinism suite (`executor/state/tests/deterministic.rs`) runs the same
> order through two independently-constructed `State`/`Executor` instances
> and asserts identical state both by equality and by canonical bytes; it
> also verifies finalized order follows consensus order and that malformed
> payloads fail identically on every instance. Membership remains static;
> add/remove-member transactions are deferred. Verified with `cargo fmt`,
> `cargo clippy`, and `cargo test --workspace`.

---

## Phase 8 — Durable State & Mirror Support (Consensus Side)

The consensus-node side of the mirror-node story: durable, replayable
storage plus the file types a mirror consumes. Everything here is what the
*consensus node* must persist and emit so any program can reconstruct the
DAG and verify consensus output offline — the mirror node itself (a
separate Go project) is downstream of this phase.

### Fjall (LSM) event log

- [x] Fjall-backed append-only event log: every verified event appended on
      insert, keyed by `EventHash`, decoupled from `.cp`/`.snap`
- [x] Two-partition layout: `by_seq` (monotonic `u64` BE key → record,
      preserving insertion = topological order for replay) and `by_hash`
      (`EventHash` → record, for dedup/lookup)
- [x] Replay-on-startup: rebuild the graph from the local log instead of
      `request_reconnect()` — a node recovers independently, no live peer
- [x] Full-rebuild replay verifies each event against the roster active at
      its birth round (roster/key verification exercised at graph rebuild
      time, not just at checkpoint load)
- [x] The log stores the complete event set, so any program can rebuild the
      DAG from it
- [x] Log pruning mirroring `RETENTION_ROUNDS` (bounded disk; history older
      than the prune floor is covered by the checkpoint)

### Merkle tree state

- [ ] Sparse Merkle tree over the KV state; `state_hash` in `.cp` becomes
      the Merkle root
- [ ] Incremental root updates (a `Put`/`Delete` touches O(depth) nodes) for
      cheap per-round checkpoint hashing
- [ ] Per-key proof of inclusion without shipping the whole state
      (mirror-friendly)
- [ ] Restart/reconnect verification switches from hashing serialized bytes
      to tree rebuild + root compare
- [ ] Fjall as the KV state backend: `State`'s `BTreeMap` moves to an LSM
      partition with WAL; the `.snap` file disappears

### New file types (mirror consumption)

- [ ] Event stream file: append-only, chained, every gossip event — the
      offline DAG source; a mirror stores all events and points from each
      event to its transactions
- [ ] Record stream file (`.rcd`): ordered finalized transactions per round
- [ ] Record stream anchored to the threshold-signed checkpoint state root,
      so a mirror verifies consensus output cryptographically rather than
      trusting any single node (source-agnostic)
- [ ] Cross-language record format decodable by the Go mirror

### Parallel execution

- [ ] Batch transaction execution across finalized rounds
- [ ] Deterministic parallelism: result independent of thread scheduling
- [ ] Parallel signature verification

> **Phase 8 status**: the Fjall event log (point 1) is implemented — a new
> `protocol/storage` crate appends every verified event into a two-keyspace
> Fjall database (`by_seq` insertion order for replay, `by_hash` for
> dedup/lookup), records `roundReceived` as events are finalized, persists the
> roster history on membership change, and prunes in lockstep with the
> in-memory graph (`RETENTION_ROUNDS`). A restarting node replays the log to
> rebuild its retained graph independently — each record signature-verified
> against the roster active at its birth round — so `request_reconnect()` is
> only a fallback for pre-event-log data. Verified with `cargo test`: codec
> round-trips, append dedup, replay equivalence, prune, and a no-peer restart
> integration test. Remaining in Phase 8: Merkle state (point 2), event/
> record stream files (point 3), and parallel execution (point 4).

---

## Phase 9 — Executor
- [ ] HCS
- [ ] HTS
- [ ] DID

---

## Phase 10 — Future

- [ ] Privacy
- [ ] Compute layer

Parallel state database / lock-free scheduler 
Aggressive gossip optimization (QUIC, batching, compression) 
Sliding-window DAG in RAM with snapshots
Efficient LSM + Merkle state storage 
Batch/GPU signature verification
