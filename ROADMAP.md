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
- `strongly_see` is correct and tested, but still uses per-member self-chain walks; the witness-specific optimization from §7.5 (precompute earliest descendant-per-creator per witness) is still unimplemented.
- Gossip/network event propagation (Phase 5), round assignment, fame voting, and final ordering (Phase 4) are now implemented. The live graph is held in memory, but the full event set is durable through the Fjall event log (Phase 8): a restarting node replays the log to rebuild its retained graph without a live peer.

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
> implemented and tested against fixed hand-constructed hashgraphs, and are
> exercised live by the gossip integration suites (Phase 5). Dynamic
> membership is implemented too — `MembershipOp::Add` orders through consensus
> and activates via the roster history at the round after `roundReceived`,
> covered by `protocol/consensus/tests/membership_transition.rs`; deterministic
> transaction execution landed in Phase 7.

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
> consensus order (`protocol/gossip/tests/gossip_integration.rs` and `e2e.rs`).

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
> payloads fail identically on every instance. Membership is now dynamic:
> add-member transactions (`MembershipOp::Add`) order through consensus and
> activate through the roster history (Phase 8). DID is implemented on top
> of the same executor (`executor/state/src/did.rs:DidOp` `0x03`,
> `executor/state/src/executor.rs:apply_did_op`, `docs/DID_method.md`) —
> create/update/rotate/deactivate with signature checks against the prior
> document's verification methods (1..=5 keys) and tombstone deactivation;
> KV ops + DID ops share the `State::Put` path with Merkle-committed proofs.
> Verified with `cargo fmt`, `cargo clippy`, and `cargo test --workspace`.

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

- [x] Sparse Merkle tree over the KV state; `state_hash` in `.cp` becomes
      the Merkle root
- [x] Incremental root updates (a `Put`/`Delete` touches O(depth) nodes) for
      cheap per-round checkpoint hashing
- [x] Per-key proof of inclusion without shipping the whole state
      (mirror-friendly)
- [x] Restart/reconnect verification switches from hashing serialized bytes
      to tree rebuild + root compare
- [x] Fjall as the KV state backend: `State`'s `BTreeMap` moves to an LSM
      partition with WAL; the `.snap` file disappears

### New file types (mirror consumption)

- [x] Event stream file: append-only, chained, every gossip event — the
      offline DAG source; a mirror stores all events and points from each
      event to its transactions
- [x] Record stream file (`.rsf`): ordered finalized transactions per round
- [x] Record stream anchored to the threshold-signed checkpoint state root,
      so a mirror verifies consensus output cryptographically rather than
      trusting any single node (source-agnostic)
- [x] Cross-language record format decodable by the Go mirror



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
> integration test. The Merkle tree state (point 2) is also implemented: a
> sparse Merkle tree over the KV state (Hiero-style domain-separated SHA-256
> nodes) replaces the flat `Sha256(State::to_bytes())` as the checkpoint
> `state_hash`, with incremental O(depth) root updates, per-key inclusion
> proofs, and tree-rebuild root comparison on restart/reconnect; a
> `data/FORMAT_VERSION` stamp makes the commitment change a loud, self-enforcing
> wipe. The last item of point 2 is done too: `State`'s `BTreeMap` moved to a
> Fjall LSM partition with WAL (`state::StateDb`, `<data>/statedb/`), and the
> per-round `.snap` files disappeared — each accepted checkpoint's state now
> lives in the state database's `snap` keyspace, which restart recovery,
> verification, and reconnect serving read from (`FORMAT_VERSION` bumped to 3).
> The mirror stream files (point 3) are implemented too — a new
> `protocol/stream` crate emits, into `<data>/streams/`, the two protobuf file
> types a mirror consumes: `events-<n>.esf` (every gossip event this node
> inserted, in topological order — the offline DAG source, registered as a
> second event sink next to the event log) and `round-<r>.rsf` (one file per
> decided round, the round's finalized transactions in `consensus_order` plus
> its threshold-signed `SignedCheckpoint` as the state-root anchor, emitted
> from `accept_checkpoint`). Both are chained by a running hash (Hiero-style,
> domain-separated SHA-256) and signed per-file (`.esf_sig`/`.rsf_sig`,
> Ed25519 over the whole file + the metadata). Both writers run on background
> tasks over an ordered channel, so the consensus hot path never blocks on
> disk. The verifier (`stream::verify`) recomputes the chain, checks the
> signature files, and enforces the embedded checkpoint quorum
> (`valid * 3 > total * 2`) against the embedded roster — what the Go mirror
> does from the files alone; determinism, chain-integrity, mirror-consumer,
> and live-wiring tests verify it. Phase 8 is complete; parallel execution is
> tracked in Phase 9.

---

## Phase 9 — Scaling (Locked)

> Design locked in `docs/OPTIMIZATION.md` (2026-08-20). Two tracks converge
> at the finalized-event boundary and do not block each other. Services
> (HCS/HTS/DID) below are deferred until the scaling tracks prove
> deterministic equivalence at 100 nodes.

### Gossip track — 1,000-node gossip

Target: 100 nodes first, interfaces sized for 1,000.

```
G0  Instrument current gossip (success rate, RTT, delta size, spread, lag)
G1  QUIC transport (SyncTransport impl, TcpTransport stays as fallback)
G2  Concurrent bounded fanout (k_min..k_max, JoinSet, per-peer Mutex)
G3  Dynamic peer scoring (frontier usefulness, success EWMA, latency,
    freshness, diversity, recent-selection penalty, failure/backoff)
G4  Adaptive fanout/interval (frontier gap, propagation lag, congestion,
    hard bounds — no gossip storm)
G5  Compression + batching (zstd on SyncResponse, chunked streams;
    IBLT/bloom summary only if O(N) >20% at target N)
G6  100 / 500 / 1,000-node benchmarks (localhost + VPS mesh)
```

- [ ] G0 — gossip instrumentation
- [ ] G1 — `QuicTransport: SyncTransport` (`protocol/gossip/src/transport.rs`, `quinn` + SPKI pin)
- [ ] G2 — bounded concurrent fanout (`protocol/gossip/src/node.rs` driver)
- [ ] G3 — scored peer selection (`protocol/gossip/src/peer_manager.rs` + `peer/scoring.rs`)
- [ ] G4 — adaptive fanout/interval controller
- [ ] G5 — compression + chunked SyncResponse
- [ ] G6 — 100/500/1,000-node bench harness

Design choices locked: QUIC is transport only (not peer selection), bounded
active QUIC pool 10–30 (tunable, not protocol constant), persistent QUIC for
hot peers / resumption for cold, topology-aware diversity, gossip scheduling
detached from consensus.

### Execution track — deterministic parallel execution

Migration: optional `access_list` + serial fallback (not mandatory).
Maturity: `100% serial → 80/20 → 95%+ parallel / <5% genuinely serial`.
`Unknown` is measured, not a permanent escape hatch.

```
E0  Benchmark + serial oracle/invariants (State::to_bytes equality)
E1  Access-list wire format + typed domains (proto AccessKey enum)
E2  Deterministic dependency scheduler (Levels, Kahn, deterministic tie-break)
E3  Scheduler correctness / property / fuzz (State A == State B)
E4  Parallel execution over versioned snapshot (overlay, spawn_blocking)
E5  Deterministic commit + batched Merkle/Fjall
E6  State partitioning / MVCC optimization
E7  Consensus/execution pipeline decoupling (bounded mpsc)
E8  Crypto/serialization optimization (batch verify, zero-copy)
```

- [ ] E0 — bench harness + serial oracle
- [ ] E1 — `Transaction.access_list` (protobuf `AccessList` / `AccessKey`), typed domains `Account / HtsToken / HcsTopic / ContractStorage / StateKey / Unknown`
- [ ] E2 — `executor/scheduler` (Levels, conflict `writes ∩ (reads ∪ writes)`)
- [ ] E3 — property/fuzz: flatten(Levels) == consensus_order, parallel == serial
- [ ] E4 — versioned snapshot + parallel workers
- [ ] E5 — deterministic commit in consensus_order + batched Merkle/Fjall
- [ ] E6 — per-domain shards / MVCC / hot-set write-behind
- [ ] E7 — `GossipNode` channel-owned executor, not `Mutex<Executor>`
- [ ] E8 — batch Ed25519, zero-copy decode, arena per batch

Convergence: both tracks meet at `state::finalized_events(&hg)` →
`GossipNode::process_finalized_rounds` boundary; build and bench independently.

### Services (HCS/HTS deferred until G6/E3 equivalence proven; DID — implemented)

- [ ] HCS
- [ ] HTS
- [x] DID — `did:jkain` (`executor/state/src/did.rs:DidId`/`DidDocument`/`DidOp`, `executor/state/src/op.rs:0x03`, `executor/state/src/executor.rs:apply_did_op`, spec `docs/DID_method.md`)

**Account / Crypto Service**
- [ ] Accounts
- [ ] Keys
- [ ] Signatures
- [ ] Transfers
- [ ] Key rotation
- [ ] Account recovery
- [ ] Threshold/multisig authorization

**Consensus Service**
- [ ] Ordered messages/events
- [ ] Consensus timestamps
- [ ] Event streams
- [ ] Application-defined state machines

**Token / Asset Service**
- [ ] Fungible assets
- [ ] NFTs
- [ ] Ownership
- [ ] Transfers
- [ ] Mint/burn
- [ ] Provenance
- [ ] Asset lifecycle

**Data / File Service**
- [ ] Immutable files
- [ ] Content-addressed data
- [ ] Metadata
- [ ] Data availability primitives

**Identity Service**
- [x] DID creation — `DidOp::is_creation` + `Executor::apply_did_op` creation path (`executor/state/src/executor.rs:162`), self-signed check against `document.verification_methods[signed_by]`
- [x] DID Documents — `DidDocument` 1..=5 `VerifyingKey`s + `deactivated` tombstone (`executor/state/src/did.rs:124`), binary `encode`/`decode` with deterministic rejects
- [x] Verification methods — capped 5, enforced at `DidDocument::new` and `DidDocument::decode` (`executor/state/src/did.rs:134`, `executor/state/src/did.rs:161`), `UnknownSigner`/`InvalidSignature` errors (`executor/state/src/executor.rs:169`)
- [x] Authentication relationships — `signed_by: u8` index into prior/current document's `verification_methods` (`executor/state/src/did.rs:185`, `executor/state/src/executor.rs:164`)
- [x] Key rotation — update `DidDocument` via `Put` authorized by prior doc's key (`executor/state/src/executor.rs:174`, tests `did_update_succeeds_with_current_verification_method`)
- [x] DID lifecycle — create → update/rotate → deactivation tombstone (not `Delete`, keeps Merkle proof — `docs/DID_method.md:102`, `executor/state/src/executor.rs:195`), `AlreadyDeactivated`/`IdentifierAlreadyExists`/`UnknownIdentifier` guards

**Credential Service**
- [ ] Verifiable Credential issuance
- [ ] Credential verification
- [ ] Credential status
- [ ] Revocation
- [ ] Expiration
- [ ] Credential schemas

**Attestation Service**
- [ ] Signed claims
- [ ] Issuer → subject relationships
- [ ] Attestation creation/revocation
- [ ] Timestamping
- [ ] Proof references

**Naming Service**
- [ ] Human-readable names
- [ ] Name → account/DID/asset/service resolution
- [ ] Ownership
- [ ] Name transfer
- [ ] Name expiry

**Capability / Authorization Service**
- [ ] Permissions
- [ ] Delegation
- [ ] Capabilities
- [ ] Scoped access
- [ ] Expiration
- [ ] Revocation

---

## Phase 10 — Future

- [ ] Privacy
- [ ] Compute layer

Sliding-window DAG in RAM with snapshots (remaining after G-track lands)
