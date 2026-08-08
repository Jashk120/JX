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
> in `gossip/tests/` covers the full stack on localhost: 2- and 4-node
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
- [ ] VPS deployment

> **Phase 6 status**: gossip-level integration on localhost is done — a lone
> node serves syncs (single-node), and 2- and 4-node clusters exchange
> transactions, converge on identical event sets, and finalize the same
> consensus order (`gossip/tests/gossip_integration.rs` and `e2e.rs`). What
> remains is real-machine networking: manual `PeerInfo` configuration
> (address + SPKI fingerprint), firewall/open-port setup, and a VPS ↔ local
> pair. A NAT'd home node can only initiate dials, but that still converges —
> each sync round is a full bidirectional exchange over one connection.
> Full-system integration with transaction execution is Phase 8.

---

## Phase 7 — Native Services

- [ ] HCS
- [ ] HTS
- [ ] DID

---

## Phase 8 — Executor

- [ ] State
- [ ] Transaction execution
- [ ] Deterministic execution

---

## Phase 9 — Future

- [ ] Parallel execution
- [ ] Privacy
- [ ] Compute layer

Parallel state database / lock-free scheduler 
Aggressive gossip optimization (QUIC, batching, compression) 
Sliding-window DAG in RAM with snapshots
Efficient LSM + Merkle state storage 
Batch/GPU signature verification
