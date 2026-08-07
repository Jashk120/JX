# JKain Implementation Roadmap

## Phase 0 — Project Setup

- [x] Cargo workspace
- [x] Monorepo
- [x] Git
- [x] Primitive crate
- [x] Crypto crate
- [x] Consensus crate
- [ ] Gossip crate

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
- Gossip/network event propagation, round assignment, fame voting, final ordering, and persistent storage are not implemented yet.

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

- [ ] TCP
- [ ] Peer manager
- [ ] Message protocol

### Synchronization

- [ ] Sync request
- [ ] Sync response
- [ ] Delta exchange

---

## Phase 6 — Integration

- [ ] Single node
- [ ] Two nodes
- [ ] Four nodes
- [ ] VPS deployment

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
