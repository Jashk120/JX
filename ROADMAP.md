# JKain Implementation Roadmap

## Phase 0 — Project Setup

- [x] Cargo workspace
- [x] Monorepo
- [x] Git
- [x] Primitive crate
- [x] Crypto crate
- [ ] Consensus crate
- [ ] Gossip crate

---

## Phase 1 — Core Primitives

### Event

- [x] Event
- [x] EventHash
- [ ] Tests

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
- [ ] Transaction model

---

## Phase 2 — Crypto

### Hashing

- [x] Hashable trait
- [x] SHA-256 implementation
- [x] Canonical serialization
- [~] Event hashing tests

### Signatures

- [ ] Ed25519
- [ ] Sign event
- [ ] Verify event
- [ ] Signature tests

---

## Phase 3 — Hashgraph

### Storage

- [ ] Hashgraph
- [ ] Insert event
- [ ] Parent lookup
- [ ] Children lookup

### Traversal

- [ ] Ancestor
- [ ] Can See
- [ ] Strongly See

### Tests

- [ ] Graph tests
- [ ] Traversal tests

---

## Phase 4 — Consensus

### Round Assignment

- [ ] Divide rounds

### Witnesses

- [ ] Witness detection

### Virtual Voting

- [ ] Vote
- [ ] Coin rounds
- [ ] Fame

### Ordering

- [ ] Round received
- [ ] Consensus timestamp
- [ ] Final ordering

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