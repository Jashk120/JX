# JX-DB

### A Versioned, Parallel-Optimized State Database for JKain

**Working Draft — v0.1**

---

# 1. Abstract

JX-DB is a high-performance state storage engine designed for deterministic distributed ledger execution. It separates three traditionally coupled concerns:

* Physical data storage
* State indexing
* Cryptographic state commitment

This separation allows each subsystem to evolve independently while maintaining deterministic state across all consensus nodes.

JX-DB is optimized for:

* Extremely fast account lookup
* High write throughput
* Parallel transaction execution
* Efficient snapshot generation
* Incremental state verification
* Deterministic replay

It is **not** intended to be a general-purpose database.

---

# 2. Design Philosophy

The storage engine follows one fundamental principle:

> Storage exists to execute transactions efficiently.
> Verification exists to prove the resulting state.

These are treated as independent systems.

Storage is optimized for performance.

Verification is optimized for integrity.

---

# 3. Architecture

```
                 Execution Engine
                        │
                        ▼
              Parallel Transaction Scheduler
                        │
                        ▼
                 Version Manager
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
  Account Index                 Append Storage
        │                               │
        └───────────────┬───────────────┘
                        ▼
                  State Snapshot
                        │
                        ▼
              State Commitment Layer
                        │
                        ▼
                  Global State Root
```

---

# 4. Core Components

## 4.1 Account Index

Every account is identified by its account identifier.

The index maps

```
AccountID

↓

Current Version Pointer
```

The index always points to the latest committed version.

Previous versions remain available until cleanup.

The index should remain memory resident whenever possible.

Expected lookup complexity:

```
O(1)
```

---

## 4.2 Append Storage

State is never modified in place.

Every state update creates a new version.

Example

```
Version 1

Balance = 100

↓

Transfer

↓

Version 2

Balance = 70
```

Old versions remain immutable.

Only the index changes.

Benefits

* Sequential writes
* SSD friendly
* Crash recovery
* Historical state reconstruction

---

## 4.3 Version Records

Each stored version contains

```
Account ID

Version Number

Consensus Timestamp

Previous Version Pointer

Serialized State

State Hash
```

Every version forms an immutable history.

---

## 4.4 State Snapshot

Execution always operates against a consistent snapshot.

Transactions never observe partially updated state.

A snapshot contains

```
Latest Version Pointer

+

Metadata

+

Commitment Root
```

Snapshots can later be archived or pruned.

---

## 4.5 State Commitment Layer

The commitment layer is independent of storage.

Its only responsibility is producing a deterministic root hash representing current network state.

Input

```
Latest Account States
```

Output

```
Single State Root
```

The commitment layer does not determine storage layout.

---

# 5. Parallel Execution Support

Every transaction declares

```
Read Set

Write Set
```

Example

```
Reads

Account A

Writes

Account B
```

The scheduler determines conflicts before execution.

Independent transactions execute simultaneously.

Conflicting transactions execute deterministically.

Storage provides version isolation.

---

# 6. Version Isolation

Transactions execute against immutable versions.

Example

```
Account

Version 12

↓

Transaction A

↓

Version 13
```

Another transaction still reading Version 12 is unaffected.

No transaction observes partial writes.

---

# 7. Commit Process

```
Receive Ordered Transactions

↓

Scheduler

↓

Parallel Execution

↓

Create New Versions

↓

Update Account Index

↓

Generate State Commitment

↓

Commit Snapshot
```

The commitment root becomes part of the finalized state.

---

# 8. Memory Model

Memory is divided into several logical regions.

## Hot State

Frequently accessed accounts.

Stored in RAM.

---

## Warm State

Less frequently accessed.

Memory mapped by the operating system.

---

## Cold State

Historical versions.

Stored on persistent storage.

Loaded only when required.

---

# 9. Snapshot System

Periodic snapshots are generated.

Each snapshot contains

```
Current Account Index

Current Versions

Commitment Root

Metadata
```

Nodes can synchronize using snapshots instead of replaying the entire ledger.

---

# 10. Historical Queries

Historical queries use immutable version chains.

Example

```
Account

↓

Version 41

↓

Version 40

↓

Version 39
```

Historical state can be reconstructed without affecting current execution.

---

# 11. Garbage Collection

Old versions remain until they satisfy cleanup policy.

Cleanup never affects:

* current state
* active snapshots
* running transactions

Garbage collection runs independently from execution.

---

# 12. Determinism

Consensus requires every node to produce identical state.

JX-DB therefore guarantees

* deterministic serialization
* deterministic hashing
* deterministic version ordering
* deterministic snapshot generation

No implementation may rely upon

* thread scheduling
* iteration order of unordered containers
* wall clock time
* floating point arithmetic

---

# 13. Recovery

After failure

```
Load Latest Snapshot

↓

Restore Account Index

↓

Verify Commitment Root

↓

Replay Missing Transactions

↓

Resume Operation
```

No manual intervention is required.

---

# 14. Scalability Goals

The architecture is designed for

* millions of accounts
* high transaction throughput
* concurrent execution
* incremental snapshots
* efficient replication
* deterministic recovery

The storage engine should remain modular so future indexing strategies, commitment algorithms, and storage formats can evolve independently without changing the execution engine.

---

# 15. Future Extensions

Potential future work includes

* Incremental commitment updates
* Sparse commitment structures
* Verkle-based commitments
* Tiered storage
* Compression of historical versions
* State expiry
* Distributed archival nodes
* Zero-copy serialization
* NUMA-aware allocation
* Adaptive caching
* Hardware acceleration for hashing

---

# 16. Guiding Principle

JX-DB is designed around a single architectural rule:

> **Storage manages data.**
>
> **Execution changes data.**
>
> **The commitment layer proves data.**
>
> **No subsystem performs another subsystem's responsibility.**
