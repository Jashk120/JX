# JKain Optimization Strategy

> **Status:** Design locked — not yet implemented. This document is the
> authoritative reference for scaling JKain beyond the current 2–4 node
> baseline to 100 nodes (first target) and 1,000 nodes (interface target).
> It supersedes any prior ad-hoc notes on gossip or execution performance.

## Table of Contents

1. [Principles](#1-principles)
2. [Layered Scaling Model](#2-layered-scaling-model)
3. [Gossip Track — 1,000-Node Gossip](#3-gossip-track--1000-node-gossip)
   - [3.1 Current Baseline and Bottlenecks](#31-current-baseline-and-bottlenecks)
   - [3.2 Target Architecture](#32-target-architecture)
   - [3.3 QUIC Transport](#33-quic-transport)
   - [3.4 Bounded Concurrent Fanout](#34-bounded-concurrent-fanout)
   - [3.5 Dynamic Smart Peer Selection](#35-dynamic-smart-peer-selection)
   - [3.6 Adaptive Fanout and Interval](#36-adaptive-fanout-and-interval)
   - [3.7 Persistent Hot Peers](#37-persistent-hot-peers)
   - [3.8 Peer Diversity](#38-peer-diversity)
   - [3.9 Separation of Gossip Scheduling and Consensus](#39-separation-of-gossip-scheduling-and-consensus)
   - [3.10 Compression and Batching](#310-compression-and-batching)
4. [Execution Track — Deterministic Parallel Execution](#4-execution-track--deterministic-parallel-execution)
   - [4.1 Transaction Access Declaration](#41-transaction-access-declaration)
   - [4.2 Typed Access Domains](#42-typed-access-domains)
   - [4.3 Migration — Optional + Serial Fallback](#43-migration--optional--serial-fallback)
   - [4.4 Deterministic Dependency Scheduler](#44-deterministic-dependency-scheduler)
   - [4.5 Execution Model](#45-execution-model)
   - [4.6 State Layer](#46-state-layer)
   - [4.7 Consensus/Execution Decoupling](#47-consensusexecution-decoupling)
   - [4.8 Cryptography and Serialization](#48-cryptography-and-serialization)
5. [Convergence — The Finalized-Event Boundary](#5-convergence--the-finalized-event-boundary)
6. [Implementation Sequence](#6-implementation-sequence)
7. [Metrics and Success Criteria](#7-metrics-and-success-criteria)
8. [Wire Format and Compatibility](#8-wire-format-and-compatibility)
9. [File Impact Map](#9-file-impact-map)
10. [Risks and Open Questions](#10-risks-and-open-questions)

---

## 1. Principles

1. **Measure before optimizing.** No gossip or execution change ships without a
   baseline bench on the current code.
2. **Correctness over throughput.** Every optimization must preserve
   deterministic state equivalence: same genesis + same `consensus_order` →
   byte-identical `State::to_bytes()` on every honest node.
3. **Conservative hot path.** The consensus-critical gossip transport was
   deliberately TCP+TLS 1.3 (`protocol/gossip/src/transport.rs:44`,
   `docs/JKain_Whitepaper.md:59`). QUIC is adopted behind the same
   `SyncTransport` abstraction so TCP remains as benchmark/fallback.
4. **Bounded resources.** No unbounded connection sets, no unbounded fanout,
   no unbounded queueing. Every bound is explicit and tunable.
5. **Scheduling before execution.** Prove that independence can be identified
   deterministically before executing independently.

---

## 2. Layered Scaling Model

```
Hashgraph consensus        — establishes what happened and in what order
        │
QUIC transport             — moves information efficiently
        │
Smart peer selection       — controls propagation, avoids storms
        │
Parallel execution         — consumes finalized work efficiently
        │
State layer                — makes execution cheap at high throughput
```

Hashgraph solves ordering; QUIC + peer selection solve dissemination;
parallel execution solves throughput. They converge at the
finalized-event boundary and do not block each other.

---

## 3. Gossip Track — 1,000-Node Gossip

### 3.1 Current Baseline and Bottlenecks

Verified against `protocol/gossip/src/node.rs:350` (`run_until_stopped`),
`protocol/gossip/src/transport.rs:31` (`SyncTransport`), and
`protocol/gossip/src/frontier.rs:24` (`known_summary`).

* **Serial fanout = 1.** One `random_peer()` per `sync_interval` (500 ms
  default, 25 ms in tests — `docs/JKain_Consensus_Spec.md:149`), one
  `run_sync` (`protocol/gossip/src/sync.rs:41`) at a time. Gossip spread
  is `O(log N)` rounds × `sync_interval` even though the algorithm is
  exponential — the driver serializes it.
* **Persistent connections underutilized.** `TcpTransport` is persistent per
  peer (`outbound: HashMap<NodeId, TcpTransport>` at `node.rs:357`,
  `is_connected` fast-path at `transport.rs:78`), but uniform random
  selection over `N=100` gives 1% hit rate per round; most cached conns sit
  idle holding FDs/TLS state, and `outbound.remove(peer)` on any `Err`
  (`node.rs:474`) discards the session.
* **`O(N)` summary per sync.** `known_summary` builds `Vec<(NodeId,u64)>`
  from `Hashgraph::latest_event_by` for every member — wire size
  `N * 16 B` (`proto.rs:282`) per request, `N * sync_rate` total. At
  `N=1,000` this is ~16 KB per sync in summaries alone.
* **Head-of-line blocking.** TCP ordered byte stream (`transport.rs:100`
  `read_exact` 5-byte header + payload) carries
  `SyncRequest → SyncResponse(large delta) → Event` sequentially. A large
  `delta_events` Kahn-sorted delta (`frontier.rs:74`) stalls the next sync.
* **No compression or batching.** Full `Event` canonical bytes in
  `SyncResponse`; no `zstd`, no chunking.

At 2–4 nodes these are invisible. At 100+ the driver, not the hashgraph,
is the ceiling.

### 3.2 Target Architecture

```
                         1,000-node network
                                │
                         PeerManager
                                │
                    ┌───────────┴───────────┐
                    │                       │
             known peer set            peer scoring
                    │                       │
                    └───────────┬───────────┘
                                ▼
                       select K peers
                         dynamically
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                 QUIC A      QUIC B      QUIC C
                    │           │           │
                    └───────────┼───────────┘
                                ▼
                       concurrent gossip
                                │
                                ▼
                         consensus layer
```

Design choices locked:

1. **QUIC is the transport.** `SyncTransport` stays abstract so `TcpTransport`
   remains as benchmark/fallback.
2. **Bounded active pool.** Maintain 10–30 active QUIC connections, not 1,000.
   Constant is deployment-tunable, not protocol-constant.
3. **Dynamic peer selection** with scoring (see 3.5).
4. **Dynamic fanout** with hard bounds (see 3.6).
5. **Persistent QUIC for hot peers**, ephemeral/resumption for cold peers.
6. **Peer diversity** — topology-aware, anti-colocation.
7. **Gossip scheduling detached from consensus** — continuous multi-peer sync
   while `Hashgraph` advances.

First implementation target: **100 nodes**, interfaces sized for **1,000**.

### 3.3 QUIC Transport

* New `QuicTransport: SyncTransport` in `protocol/gossip/src/transport.rs`
  (or `transport/quic.rs`) via `quinn` + `rustls`. Reuse
  `TlsIdentity::spki_fingerprint` pinning (`protocol/gossip/src/tls.rs:117`)
  as QUIC certificate verifier — same SPKI pin, same audit surface.
* Keep `TcpTransport` unchanged; selection via `ClusterConfig`
  (`node/src/config.rs:35` `gossip_addr`) extended with optional
  `quic_addr`. Nodes without `quic_addr` fall back to TCP.
* Gains: 1-RTT handshake (0-RTT resumption vs TCP `SYN → SYN-ACK → TLS`
  2–3 RTT), connection migration, per-stream flow control.
* Gains on HOL: QUIC streams multiplex `SyncRequest` / `SyncResponse` chunks /
  `CheckpointSig` on independent streams; TCP's single ordered stream is
  eliminated.
* Maturity risk is contained: QUIC is not responsible for peer selection,
  only transport. Controversial changes stay reviewable via trait boundary.

### 3.4 Bounded Concurrent Fanout

* Replace single `run_sync` in `node.rs:416` with `k` concurrent syncs per
  interval, `k` bounded by semaphore / `tokio::JoinSet`. Suggested initial
  bounds: `k_min=2`, `k_max=8` for 100 nodes, `k_max=12` for 1,000 —
  tuned from G0 benches, not hardcoded.
* Per-peer `Mutex<Transport>` in `outbound` pool so concurrent tasks do not
  race on same peer. Peer selected at most once per interval.
* Backpressure: if `k` tasks still in-flight at next interval, skip new
  spawns — never queue unbounded syncs.

### 3.5 Dynamic Smart Peer Selection

Extend `PeerManager` (`protocol/gossip/src/peer_manager.rs:20`) from
uniform random (`random_peer`) to scored selection.

```
peer score =
    frontier usefulness       // how many events this peer can give us (known_summary gap)
  + sync success rate        // EWMA of last N sync outcomes
  + latency (inverse)        // p50 sync RTT, lower is better
  + freshness                // time since last successful sync
  + diversity bonus          // topology /24 or provider diversity
  - recent selection penalty // anti-starvation, avoid picking same peer every interval
  - failure/backoff penalty  // exponential backoff on timeout / Behind
```

* No hardcoded weights initially — G0 instrumentation collects each signal;
  formula tuned from data. All signals are local observations, no extra
  gossip.
* Selection: pick `k` highest-scoring peers not in backoff, with small
  randomness (e.g., ε-greedy or weighted sample) to preserve exploration.
* Scoring state is ephemeral — not consensus-critical, not persisted, rebuilt
  on restart.

### 3.6 Adaptive Fanout and Interval

Fanout `k` and `sync_interval` adapt to local health:

```
healthy / caught up (decided_round lag ≈ 0, low frontier gap):
    lower fanout, longer interval

local frontier falling behind (large known_summary gap):
    increase fanout

high propagation lag (decided_round lag growing):
    increase fanout

network congestion (rising sync RTT / timeout rate / outbound queue depth):
    decrease fanout, increase interval
```

Hard bounds enforced: `k ∈ [k_min, k_max]`, `sync_interval ∈ [interval_min, interval_max]` so no gossip storm. Signals derived from `highest_decided_round` (`node.rs:513`) and frontier gaps — no global view needed.

### 3.7 Persistent Hot Peers

* **Hot peer:** top-scoring, frequently selected — keep persistent QUIC
  connection, reuse across many `run_sync` rounds (multiple streams per
  connection, no new handshake).
* **Cold peer:** rarely selected — ephemeral QUIC or 0-RTT resumption;
  connection torn down after sync, no FD held.
* Active pool size 10–30: evict least-useful hot peer when pool full,
  preferring to retain diverse / low-latency peers. Eviction is LRU over
  usefulness, not random.

### 3.8 Peer Diversity

* At `N=1,000`, picking `k` peers all in same `/24` or same provider
  creates correlated failure. Diversity signal: prefer peers whose
  `addr` / `reconnect_addr` fall in distinct subnets and (when available)
  distinct deployment zones (derived from `ClusterConfigFile` metadata,
  not consensus).
* Diversity is a soft bonus, not a hard partition — never starve a useful
  peer solely for diversity.

### 3.9 Separation of Gossip Scheduling and Consensus

* Gossip controller runs continuously with `k` concurrent syncs; `Hashgraph`
  (`protocol/consensus/src/hashgraph.rs:151`) processes inserts under
  `Arc<Mutex<Hashgraph>>` independently. `process_finalized_rounds`
  (`node.rs:540`) becomes a consumer of a bounded channel
  `finalized: Vec<(Event, u64)>` rather than a synchronous call inside the
  sync loop.
* Ensures `Hashgraph::insert` never waits for a slow sync, and execution
  (track 2) never stalls gossip.

### 3.10 Compression and Batching

Deferred until G0–G4 prove fanout is saturated:

* `zstd` (or `lz4` for lower CPU) on `SyncResponse` event deltas.
* Chunked `SyncResponse` — large deltas split across multiple QUIC streams /
  frames to bound per-frame HOL even further.
* Optional delta-summary optimization (bloom/IBLT) only if summary `O(N)` is
  measured >20% of bandwidth at target `N`.

---

## 4. Execution Track — Deterministic Parallel Execution

### 4.1 Transaction Access Declaration

Current `Transaction { payload: Vec<u8> }`
(`protocol/primitives/src/transaction.rs:14`) is opaque; scheduler has
nothing to inspect without executing. Whitepaper already reserves
`access_list` (`docs/JKain_Whitepaper.md:82`) — wire it as protobuf
(external-facing wire per `AGENTS.md:Wire Formats`, `prost` as in
`protocol/stream/`).

```proto
message Transaction {
  bytes payload = 1;              // existing opaque body
  AccessList access_list = 2;     // optional
}
message AccessList {
  repeated AccessKey reads  = 1;
  repeated AccessKey writes = 2;
}
```

### 4.2 Typed Access Domains

Prefer typed domains over raw KV keys — enables cross-service parallelism:

```
AccessKey =
    Account(AccountId)
  | HtsToken(TokenId)
  | HcsTopic(TopicId)
  | ContractStorage(StorageKey)
  | StateKey(RawKey)          // escape for Kv Put/Delete
  | Unknown                   // forces serial fallback, counted
```

Conflict rules become protocol-level, e.g.:

```
CryptoTransfer(Account A)  conflicts with  CryptoTransfer(Account A)
HtsTransfer(Token X)       does NOT conflict with  HcsSubmit(Topic Y)
HtsTransfer(Token X)       conflicts with  HtsMint(Token X)
```

`Raw StateKey` covers current `Op::Put/Delete`
(`executor/state/src/op.rs:44`). `Unknown` is measured, not permanent.

### 4.3 Migration — Optional + Serial Fallback

```
                Transaction
                     │
           access_list present?
              /              \
            yes              no
             │                │
     validate declarations  SERIAL lane
             │                │
     dependency scheduler     │
             │                │
     ┌───────┴───────┐        │
     │               │        │
 independent     conflict    │
 transactions    groups      │
     │               │        │
 PARALLEL          SERIAL    │
     │               │        │
     └───────┬───────┘        │
             ▼                ▼
           deterministic commit → State
```

1. `Transaction.access_list` optional.
2. If absent → serial lane automatically.
3. If present → scheduler uses it.
4. Executor validates that the operation's *known* declared pattern matches
   the list. If the operation cannot prove its accesses → serial fallback.
5. `undisclosed write → ExecutorError` enforcement only after every native
   op has a formally defined domain implementation.

This proves deterministic equivalence before making the format
consensus-critical for every transaction.

### 4.4 Deterministic Dependency Scheduler

New module `executor/scheduler` (or `executor/state/src/scheduler.rs`).

* Input: `Vec<(Event, u64)>` in `finalized_events` order
  (`executor/state/src/executor.rs:215`), flattened to
  `Tx { idx, reads, writes, lane }`. `lane=Serial` if `access_list` absent,
  `Unknown` present, or domain unimplemented.
* Conflict: `writes_i ∩ (reads_j ∪ writes_j) ≠ ∅` or
  `reads_i ∩ writes_j ≠ ∅` for `i < j`. `reads ∩ reads` never conflicts.
* Output: `Vec<Level>` via Kahn topological sort, deterministic tie-break
  by `consensus_order` order (`roundReceived → consensusTimestamp → sig`
  from `protocol/consensus/src/order.rs`). Each `Level` is a maximal
  independent set; serial-lane txs each occupy singleton levels in order.
* Must satisfy: flattening `Levels` in order equals original
  `consensus_order`. Index `writes → last_writer` to avoid `O(T²)`.

First milestone executes each level sequentially — isolates scheduler
correctness from concurrency.

Verification harness:

```
consensus_order
  ├── serial executor ──→ State A        (oracle, always runs)
  └── scheduler → parallel plan ──→ deterministic executor ──→ State B
                                    (initially sequential per level)
                assert State A == State B   // byte-identical State::to_bytes()
```

### 4.5 Execution Model

* **Phase 1:** scheduler + serial-per-level executor (no threads).
* **Phase 2:** real parallelism over versioned snapshot — workers execute
  against copy-on-write overlay `HashMap<AccessKey, Option<Vec<u8>>>`,
  recording read versions, not mutating live `Keyspace`/`SparseMerkleTree`.
* **Commit:** in `consensus_order` within each level (sorted by original
  `idx`). Apply overlay writes to live `State` in that order. If a conflict
  escaped the scheduler, optimistic version check
  `read_version == committed_version` triggers deterministic abort and
  serial re-execution (abort set derived from levels, not thread timing).
* Signature verification (`DidOp` at `executor/state/src/executor.rs:148`,
  `MembershipOp`) parallelized via `tokio::task::spawn_blocking` batch or
  `ed25519-dalek` batch API — measured before adding dep.

### 4.6 State Layer

Current `State { kv: Arc<Keyspace>, tree: SparseMerkleTree }`
(`executor/state/src/state.rs`) is single `Fjall::Keyspace`
(`executor/state/src/state_db.rs:StateDb`) with `O(256)` Merkle per write
(`executor/state/src/merkle.rs`). Parallelism without this layer change
just contends on one lock.

* Batched writes: single `fjall::Batch` per committed `Level` (or per
  round, matching current per-round rooting at `node.rs:594`). Recompute
  Merkle path once per batched key.
* Checkpoint contract preserved: `StateDb::snapshot(round, bytes)` still
  writes per-round `snap` keyspace; `state_hash = State::root()` derived
  from batched tree; `accept_checkpoint` pruning unchanged (`node.rs:834`).
* Later (after equivalence proven): per-domain `Keyspace` shards or
  prefix-sharded `State` so `Account / HtsToken / HcsTopic` lanes don't
  share a lock. MVCC with `version: u64` per key, lock-free reads
  (`RwLock` per shard or `ArcSwap`), hot-set write-behind flushed at
  `StateDb::flush()` / `accept_checkpoint`. Snapshot isolation: readers see
  committed version ≤ their `roundReceived`.

### 4.7 Consensus/Execution Decoupling

Refactor `GossipNode::process_finalized_rounds` Phase B: replace
`Mutex<Executor> + Mutex<ActivationState>` nesting with bounded
`mpsc` channel from hashgraph finalized queue → scheduler → executor
worker pool. `GossipNode` retains only activation/checkpoint logic
(Phases C/D at `node.rs:613/690`). Workers are pure
`fn(Snapshot, Level) -> Overlay`; crash replay via `EventLog::replay()`
(`protocol/storage/src/event_log.rs:replay`) stays deterministic.

### 4.8 Cryptography and Serialization

* Parallel/batched Ed25519 verification behind feature flag.
* Zero-copy `DecodedOp::decode` — `&[u8]` views instead of per-field
  `Vec<u8>` allocs at `op.rs:148` (`take_bytes`), arena per batch.
* Keep protobuf for external wire; internal `Op::encode` `u32 BE len`
  stays canonical.

---

## 5. Convergence — The Finalized-Event Boundary

```
Gossip track                          Execution track
  QUIC + scoring                        access_list
  concurrent fanout                     scheduler
  adaptive interval                     parallel execution
        \                                     /
         \                                   /
          └────────── finalized_events ──────┘
                         │
                    deterministic commit
                         │
                       State
                         │
                    SignedCheckpoint (threshold >2/3)
```

The two tracks meet only at `state::finalized_events(&hg)` →
`process_finalized_rounds` boundary. They are built and benchmarked
independently and do not block each other.

---

## 6. Implementation Sequence

### Gossip track

```
G0  Instrument current gossip
     sync success rate, p50/p95 RTT, delta_bytes/sync,
     known_summary_bytes, spread latency, decided_round lag,
     outbound cache hit/miss, connect latency
        │
G1  QUIC transport (SyncTransport impl, TcpTransport stays)
        │
G2  Concurrent bounded fanout (k_min..k_max, JoinSet, per-peer Mutex)
        │
G3  Dynamic peer scoring (frontier usefulness, success EWMA,
     latency, freshness, diversity, recent-selection penalty,
     failure/backoff) — weights tuned from G0 data
        │
G4  Adaptive fanout/interval (frontier gap, propagation lag,
     congestion signals, hard bounds)
        │
G5  Compression + batching (zstd on SyncResponse, chunked streams)
     IBLT/bloom summary only if O(N) measured >20% at target N
        │
G6  100 / 500 / 1,000-node benchmarks (localhost + VPS mesh)
```

### Execution track

```
E0  Benchmark + serial oracle/invariants (State::to_bytes equality)
        │
E1  Access-list wire format + typed domains (proto, AccessKey enum)
        │
E2  Deterministic dependency scheduler (Levels, Kahn, deterministic tie-break)
        │
E3  Scheduler correctness / property / fuzz testing (State A == State B)
        │
E4  Parallel execution over versioned snapshot (overlay, spawn_blocking)
        │
E5  Deterministic commit + batched Merkle/Fjall
        │
E6  State partitioning / MVCC optimization
        │
E7  Consensus/execution pipeline decoupling (bounded mpsc)
        │
E8  Crypto/serialization optimization (batch verify, zero-copy)
```

Execution maturity: `100% serial → 80/20 (E2) → 95%+ parallel / <5% genuinely serial (E8)`.

---

## 7. Metrics and Success Criteria

### Gossip

* `sync_success_rate`, `p50/p95_sync_rtt`, `delta_bytes_per_sync`,
  `known_summary_bytes_per_sync`, `outbound_cache_hit_rate`,
  `connect_latency_p95`, `gossip_spread_seconds` (time until N nodes hold
  event), `decided_round_lag`, `concurrent_fanout_k` (actual), `backoff_peers`.
* **Success at 100 nodes:** p95 spread < `3 * sync_interval`,
  `decided_round_lag` bounded, no gossip storm (fanout stays within
  `[k_min,k_max]` under load).

### Execution

* `parallel_lane_ratio = parallel_txs / total_txs` per round,
  `unknown_lane_ratio` (absent/Unknown), `levels_per_round`,
  `avg_level_width`, `abort_retry_count`, `fjall_batch_size`,
  `merkle_recompute_cost`.
* **Success:** `unknown_lane_ratio` tracked and driven down; mature target
  `parallel_lane_ratio ≥ 0.95` with `unknown_lane_ratio < 0.05` and
  `State A == State B` at every round for every run.
* **Do not let Unknown become permanent escape hatch** — if 60% of txs are
  silently serial, the system looks parallel while gaining nothing.

---

## 8. Wire Format and Compatibility

* New external fields (`Transaction.access_list`, `ClusterConfig.quic_addr`)
  are protobuf `optional` — old nodes decode missing field as `None` (serial
  lane / TCP fallback), not as error. Per `AGENTS.md:Wire Formats`, confirm
  protobuf schema scope with user before implementing.
* Internal binary (`Op::encode` `u32 BE len`, `CanonicalEncode` for
  `Event`) stays canonical and untouched.

---

## 9. File Impact Map

| Area | Files |
|---|---|
| Primitive TX | `protocol/primitives/src/transaction.rs`, `.../access.rs` (new), `.../lib.rs`, `.../proto/*.proto`, `.../build.rs` |
| Op domains | `executor/state/src/op.rs`, `.../did.rs`, `protocol/crypto/src/membership.rs`, `protocol/crypto/src/roster.rs` |
| Scheduler | `executor/state/src/scheduler.rs` or `executor/scheduler/*` (new crate) |
| Executor/State | `executor/state/src/executor.rs`, `.../state.rs`, `.../merkle.rs`, `.../state_db.rs`, `.../lib.rs` |
| Gossip transport | `protocol/gossip/src/transport.rs`, `.../transport/quic.rs` (new), `.../tls.rs` |
| Peer selection | `protocol/gossip/src/peer_manager.rs`, `.../peer/scoring.rs` (new) |
| Gossip driver | `protocol/gossip/src/node.rs` (`run_until_stopped`, `process_finalized_rounds`, `GossipController` split), `.../sync.rs`, `.../frontier.rs`, `.../proto.rs` |
| Node daemon | `node/src/bin/jkaind.rs`, `node/src/config.rs`, `node/src/storage.rs` |
| Tests/benches | `executor/state/tests/deterministic.rs`, `.../scheduler.rs` (new), `protocol/gossip/tests/*`, `benches/gossip.rs` + `benches/parallel.rs` (new) |
| Docs | `docs/OPTIMIZATION.md` (this file), `ARCHITECTURE.md`, `ROADMAP.md`, `protocol/gossip/README.md`, `executor/state/README.md` |

---

## 10. Risks and Open Questions

* **Scoring weights without data are guesses.** G0 must ship first; do not
  hardcode formula before benches.
* **QUIC maturity on consensus-hot path.** Contained by `SyncTransport`
  trait; TCP stays as fallback/benchmark.
* **Typed-domain incompleteness.** Every new native op must ship with
  `access_keys()` impl; checklist in PR template.
* **Determinism via HashMap iteration.** Guard with `BTreeMap`/sorted
  iteration as done for `State::to_bytes`; `clippy::pedantic` will flag.
* **O(N) summary at N=1,000.** Monitor `known_summary_bytes_per_sync`; IBLT
  is deferred until measured.
* **Questions to lock before G1/E1:**
  1. Minimal `AccessKey` variants for E1 — is
     `Account / HtsToken / HcsTopic / StateKey / Unknown` sufficient or
     should `ContractStorage` be included from day one?
  2. `QuicTransport` crate choice (`quinn` vs `s2n-quic`) and UDP firewall
     posture for target VPS providers.

---

*Last updated: 2026-08-20. Next step is G0/E0 instrumentation, not transport
or scheduler code.*
