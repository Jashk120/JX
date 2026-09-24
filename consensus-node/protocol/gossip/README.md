# gossip

## Purpose

The gossip-about-gossip network of JKain: TLS identities, sync transport, delta exchange, the reconnect protocol, and the long-running `GossipNode`.

Implements Consensus Spec §5. Nodes periodically fan out to `k = FanoutMode::effective_k(N)` peers concurrently (`JoinSet`+`Semaphore(k)`, ratio `0.6@N≤10 → 0.3@N≥30`, `k_max 4@N≤6, 17@7≤N≤99` Hedera cap, `12@N≥100` — `N=6→4, 10→6, 29→9, 100→12`; Hedera `17` is cap not computed), exchange event deltas over pinned-TLS TCP connections, and fold the newly received events into a locally-created event of their own. Its single responsibility in the workspace is spreading hashgraph events and checkpoint signatures between nodes; it owns no ordering, voting, execution, or persistence-format decisions.

## Responsibilities

Owns:

- Bounded concurrent fanout sync: `FanoutMode::Auto` scored `pick_k` selection (`effective_k(N)=ceil(N*ratio)` clamped to `k_max`), `JoinSet`+`Semaphore(k)` fanout driver with per-peer backpressure, per-round timeout bounding silent-peer stalls, `stop` flag draining in-flight syncs for clean exit.
- TLS identity and pinned transport: per-node Ed25519-seed identity re-wrapped via `rcgen` into a self-signed X.509 cert on every startup, SPKI-pinned TLS 1.3 (`rustls`) `TcpTransport` behind the `SyncTransport` (connect / send / recv frame) abstraction, `LruCache` hot-pool of reused outbound connections (`outbound_capacity` `10@N=6`, `30@N=100`, LRU eviction).
- Frontier delta exchange: `known_summary` from `Hashgraph::latest_event_by`, `delta_events` / `delta_events_filtered` walking each creator's self-parent chain above the frontier and topologically sorting the union (Kahn's algorithm, both parents as edges) so receivers insert parents-first; per-peer `DedupState` suppression via `SyncConfig` (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`, `filter_likely_duplicates`, per-peer isolation).
- Sync-round event creation: `run_sync` sends the request, verifies + inserts response events (already-present are benign no-ops), creates the initiator's own event (`self_parent` own last, `other_parent` peer's last, monotonic `next_timestamp` clamped against `last_timestamp`), inserts it, pushes it back on the same stream. `next_timestamp` lives in `sync` so driver and tests share clock-clamp logic.
- Checkpoint gossip + lag recovery: per-decided-round checkpoint production (deterministic per-round Merkle root, per-round `state_diffs` after-image sorted LWW via `Executor::bucket_finalized_with_diffs`, padded Merkle `records_root`), gossip of `Frame::CheckpointSig` on every successful sync until quorum (`valid*3 > total*2`), inbound-sig buffering before own payload exists, checkpoint-only fetch (`Frame::CheckpointRequest` tag `0x07` empty payload → `Frame::CheckpointResponse` tag `0x08` aggregate via `adopt_signed_checkpoint`, `signing_bytes` equality + valid BLS aggregate, normal `accept_checkpoint` path, graph kept, no state transfer) armed when decided round runs more than `CHECKPOINT_LAG_ROUNDS` (16) ahead of the latest accepted checkpoint.
- Reconnect bootstrap: `ReconnectRequest` / `ReconnectResponse` on the dedicated reconnect port (separate from the gossip port), validate-before-mutate application (state-root, roster, own-key, every retained signature, retained graph's peer-supplied metadata — seq, `ancestor_seqs`, birth round, ordering — and the decided-round bound all checked; retained graph rebuilt into a scratch `Hashgraph` before any live or durable state is touched; decided round must lie within the retained graph and its gap from the checkpoint is capped by transfer size so a `u64::MAX` watermark cannot force unbounded `mark_decided_through`).
- Dynamic membership activation: finalized events carrying `MembershipOp::Add` decoded and activated (hashgraph growth, roster schedule, peer pin via `add_peer_from_key` deriving the TLS pin from the Ed25519 consensus key under the single-seed convention, carrying the reconnect port) once the round after their `roundReceived` is fully decided.
- Observability: `GossipMetrics` (`sync_attempts`/`sync_success`/`sync_failures`, `p50`/`p95_rtt_ms`, `delta_bytes_per_sync`, `cache_hit_rate`).
- Pluggable durable sinks: `CheckpointSink`, `EventSink` (event log), `EventStreamSink` + `RecordSink` (mirror streams) + `RecordProofSink` (proof sidecar); per-round `state_diffs` carried through `process_finalized_rounds` (one `bucket_finalized_with_diffs` call per round) → `produce_checkpoint` → `accept_checkpoint` → `RecordSink::persist` → `.rsf` `state_diffs` field + `.rsf_proofs` sidecar writer (empty rounds → empty diff list; late events below the watermark still drain into the round's diff map).

Does NOT own:

- Hashgraph ordering, fame voting, round assignment, roster history semantics (`consensus`).
- Value types, canonical encoding, signing primitives, membership registry (`primitives`, `crypto`).
- Execution, state Merkle tree, DID (`executor/state`).
- Durable event-log / stream file formats (`storage`, `stream`); gossip only calls their sink traits.
- Daemon config, clustering, restart recovery orchestration (`node/` drives `GossipNode`).
- Mirror-side verification or protobuf schemas (`stream`, repo-root `proto/`).

## Contents

- `src/` — the crate implementation. See `src/README.md` for per-file detail (each source file's role, public surface, and behavior). Key public entry points/types re-exported from `lib.rs`: `GossipNode`, `SyncTiming`, `CheckpointSink`, `run_sync` / `run_sync_with_precreated_event` / `create_own_event` / `insert_own_event` / `SyncOutcome` (`sync`), `SyncTransport` / `TcpTransport` (`transport`), `SyncRequest` / `SyncResponse` / `ReconnectRequest` / `ReconnectResponse` / `Frame` (`proto`), `FanoutMode` (`effective_k`) / `PeerManager` / `PeerScore` (`peer_manager`), `PeerInfo` (`peer`), `DedupState` / `SyncConfig` (`frontier`), `TlsIdentity` (`tls`), `fetch_checkpoint` / `fetch_checkpoint_only` / `verify_signed_checkpoint` (`reconnect`), `ClusterConfig` / `MemberEntry` (`cluster_config`), `GossipError` / `Result` (`error`). Module summary: `peer` / `peer_manager` (address book + `FanoutMode::Auto` scored `pick_k` with ε-greedy exploration + backoff, matching Hedera's unweighted behavior for k=1); `tls` (Ed25519-seed identity, SPKI pinning independent of the consensus key registry); `transport` (`SyncTransport` + `TcpTransport`, `LruCache` hot-pool, `GossipMetrics`); `proto` (wire types + `[tag:u8][len:u32 BE][payload]` frame format, capacity guards on every counted field in `ReconnectResponse`); `frontier` (`known_summary`, `delta_events`, `delta_events_filtered`); `sync` (`run_sync`, `next_timestamp`); `node` (`GossipNode`, `GossipMetrics`, `SyncTiming`, checkpoint production/gossip, `prev_checkpoint_hash` Rule 1, log-first recovery); `reconnect` + `cluster_config` + `error`.
- `tests/` — integration suites over live localhost nodes plus shared harness in `tests/common/` (`tests/common/mod.rs`: `spawn_cluster`, `stop_and_settle`, `temp_state_db` stand-in for `<data>/statedb/`, `consensus_seed`/`tls_seed`, `bind_ephemeral`, `registry_for`, re-exports `test-support::{SYNC_INTERVAL, SYNC_TIMEOUT, DEADLINE, POLL_INTERVAL, HEAVY_DEADLINE}`). See Testing below for what the suites verify.
- `examples/` — currently empty; no examples ship with this crate.

## Expected outcome

A correct working state produces:

- Exponential gossip spread at `O(log N)` rounds with `k`-way parallelism: each interval fans out to `k` peers concurrently, one initiator event per peer sync, each responder folding it into its own next event; concurrent/redundant syncs never fail (already-present inserts are no-ops) and redundant resends are suppressed within the `DedupState` windows.
- Monotonic per-creator timestamps: `next_timestamp` clamps `SystemTime` against the last emitted value, persisted per checkpoint, so clock regression cannot produce equal/decreasing timestamps.
- Checkpoint closure: sigs re-sent until quorum (`valid*3 > total*2`); a node missing a round's collection window (peers drop own sigs on acceptance, only re-send what remains) recovers via the `CHECKPOINT_LAG_ROUNDS` (16) checkpoint-only fetch without state transfer; `adopt_signed_checkpoint` accepts only the exact locally-produced payload (`signing_bytes` equality) with a valid BLS aggregate.
- Chained checkpoint determinism (`prev_checkpoint_hash` Rule 1): payload for round `R` commits to decided history alone (`canonical_checkpoint_payload_chained`), priority `stored checkpoint(R-1)` → `rebuilt chained payload(R-1)` → `[0;32]`; the gossip hot path never invents a chain hash from local acceptance progress; determinism holds after a reconnect that pruned `K` behind genesis.
- Log-first recovery: durable `EventLog` is the primary restart path; `Frame::Behind` / `MissingParent` triggers `fetch_checkpoint` reconnect only as fallback; gossip and reconnect ports stay separate.
- Reconnect safety: validate-before-mutate guarantees a lying peer cannot wipe state or poison the graph.

## Testing

- Unit tests (in `src/`, run with the crate suite) cover the pure logic: frame encode/decode roundtrips and capacity-guard rejections, frontier delta correctness (including cross-creator `other_parent` topo-sorting), peer selection (`pick_k`, `effective_k`), TLS identity stability, `ReconnectResponse` round-trips, and checkpoint quorum edge cases.
- Integration tests in `tests/` run real TCP+TLS nodes on localhost, with timing driven by `test-support::SYNC_INTERVAL` through the `tests/common/mod.rs` harness. In broad view they verify: multi-node convergence on a shared event set; partition/rejoin reconciliation; rejection of hostile inputs (wrong TLS pin, forged events, malformed frames, unreachable peers, protocol violations) without taking a node down; per-round timeout bounding of silent peers; checkpoint acceptance, pruning, chaining and Merkle `records_root` proof vectors; dynamic membership activation via `MembershipOp::Add`; and live mirror-stream wiring including `.rsf_proofs` sidecars.

Commands (run inside `consensus-node/`):

```bash
cargo test -p gossip      # unit + integration suites
cargo test --workspace    # full workspace
```

## Do not change

- Frame wire format `[tag:u8][len:u32 BE][payload]` with tags `0x00`–`0x08` (`SyncRequest`, `SyncResponse`, `Event`, `CheckpointSig`, `Reconnect`, `ReconnectResponse`, `Behind`, `CheckpointRequest` `0x07` empty payload, `CheckpointResponse` `0x08`); internal gossip/consensus encodings keep the canonical binary form, never protobuf (per `AGENTS.md` wire-format rule; protobuf is for external/mirror surfaces only).
- Fanout math: `FanoutMode::effective_k` = `ceil(N*ratio)` clamped to `k_max`, ratio `0.6@N≤10 → 0.3@N≥30`, `k_max 4@N≤6, 17@7≤N≤99` Hedera cap, `12@N≥100` (`N=6→4, 10→6, 29→9, 100→12`); concurrent `JoinSet`+`Semaphore(k)` spread with scored `pick_k` is consensus-critical timing behavior.
- Dedup windows: per-peer `DedupState` (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`); monotonic `next_timestamp` clamp persisted per checkpoint.
- Quorum `valid*3 > total*2`; `CHECKPOINT_LAG_ROUNDS` (16) checkpoint-fetch trigger; `prev_checkpoint_hash` Rule 1 (pure function of decided history, stored→rebuilt→`[0;32]` priority); log-first recovery (EventLog primary, reconnect fallback).
- `ReconnectResponse` validate-before-mutate (including scratch-`Hashgraph` rebuild and decided-round/transfer-size bound) — a lying peer must never be able to wipe state or poison the graph.
- Locked scaling design in `docs/OPTIMIZATION.md:3.4` (G-track G1–G6: bounded fanout, `LruCache` hot-pool, per-peer dedup, `GossipMetrics`); whitepaper §2.2 pinned-TLS TCP choice for the consensus-hot path; `SyncTransport` stays abstract so alternatives remain benchmarkable.
- Single-seed convention: runtime-added member TLS pins derive from Ed25519 consensus keys.

## Dependencies

Depends on (see `Cargo.toml`): `primitives` (value types), `crypto` (hashing, signing, membership), `consensus` (hashgraph storage and ordering, checkpoints, roster history), `state` (`StateDb`, `Executor::bucket_finalized_with_diffs`), `storage` (`EventLog` / `EventSink`), `stream` (`EventStreamSink` + `RecordSink` + `RecordProofSink`, `.rsf`/`..rsf_proofs` writers), `tokio` + `tokio-rustls` + `rustls` (TLS 1.3) + `rcgen` + `x509-parser` (identity), `lru` (hot-pool), `ed25519-dalek` + `sha2` + `blst` + `rand` (keys/hashing), `thiserror`, `tracing`; dev-depends on `test-support` (`SYNC_INTERVAL`, `DEADLINE`, …) and `tempfile`.

Depended on by: `node/` (`jkaind` daemon drives `GossipNode`); sits under the `protocol/` umbrella alongside `primitives` → `crypto` → `consensus` → `storage` → `stream` (gossip is the top runtime layer; nothing in `protocol/` except test-only `test-support` depends upward on it).
