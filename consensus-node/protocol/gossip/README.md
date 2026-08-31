# gossip

Gossip-about-gossip network layer for JKain.

Implements Consensus Spec §5: nodes periodically fan out to `k =
FanoutMode::effective_k(N)` peers concurrently (`JoinSet`+`Semaphore(k)`,
`ratio 0.6@N≤10 → 0.3@N≥30`, `k_max 4@N≤6, 17@7≤N≤99 (Hedera cap), 12@N≥100` —
`N=6→4, 10→6, 29→9, 100→12`; Hedera `17` is cap not computed), exchange event deltas over
pinned TLS (TCP/QUIC) connections, and fold the newly received events into a
locally-created event of their own. Depends on `primitives` for the value
types, `crypto` for hashing, signing, and membership, and `consensus` for the
hashgraph that stores and orders events.

Transport is `SyncTransport` over raw TCP with TLS 1.3 (rustls) and
length-prefixed canonical frames — the conservative, well-understood transport
the whitepaper (§2.2) deliberately chooses for the consensus-hot path — plus
`QuicTransport` via `quinn`+`rustls` SPKI verifier (same `spki_fingerprint` pin,
single `gossip_addr` as QUIC endpoint, `TcpTransport` fallback, `Frame`
`[tag:u8][len:u32BE][payload]` unchanged over QUIC bidi streams). `SyncTransport`
stays abstract so `TcpTransport` remains as benchmark/fallback; bounded fanout,
`LruCache` hot-pool, per-peer dedup and `GossipMetrics` are implemented (T12)
per `docs/OPTIMIZATION.md:3.4` (G-track G1–G6).

## Contents

- `peer` / `peer_manager` — known peers (NodeId, address, reconnect address,
  expected TLS fingerprint) and `FanoutMode::Auto` scored selection
  (`effective_k(N)=ceil(N*ratio)` clamped to `k_max 4@N≤6, 17@7≤N≤99 Hedera cap, 12@N≥100`,
  ratio `0.6→0.3` — `N=6→4, 10→6, 29→9` (computed `9` vs cap `17`), `100→12`,
  `pick_k` with ε-greedy exploration + backoff, matching Hedera's
  unweighted behavior for k=1). `add_peer_from_key` admits a runtime-added
  member by deriving its TLS pin from its Ed25519 consensus key (the
  single-seed convention) and carrying its reconnect port.
- `tls` — per-node TLS identity. The durable secret is an Ed25519 seed;
  a self-signed X.509 certificate is re-wrapped from it (via `rcgen`) on
  every startup. Peers pin by comparing the presented certificate's SPKI
  fingerprint against the address-book entry, independent of the consensus
  key registry.
- `transport` — `SyncTransport` (connect / send / recv frame), `TcpTransport`
  over `tokio` + rustls, and `QuicTransport` via `quinn` + `rustls` SPKI verifier
  (same pin, QUIC bidi streams, TCP fallback). `LruCache` hot-pool outbound
  (`outbound_capacity` 10@N=6, 30@N=100) reused across sync rounds with LRU
  eviction; `GossipMetrics` tracks `sync_attempts/success`, `p50/p95_rtt`,
  `cache_hit_rate`.
- `proto` — the wire types: `SyncRequest` (a per-creator known summary),
  `SyncResponse` (a topologically-ordered event delta), `ReconnectRequest` /
  `ReconnectResponse` (Phase 4 checkpoint bootstrap), `Behind` (pruned-history
  signal), and the length-prefixed, tag-delimited frame format (`[tag: u8][len:
  u32 BE][payload]`). `ReconnectResponse` carries the signed checkpoint, state
  bytes, roster history, decided round, retained graph, and `last_timestamp`
  watermark with capacity guards on every counted field.
- `frontier` — the sync summary and delta computation: `known_summary`
  builds the per-creator frontier from `Hashgraph::latest_event_by`, and
  `delta_events` / `delta_events_filtered` walks each creator's self-parent
  chain above the frontier, then topologically sorts the union (Kahn's
  algorithm, both parents as edges) so a receiver can insert every event
  parents-first. `delta_events_filtered` applies per-peer `DedupState` via
  `SyncConfig` (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`,
  `filter_likely_duplicates`, per-peer isolation) to suppress redundant resends.
- `sync` — `run_sync`: send the request, verify + insert the response
  events (skipping ones already present), create the initiator's own event
  (`self_parent` own last, `other_parent` the peer's last, monotonic
  `next_timestamp` clamped against `last_timestamp`), insert it, and push it
  back on the same stream. `next_timestamp` lives in `sync` so both the
  driver and tests share the same clock-clamp logic. Fanout driver wraps
  `run_sync` in `JoinSet`+`Semaphore(k)` with per-peer backpressure.
- `node` — `GossipNode`: owns a `Hashgraph`, the TLS identity, the peer
  table (`PeerManager` with scored `pick_k`), the `LruCache` hot-pool and
  per-peer `DedupState` + `GossipMetrics`, the Fjall `StateDb` (live state +
  per-round snapshots + watermark), and the async machinery (inbound accept
  loop + a concurrent fanout sync driver on a fixed interval + dedicated
  reconnect port). A per-round timeout bounds how long a silent peer can
  stall the driver; a `stop` flag lets the driver drain `JoinSet` in-flight
  syncs and exit cleanly. Pluggable durable sinks:
  `CheckpointSink`, `EventSink` (event log), `EventStreamSink` +
  `RecordSink` (mirror streams) + `RecordProofSink` (proof sidecar). Finalized
  events carrying a `MembershipOp::Add` payload are decoded and activated
  (hashgraph growth, roster schedule, peer pin) once the round after their
  `roundReceived` is fully decided; checkpoints are produced per decided
  round from the deterministic per-round Merkle root, the per-round
  `state_diffs` (after-image, sorted LWW, via
  `Executor::bucket_finalized_with_diffs`), and a padded Merkle
  `records_root`, then gossiped as `Frame::CheckpointSig` on every successful
  sync until quorum. Chained payloads embed `prev_checkpoint_hash`
  (PLAN-2 Rule 1: pure function of decided history — the hash of the
  previous round's 136-byte signing_bytes — with a stored-checkpoint fallback
  for pruned-K restarts and genesis `[0;32]`); the gossip hot path never
  invents a chain hash from local acceptance progress.

## Design

- Each interval fans out to `k` peers concurrently (`JoinSet`+`Semaphore(k)`,
  `FanoutMode::Auto` `k_max 4@N≤6, 17@7≤N≤99 Hedera cap, 12@N≥100` (`N=6→4, 10→6, 29→9 vs cap 17, 100→12`),
  ratio `0.6→0.3`, LRU hot-pool `10@N=6, 30@N=100`): one initiator creates one event per peer sync, each
  responder folds it into its own next event. Over repeated scored `pick_k`
  syncs both sides create events, preserving exponential gossip spread at
  `O(log N)` rounds with `k`-way parallelism.
- Already-present events are benign no-ops during insertion, so concurrent
  or redundant syncs never fail; per-peer `DedupState` (`SyncConfig`
  `self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`) suppresses
  redundant resends within the window (`filter_likely_duplicates`).
- Sync interval + timeout (`SyncTiming`) and fanout (`FanoutMode`) are the
  explicit tuning knobs the spec leaves open; scored peer selection
  (`PeerScore`: frontier usefulness, EWMA success, latency, freshness,
  diversity, backoff) drives `pick_k` with ε-greedy exploration. `GossipMetrics`
  (`sync_attempts/success/failures`, `p50/p95_rtt_ms`, `delta_bytes_per_sync`,
  `cache_hit_rate`) exposes the signals.
- Timestamps are monotonic per creator: `next_timestamp` clamps `SystemTime`
  against the last emitted value, persisted per checkpoint, so clock
  regression cannot produce equal/decreasing timestamps.
- Checkpoint signatures are gossiped on the same stream as events
  (`Frame::CheckpointSig`), re-sent until quorum (`valid * 3 > total * 2`).
  A node that has not yet produced its own payload buffers inbound sigs.
- Per-round `state_diffs` are captured alongside the state hash in
  `process_finalized_rounds` (one call to `bucket_finalized_with_diffs` per
  round, LWW within the round, sorted for determinism) and carried through
  `produce_checkpoint` → `accept_checkpoint` → `RecordSink::persist` → the
  `.rsf` file's `state_diffs` field and the `.rsf_proofs` sidecar writer.
  Empty rounds produce an empty diff list; a late-arriving event below the
  watermark still drains into the round's diff map.
- `prev_checkpoint_hash` Rule 1: the payload for round `R` always commits to
  the decided history alone (`canonical_checkpoint_payload_chained`), with
  priority `stored checkpoint(R-1)` → `rebuilt chained payload(R-1)` →
  `[0;32]`. This preserves determinism after a reconnect that pruned `K`
  behind genesis.
- Recovery is log-first: the durable `EventLog` is the primary restart path;
  `Frame::Behind` / `MissingParent` triggers a `fetch_checkpoint` reconnect
  only as fallback. The reconnect port is separate from the gossip port.

## Tests

- Unit: frame encode/decode roundtrips (including capacity-guard rejections
  for oversized counts and invalid tags), frontier delta correctness
  (including cross-creator `other_parent` topo-sorting), peer selection,
  TLS identity stability, and `ReconnectResponse` round-trips.
- Integration (`tests/`): real 2- and 4-node clusters on localhost exchange
  gossip and converge — every node ends holding events from every creator,
  with only a bounded in-flight window separating them. A partition/rejoin
  test seeds divergent histories and verifies reconciliation, including
  that each node's isolated events reach the other. `tests/streams.rs`
  verifies the live mirror-stream wiring including `.rsf_proofs` sidecars;
  `tests/activation.rs` covers dynamic membership via `MembershipOp::Add`;
  `tests/checkpoint.rs` covers chained checkpoints (Rule 1, `prev` continuity)
  and the Merkle `records_root` / proof vectors.
