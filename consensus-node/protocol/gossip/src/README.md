# `gossip/src`

## 1. Purpose

`src/` holds the entire implementation of the `gossip` crate: the
gossip-about-gossip network layer (Consensus Spec §5) for JKain. Its single
responsibility is spreading hashgraph events across the cluster — periodic
fanout to `k = FanoutMode::effective_k(N)` peers over pinned-TLS TCP,
per-creator frontier summaries, topologically-ordered event deltas, own-event
creation folding received history into a new event, plus the checkpoint
gossip (`Frame::CheckpointSig`), checkpoint-lag recovery, and Phase 4
reconnect bootstrap that keep a live `GossipNode` converging — so that
`consensus::Hashgraph` on every node eventually holds every event.

## 2. Responsibilities

Owns:

- Gossip sync protocol: `SyncRequest` known-summaries, `SyncResponse` deltas,
  own-event creation (`self_parent` own last, `other_parent` peer's last),
  monotonic `next_timestamp` clamping, and the `SyncOutcome`
  (`fresh` / `pushback_delivered` / `blocked`) contract.
- Frontier/delta computation: `known_summary`, `delta_events` /
  `delta_events_filtered` (self-parent chain walk + Kahn topo-sort over both
  parents), per-peer `DedupState` suppression via `SyncConfig`
  (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`,
  `filter_likely_duplicates`, per-peer isolation).
- Peer bookkeeping and selection: `PeerInfo`, `PeerManager` (`random_peer`,
  scored `pick_k` with ε-greedy exploration + backoff), `FanoutMode::Auto`
  (`effective_k`, `ratio 0.6@N≤10 → 0.3@N≥30`,
  `k_max 4@N≤6, 17@7≤N≤99 Hedera cap, 12@N≥100`), `add_peer_from_key`
  (single-seed SPKI derivation + reconnect port).
- Wire framing and transport: `Frame` / `MessageType` (`[tag:u8][len:u32
  BE][payload]`, tags `0x00`–`0x08`), `SyncTransport` / `TcpTransport`
  (pinned-TLS 1.3 via rustls, `MAX_FRAME_SIZE` 64 MiB), `TlsIdentity`
  (Ed25519-seed identity, `rcgen` self-signed re-wrap, SPKI pinning via
  `FingerprintVerifier`).
- Node runtime: `GossipNode` (inbound accept loop + concurrent fanout sync
  driver on `SyncTiming`, `LruCache` hot-pool sized by `outbound_capacity`,
  per-peer `DedupState` + `GossipMetrics`, Fjall `StateDb`, `EventLog` /
  stream sinks, `MembershipOp::Add` activation at `roundReceived + 1`,
  per-decided-round checkpoint production/acceptance with chained
  `prev_checkpoint_hash` (Rule 1), quorum `valid * 3 > total * 2`,
  `CHECKPOINT_LAG_ROUNDS` (16) checkpoint-only fetch via
  `adopt_signed_checkpoint`, `fetch_checkpoint` / `fetch_checkpoint_only`
  reconnect clients, `apply_checkpoint` validate-before-mutate).
- Static cluster description: `ClusterConfig` / `MemberEntry` (`new` /
  `try_new` duplicate rejection, `registry()`, `peers_for`), and the
  `GossipError` / `Result` error taxonomy.

Does NOT own:

- Event value types, hashes, transactions (`primitives`); hashing, canonical
  encoding, Ed25519/BLS signing, membership registry, roster history
  (`crypto`); the hashgraph itself — rounds, fame voting, order,
  `CheckpointAccumulator`, `SignedCheckpoint`, `RetainedEvent`
  (`consensus`); durable event log (`storage`); mirror stream files
  (`.esf`/`.rsf`/`.rsf_proofs`, `EventStreamWriter`/`RecordStreamWriter`)
  (`stream`); deterministic execution (`state::Executor`/`StateDb` live in
  the `state` crate); cluster file parsing, daemon wiring, control socket
  (the `node` crate).

## 3. Contents

Flat directory — twelve `.rs` files, no subdirectories. Declared in `lib.rs`
as `pub mod` (`cluster_config`, `error`, `frontier`, `node`, `peer`,
`peer_manager`, `proto`, `reconnect`, `sync`, `tls`, `transport`) with
re-exports forming the crate's public API surface (see `lib.rs` entry).

- `lib.rs` — Crate root and public API surface. Role: module declarations
  plus the single import path callers use. Public surface: re-exports
  `ClusterConfig, MemberEntry` (`cluster_config`); `GossipError, Result`
  (`error`); `DedupState, SyncConfig` (`frontier`); `CheckpointSink,
  GossipNode, SyncTiming` (`node`); `PeerInfo` (`peer`); `FanoutMode,
  PeerManager, PeerScore` (`peer_manager`); `Frame, ReconnectRequest,
  ReconnectResponse, SyncRequest, SyncResponse` (`proto`);
  `fetch_checkpoint, fetch_checkpoint_only, verify_signed_checkpoint`
  (`reconnect`); `SyncOutcome, create_own_event, insert_own_event,
  run_sync, run_sync_with_precreated_event` (`sync`); `TlsIdentity`
  (`tls`); `SyncTransport, TcpTransport` (`transport`). Behavior: none
  beyond wiring; the `//!` doc header states the Spec §5 contract
  (bounded fanout, pinned TLS, `LruCache` hot-pool, per-peer dedup,
  `GossipMetrics`, T12 per `docs/OPTIMIZATION.md:3.4`). Fits the crate as
  its front door — every external user imports through here. No tests.
- `node.rs` (~3998 lines) — `GossipNode` long-running runtime plus metrics,
  timing, sinks, and all checkpoint logic. Public surface: `GossipMetrics`
  (`sync_attempts/success/failures`, `p50_rtt_ms`/`p95_rtt_ms` EWMA fast
  α0.1 / slow α0.05 — explicitly NOT true percentiles, canonical aliases
  `ewma_rtt_fast_ms`/`ewma_rtt_slow_ms`, `delta_bytes_per_sync`,
  `cache_hit_rate` legacy empty-delta EWMA, `cache_hits`/`cache_misses`,
  `true_cache_hit_rate`, `pending_dropped`, `effective_k`,
  `concurrent_syncs`; methods `success_rate`,
  `record_sync_success(_with_bytes)`, `record_cache_hit/miss`,
  `set_effective_k`, `set_concurrent_syncs`); `SyncTiming::new`;
  `outbound_capacity(n)` (`10@N≤6, 30@N≥100`, linear between);
  `GossipNode::{new, new_with_bls, set_fanout, fanout,
  set_dedup_enabled, dedup_enabled, gossip_metrics_snapshot,
  backoff_peer_count, is_consensus_member, executor_state, peer_count,
  peers, members, submit_transaction, request_reconnect, next_timestamp,
  checkpoint_notify, set_checkpoint_sink, set_event_sink,
  set_event_stream_sink, set_record_sink, set_record_proof_sink,
  flush_streams, run, run_until_stopped, run_with_reconnect,
  run_until_stopped_with_reconnect, process_finalized_rounds,
  submit_checkpoint_sig, checkpoint_signing_bytes,
  signed_checkpoint_for, latest_accepted_checkpoint_round,
  latest_signed_checkpoint, needs_checkpoint_only_sync,
  adopt_signed_checkpoint, from_checkpoint, from_checkpoint_with_bls}`;
  `CheckpointSink::persist`; constants `TX_PER_SYNC` (64),
  `MAX_PENDING_SIGS_PER_ROUND` (64), `CHECKPOINT_LAG_ROUNDS` (16),
  `SNAPSHOT_RETENTION_ROUNDS` (2), `MAX_PENDING_TRANSACTIONS` (1024),
  `MAX_SYNC_EVENT_COUNT` (4096). Behavior: `submit_transaction` queues raw
  payloads (drops + counts `pending_dropped` past cap);
  `drain_pending_transactions` takes ≤64 per round,
  `requeue_pending_transactions` restores order on failure (never requeue
  inserted payloads); fanout driver exchanges deltas concurrently via
  `JoinSet`+`Semaphore(k)` then serializes own-event creation under
  `own_event_lock` (chained `self_parent`, per-slot `other_parent`);
  `process_finalized_rounds` executes finalized events per round via
  `Executor::bucket_finalized_with_diffs` (sorted after-image diffs),
  activates `MembershipOp::Add` at `roundReceived + 1` once fully decided
  (PoP check via `verify_pop_bytes`, `Hashgraph::add_member`, roster-history
  persist, registry re-register, `add_peer_from_key`), then
  `produce_pending_checkpoints` → `produce_checkpoint` (chained payload via
  `canonical_checkpoint_payload_chained`, BLS self-sign, accumulator +
  buffered pending sigs, `accept_checkpoint` on quorum) with
  `cumulative_state_hashes` for Rule-1 determinism; `accept_checkpoint`
  emits `.rsf` via `RecordSink::persist` + `.rsf_proofs` sidecar,
  `EventSink` appends, prunes `outbound`/`pending`/diffs/snapshots, notifies
  `checkpoint_notify`; `submit_checkpoint_sig` drops at/below watermark,
  buffers undecided rounds (dedup per signer, cap 64), feeds decided ones;
  `adopt_signed_checkpoint` requires `signing_bytes` equality with the local
  accumulator + valid BLS aggregate, then routes through `accept_checkpoint`
  (graph kept, no state transfer); `apply_checkpoint` is
  validate-before-mutate (state-root, roster decode/hash/history-root,
  own-key, every retained signature, decided-round bound
  `cp ≤ decided ≤ max_retained_round`, `decided - cp ≤ retained.len()`,
  scratch-`Hashgraph` rebuild via `insert_accepted` in
  `topo_sort_retained` order) before touching live/durable state;
  `select_checkpoint_for_learner` serves the snapshot at the accepted
  checkpoint round; checkpoint sigs re-gossip every successful sync until
  quorum (`valid * 3 > total * 2`); lag detector arms
  `needs_checkpoint_sync` when `decided - accepted > 16`. Fits the crate as
  the orchestrator — every other module exists to serve this driver.
- `sync.rs` — One initiator sync round plus shared helpers. Public surface:
  `SyncOutcome { fresh, pushback_delivered, blocked }` +
  `needs_reconnect()` (`blocked > 0`); `run_sync(transport, hashgraph,
  registry, node_id, signing_key, peer_id, payload, timestamp)`;
  `run_sync_with_precreated_event(transport, hashgraph, registry, node_id,
  peer_id, precreated)`; `create_own_event(...)`, `insert_own_event(...,
  self_parent, other_parent, payload, timestamp)`;
  `next_timestamp(last: &AtomicU64)` + deterministic core
  `next_timestamp_with_clock(clock_millis, last)` (`max(clock, last+1)`,
  never emits 0, CAS loop); crate-private `exchange_delta`,
  `insert_verified`, `frame_name`. Behavior: `exchange_delta` sends
  `Frame::SyncRequest(SyncRequest { from, known })`, expects
  `Frame::SyncResponse` (`Behind` → `GossipError::Reconnect`,
  else `UnexpectedFrame`), inserts the topo-sorted delta keeping the
  insertable prefix on first `MissingParent` (`blocked = 1 + rest`,
  non-parent errors abort); `run_sync` skips own-event creation when
  `blocked > 0` (caller must reconnect + requeue), else creates the own
  event and pushes `Frame::Event` back — a failed push-back reports
  `pushback_delivered: false` without failing (next delta redelivers;
  payload must NOT be requeued); `insert_verified` verifies via
  `Verifiable::verify` and treats `AlreadyPresent` as a benign no-op.
  Fits the crate as the per-round protocol step the fanout driver invokes.
- `frontier.rs` — Sync summary, delta computation, dedup. Public surface:
  `SyncConfig { filter_likely_duplicates, non_ancestor_threshold,
  ancestor_threshold, self_threshold }` (defaults `true`, `3000 ms`,
  `250 ms`, `1000 ms`); `DedupState::{should_filter, prune_expired}`
  (key `(EventHash, NodeId)`, threshold priority self > ancestor >
  non-ancestor with `prev_self`/`prev_ancestor` upgrade, per-peer
  isolation, prune at max + 1000 ms slack); `known_summary(hashgraph,
  registry)` (per-creator highest seq via `latest_event_by`, O(members));
  `delta_events(hashgraph, known, registry)` (union over registry members +
  requester-known creators, self-parent walk above frontier, Kahn topo-sort
  over both parents); `delta_events_filtered(..., self_id, target_peer,
  dedup, config)` (self/ancestor classification via `is_ancestor` against
  own latest, `filter_likely_duplicates`, `prune_expired`); private
  `topo_sort`. Behavior: edges only between in-delta parents (outside
  parents are already known); cycle/dangling-parent yields
  `GossipError::Sync`. Fits the crate as the responder-side delta engine
  and sender-side resend suppressor.
- `proto.rs` (~1213 lines) — Wire types and frame codec. Public surface:
  `MessageType` (`SyncRequest 0x00`, `SyncResponse 0x01`, `Event 0x02`,
  `CheckpointSig 0x03`, `Reconnect 0x04`, `ReconnectResponse 0x05`,
  `Behind 0x06`, `CheckpointRequest 0x07`, `CheckpointResponse 0x08`) +
  `from_tag`; `SyncRequest { from, known }`; `SyncResponse { events }`;
  `ReconnectRequest { from }`; `ReconnectResponse { signed_checkpoint,
  state_bytes, roster_history_bytes, decided_round, retained,
  last_timestamp }`; `Frame` (the nine variants above) +
  `message_type()`, `to_bytes()`, `from_bytes()`; `CanonicalEncode` impls
  for `SyncRequest`/`SyncResponse`; private `Cursor` (bounds-checked
  `read`/`read_u32`/`read_u64`/`finish`), `decode_node_id`,
  `decode_event` (mirrors `CanonicalEncode for Event` field order),
  `decode_optional_hash`. Behavior: wire form `[tag:u8][len:u32
  BE][payload]`; `ReconnectResponse` lays out cp-len + cp-bytes (via
  `consensus::reconnect::encode_signed_checkpoint`), state-len + bytes,
  roster-len + bytes, `decided_round`, `last_timestamp`, retained-count +
  per-entry `seq`/`round`/`round_received`-tag/`ancestor_seqs`/`event`/
  `consensus_timestamp`-tag with new-format-then-legacy-`None` fallback;
  capacity guards reject before allocation (`declared count exceeds
  remaining buffer` for known/event/retained/ancestor/payload counts,
  `MAX_STATE_BYTES` 32 MiB, `MIN_RETAINED` 111-byte floor,
  `MIN_EVENT`/`MIN_KNOWN_ENTRY`/`MIN_TX` floors, `invalid optional-hash
  tag`, invalid `round-received` tag, length-mismatch/trailing-bytes).
  Fits the crate as the sole wire-format authority — `transport` moves
  bytes, this module decides what they mean.
- `peer.rs` — Single-peer address-book entry. Public surface: `PeerInfo {
  node_id, addr, reconnect_addr: Option<SocketAddr>,
  expected_spki_fingerprint: [u8; 32] }`, `PeerInfo::new(node_id, addr,
  fingerprint)`, `with_reconnect(addr)` builder. Behavior: pure data —
  gossip endpoint (`addr`) stays untouched when the separate reconnect
  socket is attached; SPKI pin is independent of the consensus key
  registry (Spec §5). Fits the crate as the unit `PeerManager`,
  `ClusterConfig`, and `transport::connect` all pass around.
- `peer_manager.rs` — Peer table plus scored fanout selection. Public
  surface: `FanoutMode::{Auto, Fixed(usize)}` + `effective_k(n_peers)`
  (`ceil(N*ratio)`, `ratio` linear `0.6→0.3` for `10<N<30`,
  `k_max 4@N≤6, 17@7≤N≤99, 12@N≥100`, `k_min 2` (1 when `N≤2`), upper
  `min(k_max, n_peers)`; `Fixed` clamps to `[1, n_peers]`; table
  `N=6→4, 10→6, 30→9, 100→12`) + `parse(s)` (`"auto"` / integer,
  `None` on `0`/garbage); `PeerScore { success_rate, avg_rtt_ms,
  frontier_gap, last_success, consecutive_failures, backoff_until }`
  (defaults `0.5 / 100.0 / 0 / None / 0 / None`) + private `score_value`
  (`gap*0.1 + success*10 − rtt/100 + freshness + diversity(0.2
  non-loopback) − 0.5*failures`, `NEG_INFINITY` in backoff);
  `PeerManager::{new, with_seed, random_peer, pick_k, record_success
  (EWMA 0.9, RTT EWMA, clears backoff), record_failure (success*0.9,
  exponential backoff `1<<min(failures,6)`s), set_frontier_gap, peer,
  all, add_peer (idempotent bool), add_peer_from_key (idempotent bool),
  len, is_empty, backoff_count}`; private `spki_fingerprint_of(key)`
  (RFC 8410 12-byte Ed25519 SPKI header + key, SHA-256). Behavior:
  `random_peer` skips backoff peers; `pick_k` sorts by score, filters
  backoff, then ε-greedy (`0.1` explore uniform, else exploit best),
  falls back to `random_peer`; `add_peer_from_key` derives the TLS pin
  from the Ed25519 consensus key (single-seed convention, verified equal
  to `TlsIdentity::spki_fingerprint`) and carries `reconnect_addr`.
  Fits the crate as the driver's peer source — fanout size from
  `FanoutMode`, membership from `add_peer`/`add_peer_from_key`, quality
  from the score loop.
- `reconnect.rs` — Phase 4 reconnect clients. Public surface:
  `fetch_checkpoint(identity, peer, reconnect_addr, node_id,
  trusted_roster_hash)`; `fetch_checkpoint_only(identity, peer,
  reconnect_addr)`; `verify_signed_checkpoint(checkpoint,
  expected_roster_hash)`; private `frame_name`. Behavior:
  `fetch_checkpoint` dials the teacher's reconnect port (address swapped,
  TLS pin from `peer`), sends `Frame::Reconnect`, expects
  `Frame::ReconnectResponse` (else `UnexpectedFrame`), then gates on
  `verify_signed_checkpoint` (roster-hash equality first, then BLS
  `>2/3` via `checkpoint.verify()`) — transport-trusted, quorum-verified;
  `fetch_checkpoint_only` sends `Frame::CheckpointRequest`, expects
  `Frame::CheckpointResponse` with NO roster anchoring (caller —
  `adopt_signed_checkpoint` — validates `signing_bytes` equality + BLS).
  Fits the crate as the fallback path when delta-sync gaps
  (`MissingParent`/`Behind`) — used by the driver after `SyncOutcome`
  signals `needs_reconnect`, and by `from_checkpoint` bootstraps.
- `tls.rs` — Per-node TLS identity and pinning verifier. Public surface:
  `TlsIdentity::{from_seed(seed, node_id), spki_fingerprint(),
  spki_fingerprint_of(cert), server_config(), client_config(expected)}`;
  private `FingerprintVerifier { expected, algorithms }`. Behavior: durable
  secret is the 32-byte Ed25519 seed; `from_seed` converts to PKCS#8 →
  `rcgen` `KeyPair` (PKCS_ED25519) → self-signed cert (`node-{id}` CN/SAN,
  `NoCa`), stores `cert_der` + `key_pkcs8`, pins
  `SHA-256(SPKI)`; cert is disposable and regenerated every startup while
  the fingerprint stays stable; `server_config` presents the identity
  (ring provider, safe-default versions, no client auth);
  `client_config` installs `FingerprintVerifier`, which accepts iff the
  end-entity cert's SPKI hash equals the pinned value (TLS 1.2/1.3
  signature verification delegated to ring/webpki). Fits the crate as the
  identity both ends of every gossip/reconnect connection authenticate
  with — independent of the consensus key registry.
- `transport.rs` — Sync byte transport. Public surface:
  `SyncTransport { connect, send_frame, recv_frame, is_connected }`
  (`async_fn_in_trait`); `TcpTransport::{new, from_tls_stream,
  acceptor}`; `AsyncReadWrite` blanket impl; crate-private
  `MAX_FRAME_SIZE` (64 MiB, validated pre-allocation — sized for
  `ReconnectResponse`'s checkpoint + retained graph); private
  `read_exact` (EOF → `GossipError::Closed`). Behavior: `connect` is a
  no-op when already connected, else TCP-dial + rustls handshake with
  SPKI-pinned client config and IP-literal `ServerName`;
  `send_frame` writes `frame.to_bytes()` + flush; `recv_frame` reads the
  5-byte header, rejects `len > MAX_FRAME_SIZE` as `Framing`, reads the
  payload, reassembles, and delegates to `Frame::from_bytes`. Fits the
  crate as the replaceable byte layer under `sync`/`reconnect` —
  `SyncTransport` stays abstract so alternatives remain benchmarkable.
- `cluster_config.rs` — Static cluster description. Public surface:
  `ClusterConfig::{new (panics on dup), try_new, registry(),
  peers_for(node_id)}`; `MemberEntry { node_id, addr, reconnect_addr,
  verifying_key, spki_fingerprint, bls_verifying_key }`. Behavior: single
  source of truth for static-membership construction — all nodes built
  from the same config get consistent `MembershipRegistry` and peer lists;
  `try_new` rejects duplicate `node_id`/`addr`/`spki_fingerprint` with a
  `String` naming the first duplicate; `peers_for` excludes self and
  carries each member's reconnect port into `PeerInfo::with_reconnect`;
  runtime joins bypass this file (`MembershipOp::Add` → `RosterHistory` →
  `Hashgraph::add_member`, activation `roundReceived + 1`). Fits the crate
  as genesis wiring — construction-time only, never on the hot path.
- `error.rs` — Error taxonomy. Public surface: `GossipError::{Io(#[from]
  std::io::Error), Closed, Tls(#[from] rustls::Error),
  CertificateVerification(String), Identity(String), Framing(String),
  UnexpectedFrame { expected, got }, Consensus(#[from]
  consensus::ConsensusError), Crypto(#[from] crypto::CryptoError),
  Sync(String), Reconnect(String)}` + `Result<T>` alias; crate-private
  `GossipError::framing`. Behavior: `thiserror`-derived messages;
  `From` conversions funnel I/O, TLS, consensus, and crypto failures into
  one type; `UnexpectedFrame` names both sides of a protocol mismatch.
  Fits the crate as the single error type every module returns.

## 4. Expected outcome

A correct `src/` delivers: exponential gossip spread — each interval fans
out to `k` scored peers concurrently (`JoinSet`+`Semaphore(k)`,
`LruCache` hot-pool reuse, `GossipMetrics`), each sync exchanging a
per-creator frontier summary for a parents-first delta and folding it into
a new own event, so every node's hashgraph converges to every creator's
events at `O(log N)` rounds; benign idempotence — already-present events
insert as no-ops, so concurrent/redundant syncs never fail; bounded
resends — `DedupState` suppresses within-window duplicates per peer;
event insertion that never forks on gaps — a `MissingParent`-blocked delta
keeps its insertable prefix but creates no own event and forces reconnect;
monotonic per-creator timestamps (`max(clock, last+1)`, never 0,
persisted per checkpoint via `last_timestamp`); per-round deterministic
checkpoints — identical `signing_bytes` on every honest node for the same
round (Rule 1: `stored(R-1)` → rebuilt chained `R-1` → `[0;32]`),
BLS-signed, gossiped as `Frame::CheckpointSig` until `valid * 3 > total *
2` quorum, accepted through one path (`accept_checkpoint`) whether from
gossip, lag-fetch (`adopt_signed_checkpoint` only over locally-produced
bytes), or reconnect; dynamic membership — `MembershipOp::Add` activates
exactly at `roundReceived + 1` when fully decided (hashgraph growth +
roster schedule + registry + TLS pin + reconnect port together); and
log-first recovery — `EventLog` replay is primary, `Behind`/`MissingParent`
reconnect and `CHECKPOINT_LAG_ROUNDS`-armed checkpoint-only fetch are
fallback, with `apply_checkpoint` guaranteeing a lying peer can neither
wipe state nor poison the graph.

## 5. Testing

Unit tests live in `#[cfg(test)]` modules inside these files; integration
tests live in `../tests/` (real multi-node clusters on localhost). In broad
view the unit suites cover: frame encode/decode round-trips and
truncation/capacity-guard rejection (`proto`); frontier summaries and
parents-first deltas, including cross-creator `other_parent` ordering and
per-peer dedup isolation (`frontier`); monotonic timestamp clamping
(`sync`); peer selection (`pick_k`/`effective_k`) and single-seed SPKI
derivation (`peer_manager`); TLS identity stability and rejection of
malformed SPKI DER (`tls`); checkpoint quorum edge cases and roster-hash
anchoring (`reconnect`, `node`); and duplicate-rejecting cluster config
(`cluster_config`). The integration suites cover cluster convergence,
partition/rejoin reconciliation, checkpoint chaining, dynamic-membership
activation, and mirror-stream wiring. Run with `cargo test -p gossip`; see
the crate `README.md` for the full workspace command.

## 6. Do not change

- Frame wire format `[tag:u8][len:u32 BE][payload]` and the nine tag
  values `0x00`–`0x08`; internal gossip encodings keep the canonical binary
  form, never protobuf (protobuf is for external/mirror surfaces only, per
  `AGENTS.md`).
- Capacity guards in `proto`/`transport`: every counted field is
  bounds-checked before allocation, and `len > MAX_FRAME_SIZE` (64 MiB) is
  rejected pre-allocation — these are the DoS defenses for
  `ReconnectResponse`.
- Fanout math in `peer_manager::effective_k` (`ceil(N*ratio)` clamped to
  `k_max 4@N≤6, 17@7≤N≤99` Hedera cap, `12@N≥100`; ratio `0.6→0.3`) and the
  `JoinSet`+`Semaphore(k)` concurrent spread with scored `pick_k`.
- Dedup windows (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`)
  and the monotonic `next_timestamp` clamp (`max(clock, last+1)`, never 0).
- Checkpoint invariants: quorum `valid * 3 > total * 2`,
  `CHECKPOINT_LAG_ROUNDS` (16) lag-fetch trigger, `prev_checkpoint_hash`
  Rule 1 (stored → rebuilt → `[0;32]`), and `apply_checkpoint`'s
  validate-before-mutate ordering (including the scratch-`Hashgraph`
  rebuild).
- `SyncTransport` stays an abstract trait so alternative transports remain
  benchmarkable; the locked scaling design in `docs/OPTIMIZATION.md:3.4`
  (G-track G1–G6) and the whitepaper §2.2 pinned-TLS TCP choice.
- The single-seed convention: runtime-added member TLS pins derive from the
  Ed25519 consensus key.

## 7. Dependencies

Depends on (see `Cargo.toml`): `primitives` (value types), `crypto`
(hashing, canonical encoding, Ed25519/BLS, membership), `consensus`
(hashgraph, checkpoints, roster history), `state` (`StateDb`,
`Executor::bucket_finalized_with_diffs`), `storage` (`EventLog` /
`EventSink`), `stream` (`EventStreamSink` + `RecordSink` +
`RecordProofSink`), `tokio`, `rustls`/`tokio-rustls`/`rcgen`/`x509-parser`
(TLS identity), `lru` (hot-pool), `ed25519-dalek`/`sha2`/`blst`/`rand`,
`thiserror`, and `tracing`; dev-depends on `test-support` and `tempfile`.

Depended on by: the `node` crate (the `jkaind` daemon drives `GossipNode`);
sits at the top of the `protocol/` dependency chain — nothing above it
depends upward.
