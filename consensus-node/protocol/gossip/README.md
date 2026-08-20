# gossip

Gossip-about-gossip network layer for JKain.

Implements Consensus Spec §5: nodes periodically pick a random peer,
exchange event deltas over a pinned TLS connection, and fold the newly
received events into a locally-created event of their own. Depends on
`primitives` for the value types, `crypto` for hashing, signing, and
membership, and `consensus` for the hashgraph that stores and orders events.

Transport is raw TCP with TLS 1.3 (rustls) and length-prefixed canonical
frames — the conservative, well-understood transport the whitepaper (§2.2)
deliberately chooses for the consensus-hot path. `SyncTransport` is abstract
so `TcpTransport` remains as benchmark/fallback; QUIC is design-locked in
`docs/OPTIMIZATION.md` (G-track G1–G6, bounded fanout + scoring) and not yet
implemented.

## Contents

- `peer` / `peer_manager` — known peers (NodeId, address, reconnect address,
  expected TLS fingerprint) and uniform-random selection for the sync target,
  matching Hedera's unweighted behavior. `add_peer_from_key` admits a
  runtime-added member by deriving its TLS pin from its Ed25519 consensus key
  (the single-seed convention) and carrying its reconnect port.
- `tls` — per-node TLS identity. The durable secret is an Ed25519 seed;
  a self-signed X.509 certificate is re-wrapped from it (via `rcgen`) on
  every startup. Peers pin by comparing the presented certificate's SPKI
  fingerprint against the address-book entry, independent of the consensus
  key registry.
- `transport` — `SyncTransport` (connect / send / recv frame) and
  `TcpTransport` over `tokio` + rustls. One persistent connection per peer,
  reused across sync rounds.
- `proto` — the wire types: `SyncRequest` (a per-creator known summary),
  `SyncResponse` (a topologically-ordered event delta), `ReconnectRequest` /
  `ReconnectResponse` (Phase 4 checkpoint bootstrap), `Behind` (pruned-history
  signal), and the length-prefixed, tag-delimited frame format (`[tag: u8][len:
  u32 BE][payload]`). `ReconnectResponse` carries the signed checkpoint, state
  bytes, roster history, decided round, retained graph, and `last_timestamp`
  watermark with capacity guards on every counted field.
- `frontier` — the sync summary and delta computation: `known_summary`
  builds the per-creator frontier from `Hashgraph::latest_event_by`, and
  `delta_events` walks each creator's self-parent chain above the frontier,
  then topologically sorts the union (Kahn's algorithm, both parents as
  edges) so a receiver can insert every event parents-first.
- `sync` — `run_sync`: send the request, verify + insert the response
  events (skipping ones already present), create the initiator's own event
  (`self_parent` own last, `other_parent` the peer's last, monotonic
  `next_timestamp` clamped against `last_timestamp`), insert it, and push it
  back on the same stream. `next_timestamp` lives in `sync` so both the
  driver and tests share the same clock-clamp logic.
- `node` — `GossipNode`: owns a `Hashgraph`, the TLS identity, the peer
  table, the Fjall `StateDb` (live state + per-round snapshots + watermark),
  and the async machinery (inbound accept loop + a sync driver on a fixed
  interval + dedicated reconnect port). A per-round timeout bounds how long a
  silent peer can stall the driver; a `stop` flag lets the driver drain
  in-flight syncs and exit cleanly. Three durable sinks are pluggable:
  `CheckpointSink`, `EventSink` (event log), `EventStreamSink` + `RecordSink`
  (mirror streams). Finalized events carrying a `MembershipOp::Add` payload
  are decoded and activated (hashgraph growth, roster schedule, peer pin) once
  the round after their `roundReceived` is fully decided; checkpoints are
  produced per decided round from the deterministic per-round Merkle root and
  gossiped as `Frame::CheckpointSig` on every successful sync until quorum.

## Design

- One initiator creates one event per sync round; the responder folds it
  into its own next event. Over repeated random syncs both sides create
  events, preserving exponential gossip spread.
- Already-present events are benign no-ops during insertion, so concurrent
  or redundant syncs never fail.
- Sync interval + timeout (`SyncTiming`) are the explicit tuning knobs the
  spec leaves open; weighting peer selection is deferred to Phase 9 (G-track).
- Timestamps are monotonic per creator: `next_timestamp` clamps `SystemTime`
  against the last emitted value, persisted per checkpoint, so clock
  regression cannot produce equal/decreasing timestamps.
- Checkpoint signatures are gossiped on the same stream as events
  (`Frame::CheckpointSig`), re-sent until quorum (`valid * 3 > total * 2`).
  A node that has not yet produced its own payload buffers inbound sigs.
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
  verifies the live mirror-stream wiring; `tests/activation.rs` covers
  dynamic membership via `MembershipOp::Add`; `tests/checkpoint.rs` covers
  quorum and retrieval.
