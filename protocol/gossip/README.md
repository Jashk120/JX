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
  `SyncResponse` (a topologically-ordered event delta), and the
  length-prefixed, tag-delimited frame format.
- `frontier` — the sync summary and delta computation: `known_summary`
  builds the per-creator frontier from `Hashgraph::latest_event_by`, and
  `delta_events` walks each creator's self-parent chain above the frontier,
  then topologically sorts the union (Kahn's algorithm, both parents as
  edges) so a receiver can insert every event parents-first.
- `sync` — `run_sync`: send the request, verify + insert the response
  events (skipping ones already present), create the initiator's own event
  (`self_parent` own last, `other_parent` the peer's last), insert it, and
  push it back on the same stream.
- `node` — `GossipNode`: owns a `Hashgraph`, the TLS identity, the peer
  table, and the async machinery (inbound accept loop + a sync driver on a
  fixed interval). A per-round timeout bounds how long a silent peer can
  stall the driver; a `stop` flag lets the driver drain in-flight syncs and
  exit cleanly. Finalized events carrying a `MembershipOp::Add` payload are
  decoded and activated (hashgraph growth, roster schedule, peer pin) once
  the round after their `roundReceived` is fully decided.

## Design

- One initiator creates one event per sync round; the responder folds it
  into its own next event. Over repeated random syncs both sides create
  events, preserving exponential gossip spread.
- Already-present events are benign no-ops during insertion, so concurrent
  or redundant syncs never fail.
- Sync interval is the one explicit tuning knob the spec leaves open;
  weighting peer selection is deliberately deferred to Phase 6.

## Tests

- Unit: frame encode/decode roundtrips, frontier delta correctness
  (including cross-creator `other_parent` topo-sorting), peer selection,
  and TLS identity stability.
- Integration (`tests/`): real 2- and 4-node clusters on localhost exchange
  gossip and converge — every node ends holding events from every creator,
  with only a bounded in-flight window separating them. A partition/rejoin
  test seeds divergent histories and verifies reconciliation, including
  that each node's isolated events reach the other.
