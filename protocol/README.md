# protocol

The consensus-critical network layer of JKain: value types, cryptography,
the virtual-voting hashgraph, and the gossip network that spreads it.

This umbrella directory holds five crates with a strict dependency chain —
nothing depends on a crate above it:

```text
primitives   zero-dependency value types (events, hashes, transactions)
    ↑
crypto       hashing, canonical encoding, Ed25519 signing, membership
    ↑
consensus    in-memory Hashgraph: rounds, fame voting, order, checkpoints
    ↑
storage      Fjall-backed durable event log + roster history (Phase 8)
    ↑
gossip       pinned-TLS gossip network + GossipNode runtime
```

## Crates

- `primitives/` — the consensus-critical value types and their plain
  serialization forms. No cryptography.
- `crypto/` — the traits and machinery for authenticity and membership:
  `Hashable`, `CanonicalEncode`, `Signable`/`Verifiable`, and the
  `MembershipRegistry`.
- `consensus/` — the virtual-voting hashgraph: ancestry traversal, round
  assignment, `decideFame(w)` fame voting, order finalization, roster
  history, and signed state checkpoints.
- `storage/` — the durable event log: a Fjall database appending every
  verified event on insert (Phase 8), so a restarting node replays its
  retained graph instead of reconnecting from a peer.
- `gossip/` — the gossip-about-gossip network: TLS identities, sync
  transport, delta exchange, the reconnect protocol, and the long-running
  `GossipNode`.

## How it fits

The `executor/` layer consumes the total order `consensus` produces and the
`node/` layer (the `jkaind` daemon) drives a live cluster with `gossip`.
See `JKain_Consensus_Spec.md` at the repo root for the algorithm this layer
implements.
