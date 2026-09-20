# l1

The L1 integration boundary for a compute node.

Whitepaper §6.3.1 bounds what a compute node may ask of the consensus layer:
read-only queries and the submission of already-signed transactions. The
governing rule is that a compute node **always defers authorization decisions
back to L1** and never re-derives ledger state independently — a second,
unsynchronized opinion about ledger state is precisely the failure mode
consensus exists to prevent.

This umbrella holds one crate:

- `client/` — the boundary surface: read-only queries (DID resolution, the
  compute-node registry, the DID-to-location mapping, authorization lookups)
  and submission of signed transaction payloads.

The crate decodes with the same `state` types L1 writes, by linking the
executor crate rather than re-implementing the canonical binary format. That
is the property the Rust compute-node choice buys: one decoder, one source of
truth for the wire bytes.
