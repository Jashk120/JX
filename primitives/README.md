# primitives

Core data types shared across the JKain workspace.

This crate defines the consensus-critical value types and their plain
serialization forms. It deliberately has **zero dependencies**, so any
crate (crypto, consensus, gossip, tests) can build on it without pulling
in extra dependencies.

## Contents

- `Event` / `UnsignedEvent` — the hashgraph event record: two parents
  (self / other), payload transactions, and an optional signature.
- `EventHash` — 32-byte content hash of an event, used as the graph node
  identifier.
- `Transaction` / `TransactionHash` — payload transactions and their hashes.
- `NodeId` — plain numeric member index with no knowledge that keys exist.
- `Signature` — the raw signature bytes carried by an event.
- `Timestamp` — nanosecond time of event creation.

## Design

- No cryptography lives here; hashing, canonical encoding, and signature
  verification are provided by the `crypto` crate via the traits that
  consume these types.
- Types are self-contained and copyable where sensible, so they are cheap
  to store in hashgraph records and pass across crate boundaries.
