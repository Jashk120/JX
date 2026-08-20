# state

Deterministic transaction execution for JKain.

Implements Phase 8 of `ROADMAP.md`: a pure executor that consumes events in
the finalized consensus order produced by `consensus` and folds each
transaction's payload into a key-value `State`. Depends on `primitives` for
the value types (`Event`, `Transaction`), on `consensus` for the
hashgraph whose `consensus_order` yields the input sequence, and on `fjall`
for the state's LSM backing.

## Contents

- `State` — the executor's key-value state. A Fjall LSM partition (raw byte
  keys to raw byte values, with a write-ahead log) whose entries are mutated
  only through the deterministic `apply` function and serialized canonically
  by `to_bytes` (ascending key order, `u32` big-endian length prefixes
  matching `crypto`'s canonical encoding). A sparse Merkle tree over the same
  keys is maintained incrementally in memory; its root is `State::root()`,
  the commitment a checkpoint signs as its `state_hash`.
- `StateDb` (in `state_db.rs`) — the on-disk state database under
  `<data>/statedb/`: the live `state` partition, a `snap` keyspace holding
  the exact state bytes of every accepted checkpoint round, and a
  monotonic `watermark` key (the last emitted timestamp). The `snap` entries
  replace the old per-round `.snap` files: restart recovery restores and
  verifies the checkpoint-round state from here, and the watermark restores
  `GossipNode::last_timestamp` so clock regression cannot rewind timestamps.
- `SparseMerkleTree` / `MerkleProof` (in `merkle.rs`) — the Merkle tree over
  the KV state. Node hashing is Hiero-style domain-separated SHA-256:
  `empty = SHA256(0x00)`, `leaf = SHA256(0x00 || len(key) || key || len(value)
  || value)`, `internal = SHA256(0x02 || left || right)`, `singleton =
  SHA256(0x01 || child)`. A `Put`/`Delete` recomputes only the O(depth) nodes
  on the affected path, so per-round checkpoint roots are cheap. `MerkleProof`
  is a per-key inclusion proof (`verify`, `encode`/`decode`) that a mirror can
  check without shipping the whole state.
- `Op` — the transaction payload: one opcode byte plus length-prefixed
  fields. `0x00` `Put { key, value }`, `0x01` `Delete { key }`, `0x03`
  `DidOp { id, document, signature, signed_by }` (`executor/state/src/did.rs`).
  `DecodedOp` is the top-level decode result: `Put`/`Delete` go to `State`,
  `DidOp` goes through `Executor::apply_did_op` (creation self-signed against
  the new document's own verification method, updates authorized by the prior
  document's indexed key, deactivation as a tombstone `Put` not `Delete`), while
  `0x02` `MembershipOp` bodies are decoded by `crypto::MembershipOp` and
  returned as a side channel. `DidDocument` holds 1..=5 `VerifyingKey`s plus a
  `deactivated` flag with binary `encode`/`decode`. Any other opcode, a
  truncated payload, or trailing bytes decodes to a deterministic
  `ExecutorError`.
- `Executor` — applies transactions to a `State` in the order presented.
  `execute_event` applies every valid transaction and returns
  `(Vec<ExecutorError>, Vec<MembershipOp>, Vec<DidError>)`; DID ops route
  through `apply_did_op` (with `is_creation` flag for duplicate/unknown-id
  checks, 1..=5 key limit, `AlreadyDeactivated` guard, and `UnknownSigner` /
  `InvalidSignature` checks) and ultimately write via the same `State::Put`
  path (with Merkle rehash) so proofs cover DID keys. Membership ops never
  touch `State`. `bucket_finalized` feeds a finalized `(event,
  roundReceived)` batch through the executor once, bucketing membership ops
  by roundReceived behind a processed-round watermark (idempotent).
- `finalized_events` — bridges to the consensus layer: walks a `Hashgraph`'s
  rounds in increasing order and returns each round's events in the exact
  order `Hashgraph::consensus_order` produces, so the executor never invents
  its own ordering rule.

## Design

- Execution is deterministic: no wall-clock reads, no randomness, and no
  *non-deterministic* I/O inside `apply`/`execute_*`. Partition writes carry
  deterministic content (the same op sequence always writes the same bytes);
  a storage error is logged and dropped, so the consensus-hot path never
  fails on storage hiccups. The durable truth for restart/verification is the
  `snap` keyspace, not the live partition, so a dropped write is healed by
  the next accepted checkpoint snapshot. The same finalized event order and
  the same starting state produce bit-identical resulting state on every
  node.
- Membership changes ride the consensus ordering as `0x02` payloads. They are
  never applied to `State`: the gossip layer collects them from the side
  channel and drives activation through `RosterHistory` /
  `Hashgraph::add_member`.
