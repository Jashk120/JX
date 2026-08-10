# state

Deterministic transaction execution for JKain.

Implements Phase 8 of `ROADMAP.md`: a pure executor that consumes events in
the finalized consensus order produced by `consensus` and folds each
transaction's payload into a key-value `State`. Depends on `primitives` for
the value types (`Event`, `Transaction`) and on `consensus` for the
hashgraph whose `consensus_order` yields the input sequence.

## Contents

- `State` — the executor's key-value state. A `BTreeMap` from byte string
  to byte string, mutated only through the pure, deterministic `apply`
  function and serialized canonically by `to_bytes` (ascending key order,
  `u32` big-endian length prefixes matching `crypto`'s canonical encoding).
- `Op` — the pure-KV transaction payload: one opcode byte plus
  length-prefixed fields. `0x00` `Put { key, value }`, `0x01`
  `Delete { key }`. `DecodedOp` is the top-level decode result: KV ops go to
  `State`, while `0x02` `MembershipOp` bodies are decoded by
  `crypto::MembershipOp` and returned as a side channel. Any other opcode, a
  truncated payload, or trailing bytes decodes to a deterministic
  `ExecutorError`.
- `Executor` — applies transactions to a `State` in the order presented.
  `execute_event` applies every valid KV transaction and returns
  `(Vec<ExecutorError>, Vec<MembershipOp>)`; membership ops never touch
  `State`. `bucket_finalized` feeds a finalized `(event, roundReceived)`
  batch through the executor once, bucketing membership ops by roundReceived
  behind a processed-round watermark.
- `finalized_events` — bridges to the consensus layer: walks a `Hashgraph`'s
  rounds in increasing order and returns each round's events in the exact
  order `Hashgraph::consensus_order` produces, so the executor never invents
  its own ordering rule.

## Design

- Execution is pure and deterministic: no wall-clock reads, no randomness,
  no I/O inside `apply`/`execute_*`. The same finalized event order and the
  same starting state produce bit-identical resulting state on every node.
- Membership changes ride the consensus ordering as `0x02` payloads. They are
  never applied to `State`: the gossip layer collects them from the side
  channel and drives activation through `RosterHistory` /
  `Hashgraph::add_member`.
