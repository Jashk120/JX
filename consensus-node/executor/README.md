# executor

The deterministic execution layer of JKain (Phase 8 of `ROADMAP.md`, extended
with `did:jkain` in `docs/DID_method.md` and hardened with monotonic
timestamps and durable watermark persistence): turning the total order
produced by consensus into an application state.

This umbrella directory holds one crate:

- `state/` — a pure, deterministic executor. Consumes events in the
  finalized consensus order and folds each transaction's payload into a
  key-value `State` backed by a Fjall LSM partition (with a write-ahead log)
  through a deterministic `apply` function (`Op::Put`/`Delete` plus
  `DidOp` `0x03` for `did:jkain` documents, all sharing the same `State::Put`
  path with Merkle commitment). The same finalized order and starting state
  yield bit-identical state on every node, which is what makes `State::root()`
  (the Merkle root over the state) a valid checkpoint commitment. The state
  database (`StateDb`, `<data>/statedb/`) also persists a
  per-accepted-checkpoint-round snapshot (the `snap` keyspace) that restart
  recovery and reconnect serving restore state from — replacing the old `.snap`
  files.

## How it fits

`consensus` (in `protocol/`) produces the event order; `state` consumes it.
`gossip` drives the ordering and snapshots the committed state into
checkpoints, and the `node/` layer persists those checkpoints for restart
recovery.
