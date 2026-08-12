# executor

The deterministic execution layer of JKain (Phase 8 of `ROADMAP.md`):
turning the total order produced by consensus into an application state.

This umbrella directory holds one crate:

- `state/` — a pure, deterministic executor. Consumes events in the
  finalized consensus order and folds each transaction's payload into a
  key-value `State` through a side-effect-free `apply` function. The same
  finalized order and starting state yield bit-identical state on every
  node, which is what makes `State::to_bytes()` a valid checkpoint
  commitment.

## How it fits

`consensus` (in `protocol/`) produces the event order; `state` consumes it.
`gossip` drives the ordering and snapshots the committed state into
checkpoints, and the `node/` layer persists those checkpoints for restart
recovery.
