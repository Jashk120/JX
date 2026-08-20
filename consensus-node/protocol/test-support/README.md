# test-support

Shared test helpers for the JKain workspace.

This crate exists to keep a single source of truth for timing and helper
constants that would otherwise be copy-pasted between `protocol/gossip`
and `node` integration tests.

## Contents

- `SYNC_INTERVAL` — how often the sync driver picks a peer (25 ms in tests).
- `SYNC_TIMEOUT` — per-round sync deadline (500 ms).
- `DEADLINE` — upper bound for `wait_for_*` helpers (30 s, conservative for 2-core CI).
- `POLL_INTERVAL` — poll interval for `wait_for_*` helpers (10 ms).
- `now_millis()` — wall-clock millis since `UNIX_EPOCH`, matching the production `next_timestamp` pre-clamp path.

## Design

- No production dependencies: only `tokio` for time types, otherwise pure constants.
- Timing values are deliberately conservative (`DEADLINE` 30 s) so failing tests surface slowly rather than flaking on slow runners.
- Helpers live here instead of `protocol/gossip/tests/common` so `node/tests` can reuse them without pulling in `gossip` test utilities.

## Usage

```rust
use test_support::{SYNC_INTERVAL, SYNC_TIMEOUT, DEADLINE};

let node = GossipNode::new(
    node_id, signing_key, registry, identity, peers,
    SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
    state_db,
);
```
