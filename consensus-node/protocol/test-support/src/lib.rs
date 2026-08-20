//! Shared test timing constants and helpers.
//!
//! Single source for `SYNC_INTERVAL`, `SYNC_TIMEOUT`, and `DEADLINE` used
//! across `node` and `gossip` integration tests. Previously these were
//! copy-pasted between `node/tests/common` (DEADLINE 30s) and
//! `protocol/gossip/tests/common` (DEADLINE 15s) — the 15s vs 30s drift is
//! now resolved in favor of 30s (conservative upper bound; cost only shows
//! up on already-failing tests).

use std::time::Duration;

/// How often the sync driver picks a peer and runs a sync round in tests.
pub const SYNC_INTERVAL: Duration = Duration::from_millis(25);
/// How long a single sync round may block in tests.
pub const SYNC_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound for any `wait_for_*` helper — not a protocol deadline.
/// 30s is deliberately conservative for 2-core CI runners.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// Tighter poll interval used by `wait_for_*` helpers when they must poll.
/// Tie to `SYNC_INTERVAL` where possible, but keep it distinct so helpers
/// can poll slightly faster than the driver if desired.
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Test helper: wall-clock millis since UNIX_EPOCH, with the same semantics
/// as the production `now_timestamp` pre-clamp path. Relocated here from
/// `gossip/tests/common/mod.rs` (audit 8.2) to avoid duplication.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
