# Phase-0 spike — ancestry walk depth for the reconnect window W

Status: complete — W recommendation pending owner ratification
Date: 2026-09-17
Component: consensus-node/protocol/{consensus,gossip}
Related: .omo/plans/PLAN-4-consensus-reanchor.md

## 1. Purpose

PLAN-4 Hard Condition 2 requires the signed reconnect window `W` (rounds)
to strictly exceed the maximum depth the two ancestry walks reach, with
margin. The two walks are `member_chain_reaches`
(`consensus-node/protocol/consensus/src/ancestry.rs:120-148`) and
`first_seen_timestamp`
(`consensus-node/protocol/consensus/src/order.rs:170-216`).

Verified: depth was measured on a live cluster with added counters, not
guessed from code reading. Assumption prior to this spike was that closure
walks could in principle descend the full retained history; this report
replaces that assumption with measured maxima.

Reproduction: `JKAIND_BIN=<debug jkaind> python3 /tmp/opencode/spike_walk.py <seconds> 80 <healthy|partition>`
(temporary driver, not committed) plus the walk counters in `jkaind status`.

## 2. Instrumentation

Verified: `consensus::Hashgraph` now carries `WalkMetrics` (relaxed atomics,
read-only) exposed as `result.walk_metrics` in `jkaind status` with eight
fields: `member_chain_max_steps`, `member_chain_hard_stops`,
`first_seen_max_span`, `first_seen_missing_boundary`,
`member_chain_max_round_span`, `first_seen_max_round_span`,
`member_chain_max_transition_steps`,
`member_chain_max_transition_round_span`. Commits `ba34ce3` and `47473dd`.

The counters form two families. All-exit maxima record every walk exit,
including false-answer closures that descend to genesis or the prune edge.
Transition-only maxima record only walks where `see(hash,y)` first returns
true, that is the depth at which the answer flips from false to true.

The counters are debug-only: updates go through `WalkMetrics` helper methods
gated by `cfg(debug_assertions)`, so release builds compile the updates out
(zero cost on the consensus hot path) and `walk_metrics` reports zeros there.
Debug builds keep the exact behavior described above, which is what the 6-node
harness and the scheduled N=100 + forks spike re-run use. If release-build
measurement is ever needed, add a dedicated Cargo feature for it.

## 3. Runs

Three real 6-node runs (80 ms sync interval, debug `jkaind`, direct LAN):

- Run A: healthy, pruning on (`RETENTION_ROUNDS=2`), 90 s, reached ~31 decided rounds.
- Run B: partition `{1,2,3}|{4,5,6}` for 15 s then heal, pruning on, 180 s, reached ~52 decided rounds.
- Run C: healthy, pruning temporarily disabled (`RETENTION_ROUNDS=u64::MAX` in a local build, reverted afterwards), 150 s, reached ~50 decided rounds.

"W=2" below means the production `RETENTION_ROUNDS = 2` (pruning enabled).

## 4. Results

Units in headers. `n/a` means the counter did not exist in that build.

| counter | A healthy (W=2) | B partition (W=2) | C pruning disabled |
|---|---|---|---|
| member_chain_max_steps | 186 | 211 | 470 |
| member_chain_hard_stops | 12,123 | 22,217 | 0 |
| member_chain_max_round_span | 22 | 23 | 50 |
| member_chain_max_transition_steps | n/a | n/a | **1** |
| member_chain_max_transition_round_span | n/a | n/a | **0** |
| first_seen_max_span (seqs) | 42 | 31 | 33 |
| first_seen_max_round_span | 2 | 2 | 2 |
| first_seen_missing_boundary | 0 | 0 | 0 |

## 5. Interpretation

- Every `see`-true transition in `member_chain_reaches` occurs on the first event of the walk (max transition steps 1, round span 0). This is a consequence of ancestry monotonicity: if the frontier event does not see `y`, no ancestor in its self-parent chain can either, so the loop can only ever flip to `true` immediately; otherwise it can only exhaust.
- Therefore the large `member_chain_max_steps` / `member_chain_max_round_span` values (including 470 steps / 50 rounds with pruning off) are non-transition closures, false-answer walks descending to the creator's genesis. In production these are truncated at the prune edge, which is why run C shows `hard_stops = 0` while A/B show thousands.
- The correctness-relevant depth is the transition depth: 0 rounds for `member_chain_reaches`, and at most 2 rounds for `first_seen_timestamp` (its boundary event). `first_seen_missing_boundary` was 0 in all three runs, including at `W = 2`.
- The 12k-22k hard stops at `W = 2` are wasted closure work, not wrong answers: by monotonicity a truncated false walk still returns the correct `false`. They are a performance finding, not a safety one, for non-forking creators.

## 6. Consequence for W

W must strictly exceed the measured transition depth (2 rounds) with margin.
Recommendation: **W = 16** (8x margin; deliberately aligned with
`CHECKPOINT_LAG_ROUNDS = 16`).

Trade-off, stated explicitly: a larger W lets false-answer closure walks
descend further before the prune edge truncates them, so W should be small
enough to bound that work and large enough for the transition/boundary
margin. W is still pending owner ratification and is not yet wired into
`RETENTION_ROUNDS`.

## 7. Caveats / not measured

- N=6 and N=8 only (the plan's open question 4 spans 6..100). A follow-up N=8
  run (80 ms, healthy, ~44 decided rounds) measured
  `first_seen_max_round_span = 3` and `member_chain_max_transition_round_span
  = 0`. The `first_seen_timestamp` boundary depth rose from 2 (N=6) to 3 (N=8),
  so it may grow with `N`; `W = 16` still has margin, but this is the quantity
  the N=100 gate exists to bound and it is not safe to extrapolate from N=8.
- No forking (Byzantine) creators, so the fork slow path (`ancestor_event_for_creator`) and its transition depth are unexercised.
- 80 ms sync interval and healthy/partition only (no 25 ms, no churn-kill-restart).
- The transition counters are per-`Hashgraph` and reset if a node rebuilds its graph on reconnect (observed on one node in run B), so per-run peaks may under-count across resets.

## 8. Follow-ups

- (a) Wired: `RETENTION_ROUNDS = SIGNED_WINDOW_ROUNDS = 16` (PLAN-4 Phase A); owner ratification of the value is still outstanding.
- (b) Candidate optimization: exploit the monotonicity above to skip the `member_chain_reaches` chain descent entirely for creators with no known fork (it cannot change the result), removing the hard-stop work; requires the determinism argument in `ancestry.rs:65-78`.
- (c) Re-run this spike at N=100 and with injected forks before shipping a wide deployment.

## 9. References

- `.omo/plans/PLAN-4-consensus-reanchor.md`, Hard Condition text in PLAN-4 §A-0.
- `docs/issues/checkpoint-reconnect-retention.md` sections 2, 4, 5.
- Commits `ba34ce3`, `47473dd`.
