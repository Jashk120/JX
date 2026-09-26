# Flaky e2e tests: convergence divergence under chaos/churn/isolation

Status: open — heavy offenders quarantined behind `--run-quarantine`; root cause not fixed
Date: 2026-09-25 (updated 2026-09-26)
Component: `tests/` (harness + heavy e2e), `consensus-node/protocol/{gossip,consensus}`
Related: [`checkpoint-reconnect-retention.md`](checkpoint-reconnect-retention.md)
(the checkpoint-lag / checkpoint-only recovery this flakiness overlaps with)

This document records which heavy e2e tests are flaky, **where** they fail,
the observed failure signatures, and what is / is not yet known about the
cause. It exists because the heavy suite is currently not a trustworthy
gate — it fails on the pre-fix tree as often as after the latency work.

---

## 0. TL;DR

Running `pytest tests -m chaos` (5 tests), the same 3 fail **consistently**,
not randomly:

| test | marker | result | signature |
|---|---|---|---|
| `test_chaos.py::test_random_latency_chaos` | chaos, bench, slow | **FAIL** | `frontiers_within_bound` — decided rounds diverge (~23 apart) |
| `test_chaos.py::test_isolate_single_node` | chaos, slow | **FAIL** | after heal the **isolated** node ends ~21 rounds **ahead** |
| `test_gossip_6node.py::test_6node_churn_kill_restart` | chaos, slow | **FAIL** | `max_cp - min_cp <= 2` — checkpoint rounds diverge |
| `test_gossip_6node.py::test_6node_latency_jitter_100ms` | gossip, chaos, slow | PASS | — |
| `test_gossip_6node.py::test_6node_partition_and_heal` | gossip, chaos, slow | PASS | — |

- These are **not** caused by the latency/backoff work (`d03fe60`, `c6658ab`):
  `test_6node_churn_kill_restart` fails ~2/3 of the time on the pre-fix tree
  too; `test_isolate_single_node` failed on the pre-fix tree as well.
- The failures are **all on convergence/divergence assertions**, and the
  spreads are large (8–23 rounds), which is why this does **not** look like a
  purely racy assertion — see §3.

---

## 1. Where it is flaky (exact assertions)

### 1.1 `test_chaos.py::test_random_latency_chaos`

- 60 s of randomized mesh latency (10–150 ms), jitter, drop (0–10 %); then
  stabilize to 15 ms / 0 drop, submit 5 tx, then
  `wait_for_decided_round(all, min_round=3, timeout=45)`.
- Assertion (`test_chaos.py:110`):
  `frontiers_within_bound(statuses, bound=5)`.
- Observed failures:
  - `{1:114, 2:114, 3:114, 4:91, 5:114, 6:91}` → spread 23 (bound 5).
  - `{1:35, 2:53, 3:37, 4:35, 5:54, 6:54}` → spread 19.
- So some nodes reached round 114 while others sat at 91 — a ~23-round lag
  that did not close within the 45 s wait after the mesh stabilized.

### 1.2 `test_chaos.py::test_isolate_single_node`

- `mesh.isolate_node(6)`, submit to the majority, wait for majority to advance,
  `mesh.heal()`, submit again, then
  `wait_for_decided_round(all, min_round=baseline+2, timeout=60)`.
- Assertions: `frontiers_within_bound(majority, 3)`,
  `checkpoint_roster_consistent`, `frontiers_within_bound(healed, 4)`,
  `len(peers) >= 4`.
- Observed failure (`test_chaos.py:190`):
  `{1: 9, 2: 9, 3: 9, 4: 9, 5: 9, 6: 30}` → the **isolated** node 6 ends 21
  rounds **ahead** of the majority that stayed connected.

### 1.3 `test_gossip_6node.py::test_6node_churn_kill_restart`

- Kill node 6 (SIGKILL), wait 3 s, restart it, submit more, then
  `wait_for_decided_round(all, min_round=4, timeout=45)`.
- Assertion (`test_gossip_6node.py:337`):
  `max_cp - min_cp <= 2` over all nodes' `latest_checkpoint_round`.
- Observed failures:
  - `{1:9, 2:1, 3:9, 4:4, 5:9, 6:None}` → cp 1..9, spread 8.
  - `{1:7, 2:6, 3:9, 4:9, 5:9, 6:None}` → spread 3.
  - `{1:9, 2:9, 3:7, 4:9, 5:5, 6:None}` → spread 4.
- Note the flaky set varies run to run (it is not always the restarted node
  that lags), which matches the "starving set varies run to run" note in
  `checkpoint-reconnect-retention.md`.

---

## 2. Failure rate (same box, release binary)

| test | pre-fix (`d03fe60`) | post-fix (`c6658ab`) |
|---|---|---|
| `test_6node_churn_kill_restart` | 2 pass / 6 (~67 % fail) | 1 pass / 4 (~75 % fail) |
| `test_isolate_single_node` | fails | fails |
| `test_random_latency_chaos` | pass | ~50 % (randomized) |

Sample sizes are small (n≈4–6), so the churn difference is **not** significant
— the point is that the baseline already fails at a comparable rate. These
tests were flaky **before** the latency/backoff work.

---

## 3. Is it "just flaky", or a real bug?

Mixed — there are likely **two** things going on:

**(a) Test-side race (affects all three).** The assertions sample a tight
bound *immediately* after `wait_for_decided_round`, with no settle window.
`wait_for_decided_round` returns as soon as the **last** node reaches
`min_round`, so any node that raced ahead is sampled at its caught-up peers'
expense. This is exactly how a fast node ends up 20+ rounds ahead in the
sample.

**(b) Node-side divergence (the isolate case looks real).** In the isolate
failure, node 6 did not just get sampled early — it **ended ahead and the
majority never caught up**:

- node 6 log: `checkpoint-only fetch starting peer=NodeId(2)` →
  `succeeded`, then repeated `checkpoint-only adoption rejected, trying next
  peer` — it advanced to `decided_round=30`.
- nodes 1–5 log: all stopped at `decided_round=9`, and node 1 was otherwise
  **healthy** at shutdown: `sync_attempts=212 sync_success=208
  success_rate=0.98`, `insert_count=1082`.

So node 1 kept syncing and inserting events but its `decided_round` froze at
9. That is a **round-decision / fanout-liveness stall**, not a sampling race.
It is consistent with the checkpoint-only recovery path
(`CHECKPOINT_LAG_ROUNDS`, `adopt_signed_checkpoint`) advancing one node's
watermark while the majority stalls — i.e. the same area as
`checkpoint-reconnect-retention.md`.

The churn failures (checkpoint spread 1..9, restarted node `None`) are most
likely **(a)** plus the known checkpoint-lag residual: `latest_checkpoint_round`
lags `decided_round` while quorum sigs assemble, so a bound of 2 is tight and
the restarted node is the slowest to accept.

---

## 4. Hypotheses (to confirm/deny next session)

- **H1 (test).** Assertions need a settle window / a "wait until spread ≤
  bound" helper instead of a single `wait_for_decided_round` + immediate
  assert. Cheap to test: add a bounded-retry wait and see if churn/chaos
  stop failing.
- **H2 (isolate, likely real).** `LatencyMesh.isolate_node(6)` is asymmetric
  (ingress only per the harness README), so node 6 can still initiate outbound
  syncs and advance, while the majority stalls — a split that `heal()` does
  not reconcile. Needs a log-level trace of node 6 vs 1–5 round/witness
  progression during the isolation window.
- **H3 (churn, likely test + checkpoint lag).** `max_cp - min_cp <= 2` is
  tighter than the checkpoint-lag residual; relax to a "wait until within 2"
  with a timeout, or assert on `decided_round` instead.
- **H4.** `wait_for_decided_round(require_all=True)` returning on the last
  node masks the spread; the tests should assert convergence, not "everyone
  crossed a line".

---

## 5. Other issues for next session

1. **The heavy suite is not a gate right now.** `-m chaos` fails ~60 % of its
   tests on a clean tree. Any change landing on `develop` cannot be validated
   by it. Decide: fix the flakes, or mark the 3 offenders `xfail`/quarantine
   until investigated so CI is meaningful again.
2. **Cross-check against `checkpoint-reconnect-retention.md`.** The isolate
   node-6-ahead behaviour and the churn checkpoint spread both sit in the
   checkpoint-acceptance / checkpoint-only recovery area that doc already
   flags (residual: adoption jumps the watermark; `.rsf` files skipped).
3. **`isolate_node` semantics.** Confirm from `tests/harness/proxy.py` whether
   isolation blocks ingress, egress, or both — the isolate test's premise
   ("isolated node is behind or stalled") is only valid for full isolation.
4. **No settle/sync helper.** Consider a `wait_for_convergence(nodes, bound,
   timeout)` in `harness/metrics.py` that polls until
   `frontiers_within_bound` holds, replacing the
   `wait_for_decided_round` + assert pattern in the three tests.
5. **Latency work is otherwise green.** `tests -m fast` passes (p50 0.107 s,
   TPS 231.8); `cargo test -p gossip` / clippy / fmt green. The only open
   verification gap is these heavy tests.

---

## 6. How to reproduce

```bash
cd consensus-node && cargo build --release --bin jkaind && cd ..
# full chaos marker (5 tests, ~2 min):
JKAIND_BIN=consensus-node/target/release/jkaind pytest tests -m chaos -v -p no:cacheprovider
# single offenders:
JKAIND_BIN=consensus-node/target/release/jkaind pytest \
  "tests/test_chaos.py::test_isolate_single_node" -v -s
JKAIND_BIN=consensus-node/target/release/jkaind pytest \
  "tests/test_gossip_6node.py::test_6node_churn_kill_restart" -v
# preserve node logs for a failing run:
JKAIN_KEEP_TMP=1 JKAIND_BIN=consensus-node/target/release/jkaind pytest \
  "tests/test_chaos.py::test_isolate_single_node" -v -s
# then: grep -h "round decided\|checkpoint-only\|reconnect" \
#   /tmp/jkain-harness-*/data-*/logs/jkaind.log.*
```

## 7. Preserved artifacts (this session)

Node logs from the failing runs are under `/tmp/jkain-harness-*`
(`data-<n>/logs/jkaind.log.<date>` and `diagnosis.log`). The isolate run whose
node 6 raced to 30 while nodes 1–5 froze at 9 is
`/tmp/jkain-harness-jm8smqua`; the chaos-run directory with frontier 91..114
is `/tmp/jkain-harness-_4mpibv9`. These are `mkdtemp` dirs and may be cleared
on reboot — re-run with `JKAIN_KEEP_TMP=1` to regenerate.

---

## 8. Update 2026-09-26 — assertions made to wait, offenders quarantined

**The assertions were sampling, not waiting.** The three tests called
`wait_for_decided_round` and then checked a frontier / checkpoint / roster bound
on the returned snapshot. Every node satisfies the `min_round` floor long before
the bound is evaluated, so the wait returned on the first poll and the bound saw
a live snapshot (§3a confirmed). Fixed in `tests/harness/metrics.py`:
`wait_for_convergence` (decided spread, optional floor),
`wait_for_checkpoint_convergence` (a `None` checkpoint counts as divergence) and
`wait_for_roster_consistency`.

**Quarantine.** The offenders are marked `@pytest.mark.quarantine` and skipped
unless `--run-quarantine` is passed (`tests/conftest.py`, `tests/pytest.ini`):
`test_random_latency_chaos`, `test_isolate_single_node`,
`test_6node_churn_kill_restart`, `test_6node_concurrent_tx_load`. With those
skipped, `pytest tests -m chaos` is green (jitter + partition only).

**Refreshed evidence (release binary, 6-node, same box).**

| test | result | note |
|---|---|---|
| `test_isolate_single_node` | 1 pass / 2 fail | once the snapshot race is gone the failures are **real**: intra-majority spread 163 vs 23 during isolation, and after heal node 6 stuck 59 rounds behind (60 s timeout). |
| `test_random_latency_chaos` | 1 pass / 1 fail | one full-suite failure was `OSError errno 98` binding a proxy port in `LatencyProxy.start()` — a harness `_free_port()` TOCTOU race, not divergence. |
| `test_6node_churn_kill_restart` | flaky | a standalone run stalled the 5-node majority at `decided=2` for 30 s; a full-suite run passed. |
| `test_6node_concurrent_tx_load` | 2/2 fail | checkpoint spread 8 (`[16,12,8,16,10,13]`, bound ≤1) and decided `{16,125,125,16,172,118}`. |
| `test_gap_vs_fanout_sweep` | fail | `p50 0.103s` below the `0.15` floor: machine calibration, not divergence; left un-quarantined. |

**Open.** The failures are node-side divergence / fanout-liveness stalls
(consistent with §3b and `checkpoint-reconnect-retention.md`), now surfaced
reliably by the waiting helpers. A green `-m chaos` means only that the two
healthy tests passed; the quarantined set still needs the node-side fix.
`test_gap_vs_fanout_sweep`'s band needs recalibration or quarantine (owner call).
