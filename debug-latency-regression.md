# Debug Journal — Gossip Latency Regression (10× submit→decided)

> Continuation note. Everything we've established so far, every option we
> tried and why it failed, and the current leading hypothesis — so the next
> session can pick up exactly here.

## TL;DR

A ~10× latency regression: `submit→decided` went from **0.230 s** (baseline
`f28d648`) to **~2.1–3.0 s** on HEAD, release build, 6-node direct LAN,
`sync_interval 25 ms`. The phase breakdown is **100% gossip**
(`submit→ordered`); consensus (`ordered→decided`) and checkpoint are ~0.

**ROOT CAUSE (verified): peer backoff starvation.** Transient TCP errors
(`Broken pipe`, `connection closed`) call `PeerManager::record_failure`
(`peer_manager.rs:245`), which sets an exponential `backoff_until`
(`1 << min(failures, 6)` s → 2, 4, 8, …, 64 s). `pick_k` / `random_peer`
**never select a peer in backoff**, and only `record_success` clears the
backoff — but a backed-off peer is never retried, so it can never succeed.
The backoff is **self-locking**: 4–5 of 5 peers end up backed off, `pick_k(4)`
returns ~1 (or 0), the fanout collapses k=4 → ~1, dissemination stalls, and
rounds advance only every **~2.05 s** (= the `2¹` first backoff step).
`submit→decided` ≈ one round cadence ≈ 2.1 s.

**Proof (A/B, same box, same test):** disabling `record_failure`'s backoff
(one line) changed:

| signal | backoff ON | backoff OFF |
|---|---:|---:|
| `backoff_peers` (of 5) | 4–5 | 0 |
| `concurrent_syncs` | 1 | 4 |
| round cadence | ~2.05 s | ~0.1 s |
| `decided p50` | 2.239 s | **0.105 s** |

21×, and *below* the 0.230 s baseline. (Experiment reverted; backoff restored.)

**Everything else is exonerated:** not a per-event CPU cost (verification
26 µs; insert ~108 µs/event ≈ 0.2% CPU), not fanout multiplicity, not dedup,
not the fame gate, not the backfill loop, not eager-decide, and not the driver
loop (healthy: ~33 ms/tick, ~30 ticks/s). Those levers all washed out *because*
backoff had already collapsed the effective fanout to ~1 peer — which is also
why `--fanout 1` and `--fanout auto` measured the same.

**Underlying trigger (separate from the regression):** ~13–42% of syncs fail
with TCP `Broken pipe` / connection churn (the QUIC hot-pool that was meant to
fix this was removed in `6522d86`). Without the backoff self-lock, those
failures are harmless — the no-backoff run still had ~42% failures but ran at
0.105 s. So the *latency* is the backoff logic, not the failures themselves.

---

## ROOT CAUSE — mechanism in full

1. The `b8f3c1f` / `8beecc6` era introduced `PeerManager` scoring with
   `record_failure` → exponential `backoff_until`, and `pick_k` filtering
   `NEG_INFINITY` backoff peers (`peer_manager.rs:211-213`).
2. A transient TCP error (stale pooled connection → `Broken pipe`) is treated
   as a *peer* failure and backs the peer off for `2^failures` seconds.
3. `pick_k` never picks it; `record_success` (the only clearer) never runs for
   it → the peer stays backed off the full duration.
4. Multiple peers fail transiently → 4–5 of 5 backed off → `pick_k(4)` yields
   ~1. `pick_k`'s `random_peer` fallback (`peer_manager.rs:227-231`) *also*
   filters backoff, so when all 5 are backed off it returns **empty** →
   `concurrent_syncs: 0`, no sync at all that tick.
5. Graph growth is starved → round cadence ~2.05 s (= first backoff step) →
   `submit→decided` ~2.1 s.

### Fix options (not yet implemented)

- **Do not apply peer backoff to transient connection errors** (`Broken pipe` /
  `Io` / `Closed`): reset the transport and retry next tick (the baseline
  behaved this way and was fast). Reserve backoff for protocol-level /
  persistent failures. *Minimal, targeted fix.*
- **Cap the backoff** much lower (e.g. 100–250 ms) and/or make the first step
  sub-second, so a transient blip cannot freeze dissemination for 2 s+.
- **Make the `random_peer` fallback ignore backoff** so an all-backoff tick
  still makes *some* progress (breaks the zero-sync deadlock).
- **Fix the connection churn at the source** (persistent hot-pool / QUIC),
  removing the trigger — but the no-backoff run proves the latency is the
  backoff logic, not the churn.

**Deep-chain hypothesis is REFUTED:** `--fanout 1` (serial path, 1 event/tick,
no chaining) was *also* ~2.4 s, and the instant backoff was removed latency hit
0.105 s.

---

## The measurement that matters — insert-phase timing

Instrumented `Hashgraph::insert` and logged per-phase wall-clock (nanoseconds,
accumulated, release build). Steady state (`insert_count ≈ 1037`, one node):

| phase | avg cost | runs on | % of insert |
|---|---:|---|---:|
| **`finalize_round`** (strongly-see walk) | **~84 µs** | *every* insert | ~78% |
| **`vote_as_witness`** (fame vote) | ~207 µs | witnesses only (~11%) | ~21% amortized |
| └ candidate vote loop (`vote_of` + eager) | ~206 µs | (inside vote) | — |
| └ **backfill loop** | **~19 ns** | (inside vote) | ~0 |
| └ **`try_eager_decide`** | **~66 ns** | (inside vote) | ~0 |
| **total `insert`** | **~108 µs** | | 100% |

Key growth signal — `finalize_round_avg_ns` grows with the graph (chain depth):

| `insert_count` | `finalize_round_avg_ns` |
|---|---:|
| 202 | ~19 µs |
| 532 | ~44 µs |
| 1037 | ~84 µs |

Interpretation:

- `finalize_round` = `strongly_see_at` → `member_chain_reaches`
  (`ancestry.rs:96/120`): an `O(members × chain_depth)` self-parent walk, run
  on **every** insert, behind the single `hashgraph` mutex. This is the real
  per-insert cost, and it is the only thing that scales.
- `vote_as_witness`'s cost is **entirely the candidate vote loop**
  (`vote_of` over all undecided witnesses below y). The backfill loop and
  `try_eager_decide` are noise.
- Even so, ~108 µs/insert at ~17 inserts/sec/node ≈ **0.2% CPU**. The mutex is
  not contended. Insert CPU is **not** the latency driver.

---

## Investigation log (chronological, with outcomes)

### 1. The README's own analysis — "verification is 99.9%" — **WRONG**

`tests/README.md` concluded the dominant cost is Ed25519 `verify_strict`
(~26 µs) and that the regression is a "volume" problem. **Why it misleads:**
its microbenchmark measured only `verify_strict` (26 µs, *outside* the lock),
`is_ancestor` (215 ns, the *fast path* = one `ancestor_seq` compare), and
SHA-256 (163 ns). It **never measured** the serialized `insert` critical
section (`finalize_round` + `vote_as_witness`). The "volume" conclusion was
already contradicted by `--fanout 1` still being slow.

### 2. User's mitigation table (5 items) — **all ineffective**

| # | Mitigation | Outcome |
|---|---|---|
| 1 | Parallelize inbound verification (JoinSet, then insert serially) | **Failed badly** — 2 e2e tests regressed 7.5 s → 104 s. Root cause: breaking the topological insert order → `MissingParent` → reconnect storm. Not verification cost. |
| 2 | Stop re-verifying already-present events (contains-before-verify) | **No win.** The delta is computed from the receiver's `known_summary` to *exclude* known events, so `AlreadyPresent` is rare by construction; dedup already suppresses resends. |
| 3 | Cache verifier per creator | Not attempted. Ceiling is small (`key_for` is already a plain `HashMap` lookup). |
| 4 | Cut event multiplicity (fewer k chained events) | Not attempted directly. `--fanout 1` = 2.41 s vs 2.15 s auto → fanout multiplicity is a small lever. |
| 5 | Keep dedup as-is (215 ns, fixes a real correctness bug) | Honored. `--dedup false` = 2.35 s → dedup is not the lever either. |

### 3. Fame-gate isolation (hypothesis: the `971ad1f` fame gate) — **only 0.5 s**

Disabled both gates in `try_eager_decide` (`fame.rs`: roster-churn gate
`count_next != count_agg`, and completeness gate `seen != voters.len()`),
rebuilt release, A/B measured on the same box:

| config | decided p50 | p95 |
|---|---:|---:|
| gates ON | 3.041 s | 4.082 s |
| gates OFF | 2.560 s | 3.812 s |

→ ~0.48 s of the gap, ~16%. **The fame gate is a contributor, not the cause.**
(Consistent with #4 below: `try_eager_decide` itself is ~66 ns; the gate only
changes *when* a round decides, not the per-insert voting work.)

### 4. Insert-phase instrumentation (this session) — **the key finding**

Added read-only timing to `insert` / `vote_as_witness` (see "In the tree"
below), ran the latency test, captured the table above. Conclusions:

- `finalize_round` (strongly-see) is the dominant insert cost and grows with
  graph depth.
- backfill + eager-decide are ~0 → hypotheses #2/#3 from the prior session are
  **refuted**.
- total insert CPU is ~0.2% → **the whole "per-event cost" framing is
  exhausted**. The latency is structural, not computational.

---

## What is DEFINITIVELY ruled out

| suspect | evidence | verdict |
|---|---|---|
| Signature verification (`verify_strict`) | parallelize → worse; contains-before-verify → no win | **ruled out** |
| Fanout multiplicity (k=4) | `--fanout 1` → 2.41 s | **ruled out** |
| Dedup / re-sends | `--dedup false` → 2.35 s | **ruled out** |
| Fame gate (`seen == voters.len()`, roster gate) | A/B → 0.5 s | **ruled out (minor)** |
| Fame backfill loop | ~19 ns | **ruled out** |
| Eager-decision churn (`try_eager_decide`) | ~66 ns | **ruled out** |
| `is_ancestor` / delta building / hashing | README microbench: noise | **ruled out** |
| Insert CPU (any phase) | ~108 µs/event ≈ 0.2% CPU | **ruled out** |
| Debug build profile / thermals | release helps ~1.5× only; no throttling | **ruled out** |

## How it was localized — loop timing + backoff

The insert profiling ruled out CPU, so the next suspect was the dissemination
*rate*. Instrumenting the driver loop showed it is **healthy**: ~33 ms/tick
(25 ms sleep + ~8 ms work), ~30 ticks/s, `drain` ~5–10 ms, `process` ~0.5 ms.
So the loop is not throttled — but `concurrent_syncs` was **1** and
`backoff_peers` **4–5**, and the round cadence was an eerily regular
**~2.05 s** (gaps `2.05, 2.11, 2.06, …`, occasionally `4.0` = a skipped beat).

`diagnosis.log` (1 s JSON, written by `node/src/cli/run.rs`) showed the smoking
gun: `{"concurrent_syncs": 1, "backoff_peers": 4}` — and at the tail
`{"concurrent_syncs": 0, "backoff_peers": 5}`. The fanout had collapsed to
~1 peer (and sometimes 0). The `~2.05 s` cadence is exactly the `2¹ = 2 s`
first backoff step of `record_failure`.

The A/B proof is in the TL;DR: disabling backoff → `backoff_peers 0`,
`concurrent_syncs 4`, round cadence ~0.1 s, `decided p50 0.105 s`.

### The bimodality is explained too

The earlier `~2.1 s` vs `~4.1 s` split is the backoff jumping between the
`2¹ = 2 s` and `2² = 4 s` steps as `consecutive_failures` climbs — a clean 2×,
which is why it looked "periodic".

---

## Reference measurements

| config | decided p50 | notes |
|---|---:|---|
| `release` @ `f28d648` (baseline) | 0.230 s | README, reproduces 0.536 s debug-era |
| `release` @ HEAD (README 2026-09-23) | 2.156 s | p95 4.028 s |
| `release` @ HEAD, this box (gates ON) | 3.041 s | box load varies; bimodal ~2.1/4.1 |
| `release` @ HEAD, this box (gates OFF) | 2.560 s | fame-gate experiment |
| `release` @ HEAD, this box (instrumented) | 2.116 s | least-loaded run; no bimodality |
| `release` @ HEAD, backoff **OFF** (experiment) | **0.105 s** | p95 0.190; `backoff_peers 0`, `concurrent_syncs 4` |
| `--fanout 1` | 2.41 s | user's measurement |
| `--dedup false` | 2.35 s | user's measurement |

## Key commits

- `f28d648` — baseline (0.230 s). Serial single-peer sync, no eager fame.
- `b8f3c1f` — *"Add dynamic fanout k=auto"* — first bad; cluster **stalls**
  (concurrent self-parent fork bug).
- `8beecc6` — *"Implement PLAN-2.4 waves 3-6 … eager fame"* — adds the eager
  fame pipeline (`try_eager_decide`) + backfill.
- `971ad1f` — *"Fix gossip liveness: chained k-events, push-back SyncOutcome,
  fame roster gate"* — restores liveness at ~10× cost. Changed gossip (chained
  k events, push-back) **and** consensus (fame gate).

## In the tree right now (uncommitted instrumentation on `develop`)

Committed in `ca2e868`: `InsertTiming` instrumentation (hashgraph.rs, fame.rs,
lib.rs) + `node.rs` `log_insert_timing()` helper + this journal.

Added this session, **uncommitted**:

- `consensus-node/protocol/gossip/src/node.rs` — driver-loop timing
  (`loop timing` log: `avg_period_ms` / `avg_drain_ms` / `avg_process_ms`).
- The backoff experiment (`peer_manager.rs`) was made, measured, and
  **reverted** — `backoff_secs` is back at `peer_manager.rs:249`.

The release binary is currently built **with the loop-timing only** (backoff
restored to HEAD). Revert everything with
`git checkout -- consensus-node/protocol/consensus consensus-node/protocol/gossip/src/node.rs`
then `cargo build --release --bin jkaind`.

## How to reproduce / measure

```bash
cd consensus-node && cargo build --release --bin jkaind
cd ..
JKAIND_BIN=consensus-node/target/release/jkaind pytest tests/test_finality_tps.py::test_latency_single_tx_direct -v -s
# fast tier (cheaper):
JKAIND_BIN=consensus-node/target/release/jkaind pytest tests -m fast -v -s
# capture insert-timing logs:
JKAIN_KEEP_TMP=1 JKAIND_BIN=consensus-node/target/release/jkaind pytest tests/test_finality_tps.py::test_latency_single_tx_direct -v -s
# then: grep -h "insert timing" /tmp/jkain-harness-*/data-*/logs/jkaind.log.*
```

## Open questions for next session

1. **Implement the fix.** Minimal: stop treating transient connection errors
   (`Io` / `Broken pipe` / `Closed`) as peer failures for backoff — reset the
   transport and retry next tick. Then re-run the fast tier and expect ~0.1 s.
2. Decide the backoff policy: keep *some* backoff for protocol-level failures
   (bad frame, wrong pin) vs none for connection errors; cap it sub-second; and
   make the `random_peer` fallback ignore backoff so the zero-sync deadlock
   can't recur.
3. Why is TCP churn so high (~13–42% `Broken pipe`)? The QUIC hot-pool
   (`6522d86` removed it) was the intended fix. Even with backoff fixed, churn
   wastes work — worth revisiting the transport.
4. Does the fix hold under the heavier tests (`-m fast`, `test_tps_sustained_6node`,
   `-m gossip`)? Backoff also affects the 100 ms-jitter and partition tests.
