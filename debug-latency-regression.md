# Debug Journal — Gossip Latency Regression (10× submit→decided)

> Continuation note. Everything we've established so far, every option we
> tried and why it failed, and the current leading hypothesis — so the next
> session can pick up exactly here.

## TL;DR

A ~10× latency regression: `submit→decided` went from **0.230 s** (baseline
`f28d648`) to **~2.1–3.0 s** on HEAD, release build, 6-node direct LAN,
`sync_interval 25 ms`. The phase breakdown is **100% gossip**
(`submit→ordered`); consensus (`ordered→decided`) and checkpoint are ~0.

**What we now know:** it is **not** a per-event CPU cost. Signature
verification (26 µs), fanout multiplicity, dedup, the fame gate, the fame
backfill loop, and the eager-decision pipeline are **all exonerated**. The
insert critical section's total cost is ~108 µs/event (~0.2% CPU). The latency
is a **dissemination / hop-count problem** — a tx now takes ~84 sync intervals
to order instead of ~9.

**Leading hypothesis (untested):** `971ad1f`'s "chain k own events per tick"
deepened each node's `self_parent` chain ~4× (k=4 events/tick chained via
`self_parent` instead of 1), which (a) makes `strongly_see` walks longer and
(b) spreads witnesses across more rounds, so a round needs more events to
reach its strongly-see supermajority. The one measurement that supports this:
`finalize_round` cost **grows** with the graph (19 µs → 84 µs over the test),
and `finalize_round` is the dominant insert cost.

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

## What is NOT yet ruled out (the actual latency)

The latency is **how many sync intervals (25 ms) a tx needs to reach "ordered"
on all 6 nodes**. Baseline ~9 intervals; now ~84. This is a
**graph-structure / round-ordering cadence** problem, not CPU. Leading suspect:
**deep `self_parent` chains from `971ad1f`'s "chain k own events per tick"** —
each node mints k=4 chained events per tick, so chains grow ~4× faster, and
`strongly_see` (round advancement) has to walk 4× deeper chains.

### The discriminating experiment (next step)

Run the **same instrumented build at `JKAIN_FANOUT=1`** (serial path, 1
event/tick, shallow chains) and compare:

- If `finalize_round` stays flat (~19 µs) **and** latency drops → deep-chain
  theory confirmed; fix is structural (don't chain empty-shard events).
- If fanout=1 is still slow **and** `finalize_round` still grows → depth is
  coming from somewhere else (e.g. the push-back `SyncOutcome` delivery, or the
  round/witness assignment).

Also worth a look: the earlier runs showed a sharp **bimodality** (~2.1 s vs
~4.1 s — a clean 2×). It didn't reproduce in the cleanest run (all ~2.1 s), but
when it appears it suggests a periodic / every-other-round phenomenon.

---

## Reference measurements

| config | decided p50 | notes |
|---|---:|---|
| `release` @ `f28d648` (baseline) | 0.230 s | README, reproduces 0.536 s debug-era |
| `release` @ HEAD (README 2026-09-23) | 2.156 s | p95 4.028 s |
| `release` @ HEAD, this box (gates ON) | 3.041 s | box load varies; bimodal ~2.1/4.1 |
| `release` @ HEAD, this box (gates OFF) | 2.560 s | fame-gate experiment |
| `release` @ HEAD, this box (instrumented) | 2.116 s | least-loaded run; no bimodality |
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

Diagnostic-only, read-only (no consensus-behavior change). Files touched:

- `consensus-node/protocol/consensus/src/hashgraph.rs` — `InsertTiming` struct
  + `insert_timing` field (init in `new` and `from_checkpoint`) + timing in
  `insert` + `insert_timing()` getter.
- `consensus-node/protocol/consensus/src/fame.rs` — timing in `vote_as_witness`
  (candidate loop / backfill loop / each `try_eager_decide`).
- `consensus-node/protocol/consensus/src/lib.rs` — `InsertTiming` re-export.
- `consensus-node/protocol/gossip/src/node.rs` — `log_insert_timing()` helper +
  2 call sites (serial + fanout periodic metrics logs, every 10 syncs).

The release binary is currently built **with** this instrumentation. To revert
everything: `git checkout -- consensus-node/protocol/consensus consensus-node/protocol/gossip/src/node.rs`
then `cargo build --release --bin jkaind`.

Leftover temp dir from `JKAIN_KEEP_TMP=1`: `/tmp/jkain-harness-cvc20an0`
(node logs incl. `insert timing` lines, in `data-*/logs/jkaind.log.<date>`).

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

1. Does `JKAIN_FANOUT=1` flatten `finalize_round` and drop latency? (deep-chain
   discriminator — run it first.)
2. If deep-chain is confirmed: what's the sound fix? Options to weigh — mint
   only as many chained events as there is payload to shard (skip empty shards),
   vs. one event per tick with k parent references, vs. un-chaining the k
   events (the chain exists to avoid a concurrent self-parent fork; that
   constraint may be satisfiable differently).
3. The push-back `SyncOutcome` delivery (`run_sync` / `run_sync_with_precreated_event`)
   has not been isolated from the chained-events change — they landed together
   in `971ad1f`.
4. What drives the ~2.1 s vs ~4.1 s bimodality when it appears?
