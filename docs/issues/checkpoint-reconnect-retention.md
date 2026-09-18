# Checkpoint lag and reconnect retention

Status: Stage 1 shipped (`c2f485c`); PLAN-4 Phase A signed window shipped;
Stage 2 proposed
Date: 2026-09-17
Component: `consensus-node/protocol/{consensus,gossip}`, `consensus-node/node`

This document records (a) the checkpoint-liveness bug found by the e2e stress
pass and how it was fixed, (b) the still-open reconnect defect that blocks a
genuinely-behind node from catching up, and (c) the staged plan for resolving
it, including the upstream Hiero/Hedera design this repository already draws
on elsewhere.

---

## 1. The checkpoint-lag stall (fixed)

**Symptom.** On a 6-node cluster a minority of nodes stopped advancing their
accepted checkpoint for 60–120 s while still deciding rounds. Live status poll
(release binary, no thermal throttling):

| t | decided | accepted checkpoint |
|---:|---|---|
| 60 s | all 24 | `{1:16, 2:16, 3:17, 4:22, 5:20, 6:20}` |
| 180 s | all ~69 | `{1:34, 2:65, 3:67, 4:65, 5:20, 6:65}` |

Node 5 held checkpoint round 20 for 120 s while every node decided round 69.
The starving set varies run to run. It made `wait_for_checkpoint` over all
nodes unreliable (`tests/test_gossip_6node.py:78`, and the post-heal wait in
`test_6node_partition_and_heal`).

**Root cause.** A checkpoint needs a 5-of-6 BLS quorum over one round's
payload. Every node produces and gossips its own signature, but
`accept_checkpoint` drops a node's own signatures for rounds `<= accepted`
(`protocol/gossip/src/node.rs`, `outbound.retain(|sig| sig.round > round)`),
and `gossip_checkpoint_sigs` re-sends only what remains. A round's
signature-availability window therefore closes the moment the majority
accepts it, so a node that is even slightly late can never assemble quorum
for that round and recovers only by racing into a fresh one. `RETENTION_ROUNDS
= 2` (`protocol/consensus/src/checkpoint.rs`) is a snapshot-servability floor,
not a signature window — ~0.8 s at ~2.4 rounds/s, versus a 30–45-round lag.

Ruled out: thermal throttling, state/snapshot divergence, and an ordering
stall (`ordered_round == decided_round` on every node throughout the watched
run, so `is_round_decided` was not gating production).

**Fix shipped.** Checkpoint-only recovery (commit `e7f68df`):

- new internal gossip frames `CheckpointRequest` / `CheckpointResponse`
  (`protocol/gossip/src/proto.rs`, tags `0x07` / `0x08`);
- `CHECKPOINT_LAG_ROUNDS = 16` arms a fetch when `decided − accepted` exceeds
  it (`protocol/gossip/src/node.rs`);
- the learner adopts a peer's aggregate only if it commits to **the exact
  payload the node independently produced** (accumulator `signing_bytes`
  equality) and `SignedCheckpoint::verify()` passes, then records it through
  the existing `accept_checkpoint` with the local accumulator's snapshot and
  retained diffs. The learner keeps its own hashgraph; no state or
  retained-graph transfer, so `insert_accepted` is not involved.

Residual: adoption jumps the accepted watermark, so `.rsf` record files for
the skipped rounds are not emitted by that node (other nodes emit them).

---

## 2. The reconnect defect (open)

**Symptom.** A node that is genuinely behind (not just lagging on checkpoint
acceptance) cannot catch up via the reconnect path. `fetch_checkpoint` reaches
a peer and `apply_checkpoint` rejects every response with:

```
reconnect: retained event rejected
  error=retained ancestor_seqs disagree with the present parents' rows
```

**Mechanism.** The reconnect response carries the signed checkpoint, state
bytes, and a "retained graph" of recent events with peer-supplied metadata
(`seq`, `ancestor_seqs`, `round`, `round_received`, timestamp). The learner
refuses to trust that metadata and re-derives it in
`Hashgraph::insert_accepted` (`protocol/consensus/src/hashgraph.rs`). For
`ancestor_seqs` the current rule is:

| parents present | behaviour |
|---|---|
| both | exact equality against the elementwise max of both rows |
| neither | own slot must equal `seq`; the row is otherwise accepted |
| **exactly one** | **exact equality against the present parent's row only** |

When one parent was pruned, the true row is `max(present, pruned)`. If the two
parents are concurrent (neither is the other's ancestor), the pruned parent's
contribution — at minimum its own creator slot — is not present in the
surviving parent's row, so the learner's recomputation is strictly smaller and
the equality check fails. Because the reconnect transfer is a *window* whose
boundary events routinely have one pruned parent, essentially every live
transfer is rejected.

Note the asymmetry: the "neither parent present" branch already accepts a
fully unverifiable row (own slot only), while the "exactly one present" branch
— which has *more* information — is stricter. That branch also has no test
coverage (`hashgraph.rs` tests cover both-present and neither-present only),
which is why the P1-3 audit missed it.

---

## 3. How Hiero avoids this

Upstream reference: `hiero-ledger/hiero-consensus-node` (local checkout at
`/home/curator/HEKA/hiero-consensus-node`, `0.78.0-SNAPSHOT`). This repository
already cites Hedera/Hiero for Merkle domain separation, `records_root`,
`coinFreq`, and fanout caps; the reconnect design is the part we did **not**
follow.

**Hiero's catch-up transfers no events.** Reconnect is `SigSet` (state
signatures) plus a **Merkle state-delta sync**
(`ReconnectStateTeacher`/`ReconnectStateLearner` over
`TeachingSynchronizer`/`LearningSynchronizer`). The learner then **clears its
old DAG**, adopts the signed state at round R, and re-anchors consensus from
`ConsensusSnapshot` (judges + minimum judge birth rounds + next consensus
number) plus the init-judge gate. What is signed is the **Merkle root hash**
(`StateSignatureTransaction{round, signature, hash}` gossiped inside events);
`isComplete()` is >2/3 weight, `isVerifiable()` is >1/2.

**A pruned parent is not an error.** Pruning has two birth-round horizons —
ancient (`roundsNonAncient = 26`, consensus correctness) and expired
(`roundsExpired = 1000`, gossip retention) — both derived from
`minimumJudgeBirthRound`. The orphan buffer *releases* orphans once a missing
parent ages out (`missingParentBecameAncient`), and the linker treats ancient
parents as linkable-without (`getParentToLink`). Nothing recomputes lineage
across the prune boundary.

**Consequence:** there is no analogue of `InvalidRetainedAncestors`, because
Hiero never re-derives per-event ancestry for transferred history — it sends
state instead of a graph.

---

## 4. Why we cannot simply "recover the state"

We already recover state: `apply_checkpoint` does `clear_state()` →
`State::from_bytes(state_bytes)` → `Executor::from_state(...)`, verifying the
bytes rebuild to the committed `state_hash`. The missing pieces are the two
primitives Hiero relies on:

1. **A consensus re-anchor snapshot.** `Hashgraph::from_checkpoint` seeds only
   `fully_decided_rounds` (1..=round), `next_round_to_order`, the roster, and
   `highest_witness_round = checkpoint.round`. There is **no judge /
   `minimumJudgeBirthRound` / `ConsensusSnapshot` concept anywhere** in this
   codebase. With state at round R but no DAG, the node cannot decide round
   R+1: fame needs round-R witnesses, and `insert` treats a missing parent as
   fatal (`MissingParent`) and signals reconnect.
2. **Birth-round ancient window with lenient parent linking.** We hard-error;
   Hiero drops ancient parents and releases orphans.

So the retained graph is load-bearing today, and "state-only reconnect" is a
consensus-core change, not a reconnect tweak.

---

## 5. Stage 1 — validator consistency (next)

Make the one-pruned-parent branch consistent with the already-lenient
zero-parents branch. This is the same move Hiero makes in spirit — do not
demand a re-derivation that is impossible — but stays inside the existing
architecture.

Rule after this change (`Hashgraph::insert_accepted`):

| parents present | behaviour |
|---|---|
| both | exact equality (unchanged; this is the anti-forgery case) |
| exactly one | own slot equals `seq`, **and** no slot is below the present parent's row (elementwise floor) |
| neither | own slot equals `seq` (unchanged) |

- Scope: `protocol/consensus/src/hashgraph.rs` (the `ancestor_seqs` check in
  `insert_accepted`) plus a regression test for the one-pruned-parent case.
- Guarantees: prevents **understatement** (the direction that corrupts
  `see`/`strongly_see`); keeps exact equality wherever it is computable.
- Residual: **overstatement** remains possible for boundary events, exactly as
  the zero-parents branch already permits. Closing that is Stage 2.
- Verification: the reconnect transfer must be accepted end to end; the
  existing `insert_accepted_rejects_forged_ancestor_seqs` (both present) must
  still reject.

**Landed — PLAN-4 Phase A.** The retained window and the roster history are
now committed by the checkpoint itself, so the overstatement residual above is
closed at the window layer rather than by the validator. `signing_bytes` grew
136 → 200 B with `window_root` (a canonical Merkle root over
`window(R, SIGNED_WINDOW_ROUNDS)` derived from decided history) and
`roster_history_root`; `RETENTION_ROUNDS` is coupled to
`SIGNED_WINDOW_ROUNDS = 16` (Phase-0 walk-depth spike); the teacher serves the
canonical roster subset; and the learner recomputes both roots from the
transfer and rejects on mismatch before any live or durable state is touched.
The event log now persists `consensus_timestamp` so a node restored from its
own log derives the same window leaf as its peers.

The `insert_accepted` floor check is deliberately **retained** rather than
retired: restoring exact equality would re-break the one-pruned-parent case,
and removing validation would drop the guard on the trusted log-replay path
that shares the routine. With the window authenticated, the check is a
redundant consistency test, not the trust boundary.

---

## 6. Stage 2 — Hiero-consistent state-only reconnect (proposed)

Eliminate the retained-graph transfer rather than validate it.

1. Extend `CheckpointPayload` with a consensus re-anchor snapshot (judges +
   their birth rounds + next consensus number). Signing bytes change → wire
   format, `.cp`, Go mirror verifier, and shared golden vectors must move
   together; `FORMAT_VERSION` bump.
2. `Hashgraph::from_checkpoint` seeds that snapshot instead of only
   `fully_decided_rounds`.
3. Make `insert` birth-round-windowed and parent-lenient: drop ancient parents
   (linkable-without) and release orphans when a parent ages out.
4. Delete the retained graph from `ReconnectResponse`; `apply_checkpoint`
   becomes state-only; retire `insert_accepted` and its validation.
5. Add the persist-before-contribute gate: do not create events until the
   learned state is durable (ADR-007 / RUL-003 analogue).

Cost: consensus-core plus shared wire format; needs its own written plan and
review before implementation.

---

## References

- `consensus-node/issues.md` — CP-1 resolution and residual items.
- Commits: `e7f68df` (checkpoint-only recovery), `64874ff` (CP-1 write-up).
- Hiero: `platform-sdk/consensus-reconnect-impl`, `platform-sdk/consensus-state`
  (`SignedState`, `DefaultSignedStateValidator`), `platform-sdk/consensus-hashgraph`
  (`ConsensusConfig`, `ConsensusRounds`), `platform-sdk/consensus-utility`
  (`DefaultOrphanBuffer`, `FallBehindStatus`), and the `docs/` ADR/INV set
  (ADR-007, INV-012).
