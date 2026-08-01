# JKain Consensus Specification
### Hashgraph — Gossip-about-Gossip and Virtual Voting
**Implementation Reference — v0.1**

This document specifies the consensus algorithm precisely enough to implement directly. It separates clearly, throughout, between:

- **[SPEC]** — the formally defined algorithm as established in the original Swirlds technical reports (Baird, 2016), which you should implement as-is, not reinvent
- **[DECISION NEEDED]** — a real engineering choice the original papers leave to the implementer, which you must decide before or during implementation

Primary sources referenced: Swirlds Technical Reports SWIRLDS-TR-2016-01 ("The Swirlds Hashgraph Consensus Algorithm: Fair, Fast, Byzantine Fault Tolerance") and SWIRLDS-TR-2016-02.

---

## 1. Data Model

### 1.1 Event [SPEC]

An **event** is the fundamental unit of the hashgraph. Each event contains:

| Field | Description |
|---|---|
| `creator` | The member (node) that created this event |
| `self_parent` | Hash reference to this creator's own immediately preceding event (null for a member's first-ever event) |
| `other_parent` | Hash reference to the most recent event from the peer this event's gossip came from (null for a member's first-ever event) |
| `timestamp` | Wall-clock time the creator claims to have created this event |
| `payload` | Zero or more transactions this event carries (an event may carry no transactions and exist purely to propagate consensus information) |
| `signature` | The creator's signature over the above fields |
| `hash` | Cryptographic hash of the above fields, used as this event's identifier |

**[DECISION NEEDED]**: exact hash function (SHA-256 is the conventional default; no reason to deviate) and exact serialization format for computing the hash and signature (must be deterministic and canonical — see Section 2.7 of the whitepaper's determinism requirement).

### 1.2 The Hashgraph [SPEC]

The hashgraph itself is the directed acyclic graph (DAG) formed by all events and their parent references, as known to a given member. Each member maintains its own local copy — different members' copies may differ at any instant (some members may not yet have received the latest events from others), but the algorithm guarantees they converge to consistent conclusions about ordering.

### 1.3 Ancestry, "See," and "Strongly See" [SPEC]

- **Ancestor**: event `y` is an ancestor of event `x` if `y` is reachable from `x` by following `self_parent`/`other_parent` references (or `y = x`).
- **See**: event `x` *can see* event `y` if `y` is an ancestor of `x`, **and** the ancestors of `x` do not include a fork by `y`'s creator (i.e., no evidence in `x`'s ancestry that `y`'s creator created two different events with the same self-parent — this is the mechanism that detects and neutralizes equivocation/forking attempts).
- **Strongly see**: event `x` can *strongly see* event `y` if `x` can see `y`, **and** there exists a set of events, created by more than two-thirds (supermajority) of all members, such that `x` can see every event in that set, and every event in that set can see `y`. Informally: information from `y` has propagated widely enough, through enough independent members, that `x` can be confident a supermajority is aware of `y`.

**[DECISION NEEDED]**: efficient computation of ancestry/see/strongly-see is a real algorithmic concern, not just a definition — naive graph traversal on every check is prohibitively slow at scale. Real implementations maintain incremental, cached ancestor-set information per event (e.g., bit-vectors over member indices, updated incrementally as events are added) rather than recomputing full traversals. This caching strategy is left to you to design and is one of the more performance-critical pieces of the whole system.

---

## 2. Round Assignment [SPEC]

Every event is assigned a **round number** as it is added to the hashgraph:

```
procedure divideRounds(x):
    r = max(round of x.self_parent, round of x.other_parent)  # or 1 if x has no parents
    if x can strongly see more than 2n/3 witnesses of round r:
        x.round = r + 1
    else:
        x.round = r
```

Where `n` is the total number of members (nodes) participating in consensus.

### 2.1 Witness [SPEC]

An event `x` is a **witness** if it is the first event created by its creator in its round — i.e., `x.round > round(x.self_parent)`, or `x` is a member's very first event.

---

## 3. Virtual Voting — Determining Fame [SPEC]

The purpose of this phase is to determine, for each witness, whether it is **famous**. Famous witnesses of a round are what allow the algorithm to finalize the ordering of all earlier events. This is computed **without any votes actually being sent over the network** — every member computes every other member's hypothetical votes locally, purely by inspecting their own copy of the hashgraph, since a member's ancestry fully determines what that member "would" vote.

### 3.1 Election Procedure [SPEC]

For a witness `w` created in round `r`, its fame is decided via an election carried out by witnesses of later rounds:

```
procedure decideFame(w):
    for each round r' > r, in increasing order:
        for each witness y created in round r':
            if r' == r + 1:
                y's vote = "true" if y can see w, else "false"
            else:
                # y strongly sees a set S of round-(r'-1) witnesses
                let v = majority vote among votes of witnesses in S (as seen by y)
                let stake = count of witnesses in S whose vote agrees with v

                if r' - r is a multiple of a "coin round frequency" constant (e.g. every 10 rounds)
                    and no clear supermajority exists:
                        y's vote = middle bit of y's signature   # pseudo-random fallback, breaks ties/deadlock
                elif stake > 2n/3:
                    w is decided: FAMOUS if v == "true", NOT FAMOUS if v == "false"
                    stop — fame of w is finalized
                else:
                    y's vote = v   # continue voting into the next round
```

**[SPEC, exact mechanism from the source material]**: a witness in round `r+1` votes `true` if it can see `w` directly. From round `r+2` onward, a witness's vote is the majority opinion among the round-below witnesses it strongly sees; if more than two-thirds of those strongly-seen witnesses agree, that supermajority opinion becomes the final, irreversible decision on `w`'s fame. The original papers additionally specify an occasional pseudo-random "coin round" (voting on a pseudo-random bit derived from a signature, rather than majority) at a periodic interval, to guarantee the election eventually terminates even under adversarial conditions that might otherwise stall a pure-majority vote indefinitely.

**[DECISION NEEDED]**: the exact coin-round frequency constant, and the exact source of the pseudo-random bit (the original design uses the middle bit of the witness's cryptographic signature — deterministic, unpredictable in advance, and requires no extra communication). Also needed: how far back in round history your implementation is willing to search before invoking a coin round, which is a tuning parameter, not a correctness requirement.

### 3.2 Forking [SPEC]

If a member is detected to have forked (created two different events with the same self-parent — equivocation), at most one of any resulting "famous witnesses" in the same round arising from that fork is used going forward; the rest are discarded. Fork detection is implicit in the "see" definition (Section 1.3) — an event that can see evidence of a fork cannot "see" the forked events cleanly.

---

## 4. Finalizing Order — Received Round and Consensus Timestamp [SPEC]

Once **all** witnesses of a round `r` have had their fame decided, the round is "decided," and every not-yet-ordered event whose ancestry is now fully resolved by that round can be assigned:

```
procedure assignOrder(x):
    x.roundReceived = the first round r such that all famous witnesses of round r
                       can see (or are descendants of) x
    x.consensusTimestamp = median of the timestamps that each famous witness of
                            round x.roundReceived first received x (i.e., the
                            timestamp of the earliest event, in each famous
                            witness's ancestry, that can see x)
```

Final total ordering of all events (and thus their contained transactions) is:

1. Primary sort key: `roundReceived` (ascending)
2. Tie-break: `consensusTimestamp` (the median-derived timestamp above, ascending)
3. Further tie-break (rare, for exact timestamp ties): **[DECISION NEEDED]** — the original papers suggest using a signature-derived value (e.g., whitened/hashed signature bits) as a final, deterministic tie-breaker so that all honest members compute an identical order even in this edge case. Choose and document a specific method (e.g., XOR of all witness signatures for that event, or similar) — the specific choice doesn't matter for correctness, only that all nodes apply the same deterministic rule.

This order, once determined, is **final** — this is what gives hashgraph its deterministic (non-probabilistic) finality property described in the whitepaper (Section 2.1).

---

## 5. Gossip Protocol [SPEC + DECISION NEEDED]

**[SPEC]** — the high-level gossip mechanism ("gossip about gossip"):

1. A member periodically selects another member at random (a "sync").
2. The two members exchange all events each has that the other does not yet have, determined by comparing what each knows about the other's most recent events.
3. Each member, upon receiving new events, creates a new event of its own (an "other_parent" pointing to the last event received from the sync partner, "self_parent" pointing to its own prior event), which itself gets gossiped onward in future syncs.

This is what causes information (including the fact that gossip itself occurred) to propagate exponentially through the network, giving the algorithm its speed and its property that events themselves encode a verifiable history of who-knew-what-when.

**[DECISION NEEDED — real engineering, not covered precisely by the original papers]**:
- **Peer selection strategy** for choosing sync partners (uniform random is the simplest correct starting point; production systems sometimes weight this, which is an optimization, not a correctness requirement).
- **Sync frequency / interval** — a tuning parameter directly trading off gossip speed against network bandwidth.
- **Wire protocol for a sync exchange** — the original papers describe *what* information needs to be exchanged (events each side lacks), not the exact bytes-on-the-wire format. This is where Section 2.2 of the whitepaper's transport decision (raw TCP, custom binary framing) becomes concrete: you need to design the actual sync request/response message format.
- **Efficient "what does the other side already have" determination** — naively this requires knowing the full state of the other member's hashgraph; real implementations use compact summaries (e.g., each member's latest known event hash per creator) to determine the delta efficiently, rather than exchanging full hashgraphs each sync.

---

## 6. Signature Verification and Transaction Validity [DECISION NEEDED — connects to whitepaper Section 2.4]

The consensus algorithm above determines *ordering*, not transaction *validity*. Once an event's contained transactions are finally ordered (Section 4), each node executes them against its local state (Section 2.7 of the whitepaper), checking:

- Signature validity against the transaction's `AuthorizerSet` (Section 2.4/2.5 — single-signer or threshold, resolved against current account state, not re-derived independently per Section 7.3.1's defer-to-L1 principle for compute nodes specifically)
- Nonce/replay validity
- Sufficient balance/state preconditions for the specific operation

This execution step must be strictly deterministic (whitepaper Section 2.7) — the consensus algorithm above guarantees all honest nodes agree on *order*; determinism in execution is what additionally guarantees they agree on *resulting state*. These are separate guarantees and both are required.

---

## 7. Suggested Implementation Order

Given the dependencies above, a workable build sequence:

1. **Event and hashgraph data structures** (Section 1) — including the ancestor/see/strongly-see caching strategy, since this underlies everything else and is worth getting right early rather than retrofitting.
2. **Round assignment** (Section 2) — depends only on Section 1.
3. **Gossip/sync protocol** (Section 5) — can be built and tested independently of virtual voting; you can verify events propagate correctly across nodes before consensus decisions are layered on top. This is also your natural point to attempt the "4 VPS gossiping" milestone.
4. **Virtual voting / fame decision** (Section 3) — the most algorithmically intricate part; consider building and testing this against a small, fixed, simulated hashgraph (constructed by hand or scripted, not from live gossip) before wiring it to real network gossip, so you can verify correctness against known expected outcomes independently of network timing issues.
5. **Order finalization** (Section 4) — depends on 3.
6. **Transaction execution / state transition** (Section 6) — can be developed in parallel with 3–5, since it only needs a finalized ordering as input, not the internals of how that ordering was produced.

---

## 8. Testing Strategy Notes

- **Deterministic replay tests**: given a fixed, hand-constructed or logged sequence of events (not live network gossip), the fame-decision and ordering logic (Sections 3–4) should produce an identical, reproducible result every run — this is the cleanest way to unit-test the algorithmic core without network non-determinism in the loop.
- **Partition/rejoin tests**: simulate a subset of nodes losing connectivity, then rejoining — verify the gossip protocol (Section 5) correctly reconciles and consensus proceeds correctly afterward.
- **Fork/equivocation tests**: deliberately construct a simulated member that creates two conflicting events with the same self-parent, and verify the "see" definition's fork-detection (Section 1.3, Section 3.2) correctly neutralizes it.
- **Byzantine minority tests**: simulate up to (but not exceeding) the tolerated fraction of adversarial/faulty members and verify consensus still converges correctly among the honest majority — this is the direct test of the "asynchronous Byzantine fault tolerant" claim underlying the whole system.
