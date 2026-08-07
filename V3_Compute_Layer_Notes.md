# V3 Compute Layer — Design Exploration Notes
**Status: unresolved exploration, not a specification. Do not build against this without re-deriving/re-deciding the open items below.**

This document captures a design discussion that went deeper than the whitepaper's Section 6 on specific mechanisms. Per Section 6.10's own stated intent, none of this is meant to be locked in or reserved as interface ahead of v1–v3 actually existing. It's recorded here, separately from the whitepaper, so today's reasoning isn't lost — and so it doesn't get mistaken for settled design.

---

## 1. Core framing (the one piece worth keeping)

**A DID functions like OAuth for actors** — a single portable identity primitive that authenticates a user across every application built on the compute layer, the same way OAuth lets one identity provider authenticate a user across many unrelated apps. The difference: OAuth authenticates access to data held by a third party; here, the DID anchors both the user's identity *and* the actual compute/state itself, so there's no third party holding the data in the first place.

This is the sharpest, most defensible idea from today's discussion and is a reasonable candidate to fold into the whitepaper's Section 6.1/6.2 as a framing sentence, independent of everything else below.

## 2. Developer/runtime division of labor (clarification of existing 6.2/6.5, not new)

Verbal description from today: developers write application-specific logic only (e.g., for a chat app: friends list, message handling). The runtime handles routing, discovery, and delivery of messages to wherever the actor currently lives.

This is consistent with 6.2 and 6.5 as written but is more concretely stated here than in the whitepaper itself. Reasonable to tighten 6.2's language to make this boundary explicit, since the whitepaper currently implies but doesn't state it this cleanly.

**Not resolved:** the exact interface boundary — what the runtime guarantees to deliver to an actor vs. what the actor must handle itself (e.g., does the runtime guarantee delivery order, at-least-once vs exactly-once delivery, etc.) was not discussed and remains open.

## 3. DID-to-location resolution — outer shape only

Confirmed today: the DID itself is opaque and permanent (per 6.2's existing principle). A **separate on-chain mapping** resolves DID → current location, expressed as a path-like structure: `region / compute_node_name / storage_location`.

This is consistent with 6.4's existing "DID-to-current-actor-location mapping," just with a concrete path shape proposed for the value.

**Open, not resolved:**
- Whether `storage_location` needs to be part of the on-chain-resolvable path, or whether the compute node should own that lookup internally once a connection reaches it (leaning toward the latter, per 6.3.1's boundary principle, but not decided).
- Whether the path is fully re-resolved on every connection (treat as ephemeral, DNS-lease-style) or has some other caching/staleness contract. Leaning ephemeral, not decided.

## 4. Replication and migration — the least resolved part

Today's discussion, in order, and where each thread was left:

- Confirmed: **2–3 replicas per actor**, tracked via the on-chain index (extends 6.4's "small set of reachable locations," now with a number attached — not previously specified in the whitepaper).
- Confirmed: **active-passive, not active-active.** Only one replica is live (accepting requests) at a time; others are passive backups. This resolves the state-divergence question — single-writer means no concurrent-write conflicts to reconcile.
- **This directly contradicts 6.4's current text**, which offers "last-write-wins or vector clocks" as reconciliation — those mechanisms are for multi-writer conflicts, which no longer apply under confirmed active-passive. **6.4 needs correcting, not extending**, if this direction is later confirmed — the current whitepaper text describes a harder problem than what was actually decided today.
- Migration mechanism discussed: rather than a clean handoff, the old node keeps a **redirect/forwarding pointer** after migration, so callers with a stale resolution still reach the actor.
  - **Open, not resolved:** how long the redirect is retained. Flagged as a real tradeoff — indefinite retention reintroduces unbounded state growth on compute nodes (same shape as the ledger's own state-growth problem, Section 2.6/8); an expiring redirect means callers must be able to fall back to re-resolving DID→location from chain on failure, i.e., the redirect can only be a latency optimization, not a correctness guarantee. No decision was made on which.
- Failover mechanism discussed: if the active replica becomes unreachable, a passive replica is promoted.
  - **Open, not resolved — the most important unresolved item:** how promotion is agreed upon without risking split-brain (a network partition causing two replicas to both believe they should promote, temporarily reintroducing the exact dual-writer problem active-passive was chosen to avoid). Discussed direction: route promotion decisions through the on-chain index itself, requiring some quorum of replicas (e.g. 2-of-3) to agree the active is unreachable before the index updates the current-active pointer — analogous in shape to how `roundReceived` requires all famous witnesses to agree rather than trusting a single observer, applied one layer up, outside of consensus proper. **This was never confirmed as the actual design, only raised as a plausible direction.**

## 5. What this means for the whitepaper right now

Recommended action: **none, beyond the one-line OAuth framing in item 1.** Everything in items 3 and 4 is either underspecified (item 3) or actively contradicts existing whitepaper text without a confirmed replacement (item 4's redirect/failover questions, and the last-write-wins language in 6.4 that no longer matches the active-passive decision). Writing this into the whitepaper as settled would misrepresent open questions as resolved architecture — worth avoiding, especially since 6.10 already commits to not doing exactly that.

If/when these get re-derived and actually resolved (most likely once v1 is built and something like this becomes concretely necessary), revisit 6.4 specifically — it's the section most out of date relative to today's discussion.

---
*Generated from a design conversation on 2026-08-06. Not reviewed against the primary Swirlds/Hedera source material or tested against any implementation. Treat as scratch notes, not a spec.*
