# consensus

Virtual-voting hashgraph consensus for JKain.

Implements the Hashgraph consensus algorithm described in
`docs/JKain_Consensus_Spec.md`: an in-memory `Hashgraph` that stores verified
events and derives ordering through round assignment, virtual voting, and
order finalization. Depends on `primitives` for the value types and
`crypto` for hashing, signatures, and membership.

## Contents

- `Hashgraph` — the graph store. Inserts verified events (rejecting
  duplicates, missing parents, and unknown creators), maintains
  incremental per-member ancestor metadata, and tracks each event's
  `FameStatus` (`Undecided` / `Famous` / `NotFamous`).
- `ancestry` — graph traversal: `see`, `strongly_see`, and fork detection
  (observer-relative `see` checks with a first-seen branch policy).
- `round` — round assignment (`base_round` from parent rounds, witness
  detection, `2n/3` threshold).
- `fame` — virtual voting: the `decideFame(w)` election, run eagerly and
  incrementally as a side effect of insertion, with memoized on-demand
  votes and backfill so late-arriving witnesses still resolve.
- `order` — order finalization: `roundReceived`, `consensusTimestamp`, and
  the final total order (sorted by round, then timestamp, then a
  signature-derived tie-break).
- `reconnect` — wire codecs for `SignedCheckpoint`, `RosterHistory`, and the
  `RetainedEvent` record (event + record metadata) shared by the reconnect
  protocol and the Phase 8 durable event log.
- `checkpoint` — `SignedCheckpoint` / `CheckpointPayload` / `CheckpointSig` /
  `CheckpointAccumulator` and `RETENTION_ROUNDS` (prune floor). Payload
  signing bytes are domain-separated; quorum is `valid * 3 > total * 2`.
- `latest_event_by` / `all_event_hashes` / `retained_events` /
  `prune_before_round` / `from_checkpoint` — per-creator frontier accessors
  and lifecycle helpers that the gossip layer and event log use to build sync
  summaries, serve reconnect, and mirror pruning.

## Design

- One-member-one-vote (no stake), using the `* 3 > * 2` integer idiom to
  avoid float rounding in supermajority checks.
- Fork deduplication to a canonical branch is deliberately deferred: it
  requires finalized order, which is what this crate produces.
- Dynamic membership is implemented: `MembershipOp::Add` orders through
  consensus and activates via `RosterHistory` one round after
  `roundReceived` (see `protocol/gossip/src/node.rs` activation). The
  membership registry for a `Hashgraph` is still snapshot-scoped; execution
  (KV + DID) lives in `executor/state`, not here.
