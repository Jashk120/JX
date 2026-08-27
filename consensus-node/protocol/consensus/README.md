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
  `CheckpointAccumulator` and `RETENTION_ROUNDS` (prune floor, still 2).
  Payload signing bytes are **136 B** domain-separated:
  `round(8 BE)||records_root(32)||state_hash(32)||roster_hash(32)||prev_checkpoint_hash(32)`
  (was 72 B → 104 B in PLAN-1 with `records_root`, then 104 B → 136 B in
  PLAN-2 with `prev_checkpoint_hash`). Quorum is `valid * 3 > total * 2`
  (one-member-one-vote, unit stake). `prev_checkpoint_hash` chains history:
  round `R+1` commits to `SHA256(signing_bytes(R))`, genesis `[0;32]`.
  Also exposes `compute_records_root` / `build_records_proofs` /
  `verify_records_proof` (padded power-of-two Merkle over `RecordsRootItem`
  triples with Hiero prefixes `empty=SHA256(0x00)`, `leaf=SHA256(0x00||...)`,
  `singleton=SHA256(0x01||child)`, `internal=SHA256(0x02||l||r)`).
- `latest_event_by` / `all_event_hashes` / `retained_events` /
  `prune_before_round` / `from_checkpoint` — per-creator frontier accessors
  and lifecycle helpers that the gossip layer and event log use to build sync
  summaries, serve reconnect, and mirror pruning.

## Two Merkle trees (distinct, shared prefixes)

This crate defines the **records Merkle** for `records_root` (over
`RecordsRootItem` = `event_hash||tx_index||tx_payload`, padded to a power of
two, `empty/leaf/internal/singleton` as above) and depends on
`executor/state` for the **state sparse Merkle** over the KV state
(`State::root()` committed as `state_hash`). The two trees are distinct
commitments but share the same Hiero-style domain separation constants, and
the records tree's construction is mirrored byte-for-byte in Go
(`mirror-node/internal/stream/verify.go:ComputeRecordsRoot`), with golden
vectors asserting equality.

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
- `RETENTION_ROUNDS` is unchanged by PLAN-2 (still 2); pruning policy is
  orthogonal to checkpoint chaining.
