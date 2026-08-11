use std::collections::{
    BTreeSet,
    HashMap,
};

use crypto::{
    Hashable,
    MembershipRegistry,
    RosterHistory,
    VerifiedEvent,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
    Timestamp,
};

use crate::checkpoint::CheckpointPayload;
use crate::error::{
    ConsensusError,
    Result,
};

/// Consensus Spec §3 — the fame decision for a witness event.
///
/// Three states, deliberately distinct from `Option<bool>`: a *non-witness*
/// never has a meaningful decision, a *witness* starts `Undecided`, and only
/// once the virtual-voting election for it terminates does it become
/// `Famous` or `NotFamous`. Distinguishing "not a witness" from "witness,
/// undecided" this way is what lets tests (and §4's ordering task) tell
/// them apart at a glance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FameStatus {
    Undecided,
    Famous,
    NotFamous,
}

/// A stored event plus the incremental bookkeeping needed for ancestry
/// queries (Consensus Spec §1.3), computed once at insertion time so
/// `see`/`strongly_see` never re-traverse the graph on the fast path.
#[derive(Clone, Debug)]
pub struct EventRecord {
    event: Event,
    seq: u64,
    /// Indexed by member index (see `Hashgraph::member_index`). Slot `i`
    /// holds the highest sequence number, among this event's ancestors,
    /// created by member `i` — 0 means "no ancestor from that member".
    ancestor_seqs: Vec<u64>,
    /// Consensus Spec §2 — computed once at insertion time (`round.rs`),
    /// mutated in place immediately after this record is first stored
    /// (see `Hashgraph::insert`), never touched again afterward.
    round: u64,
    /// Consensus Spec §2.1 — true iff this is the first event created by
    /// its creator in `round`.
    is_witness: bool,
    /// Consensus Spec §3 — votes this event cast on candidate witnesses,
    /// keyed by candidate hash. Meaningful only when `is_witness()`;
    /// non-witnesses simply keep an empty map (deliberately *not*
    /// special-cased in the type — see `fame.rs`'s module doc on why a
    /// plain map is preferred over Hedera's dense `bool[]`).
    votes: HashMap<EventHash, bool>,
    /// Consensus Spec §3 — this event's fame decision. Only meaningful for
    /// witnesses; non-witnesses keep `Undecided` forever.
    fame_status: FameStatus,
    /// Consensus Spec §4 — the first round whose famous witnesses all see
    /// this event, once that round has been decided (see `order.rs`).
    /// `None` until then; never reassigned afterward (ordering is final).
    round_received: Option<u64>,
    /// Consensus Spec §4 — median of the timestamps at which the famous
    /// witnesses of `round_received` first received this event. `None`
    /// until `round_received` is assigned.
    consensus_timestamp: Option<Timestamp>,
}

impl EventRecord {
    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn ancestor_seq(&self, member_idx: usize) -> u64 {
        self.ancestor_seqs[member_idx]
    }

    /// The width of the `ancestor_seqs` row — the number of members the
    /// event's hashgraph was operating under when it was stored. Pre-join
    /// events are backfilled to the current width by `add_member`.
    pub fn ancestor_seqs_len(&self) -> usize {
        self.ancestor_seqs.len()
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn is_witness(&self) -> bool {
        self.is_witness
    }

    /// Consensus Spec §3 — this event's fame decision (meaningful only for
    /// witnesses).
    pub fn fame(&self) -> FameStatus {
        self.fame_status
    }

    /// Consensus Spec §3 — this witness's recorded vote on candidate `w`,
    /// if one has been computed and cached. `None` also covers the
    /// "not yet voted" case.
    pub(crate) fn vote_for(&self, w: &EventHash) -> Option<bool> {
        self.votes.get(w).copied()
    }

    /// Consensus Spec §4 — this event's finalized `roundReceived`, if it has
    /// been ordered.
    pub fn round_received(&self) -> Option<u64> {
        self.round_received
    }

    /// Consensus Spec §4 — this event's finalized `consensusTimestamp`, if
    /// it has been ordered.
    pub fn consensus_timestamp(&self) -> Option<Timestamp> {
        self.consensus_timestamp
    }

    /// Consensus Spec §4 — marks this event as ordered. Only ever called
    /// from `order.rs`'s `assign_order`, exactly once per event.
    pub(crate) fn set_order(&mut self, round_received: u64, consensus_timestamp: Timestamp) {
        self.round_received = Some(round_received);
        self.consensus_timestamp = Some(consensus_timestamp);
    }
}

pub type InsertError = ConsensusError;

/// This node's local copy of the hashgraph (Consensus Spec §1.2).
/// Storage plus the ancestry caching strategy from §1.3's
/// `[DECISION NEEDED]` note.
#[derive(Debug)]
pub struct Hashgraph {
    events: HashMap<EventHash, EventRecord>,
    children: HashMap<EventHash, Vec<EventHash>>,
    /// First-seen (creator, self_parent) -> event hash. A second, different
    /// hash arriving under the same key is direct evidence of a fork
    /// (Consensus Spec §3.2) and flips that creator's bit in
    /// `known_forkers`. Kept as first-seen deliberately: the spec says at
    /// most one branch from a forking creator is used going forward, so
    /// treating the first-registered branch as canonical is spec-consistent,
    /// not just a convenience.
    first_child: HashMap<(NodeId, Option<EventHash>), EventHash>,
    /// First-seen (creator, seq) -> event hash. Lets `strongly_see` walk a
    /// single creator's chain by sequence number without a graph
    /// traversal. Same first-seen-wins policy as `first_child`, for the
    /// same reason.
    by_creator_seq: HashMap<(NodeId, u64), EventHash>,
    /// Newest stored event per creator, tracked incrementally so the gossip
    /// layer can build per-creator "what's my latest" summaries in O(1)
    /// (Consensus Spec §5). Overwritten only when the new event's seq
    /// exceeds the current entry's, so a straggling lower-seq branch never
    /// clobbers the frontier.
    latest_by_creator: HashMap<NodeId, EventHash>,
    member_index: HashMap<NodeId, usize>,
    member_count: usize,
    /// Round-indexed membership snapshots (Phase 2). Every quorum computation
    /// reads the roster active at the *event's birth round* via
    /// [`Hashgraph::member_count_at_round`], not the scalar `member_count`
    /// field — the scalar is only the live width of the frozen structures
    /// (`member_index`, `known_forkers`, `ancestor_seqs`).
    roster_history: RosterHistory,
    /// Node-global, not observer-relative: "has this local hashgraph copy
    /// ever seen evidence this member forked, anywhere." This is only a
    /// routing hint for `see`'s fast/slow path split — the actual
    /// observer-relative correctness lives in
    /// `ancestry::Hashgraph::ancestry_contains_fork_of`.
    known_forkers: Vec<bool>,
    /// Consensus Spec §2.1 — witness events, indexed by round. Maintained
    /// incrementally as events are inserted, so `round.rs`'s
    /// strongly-see-a-supermajority-of-round-r-witnesses check
    /// (`divideRounds`) never has to scan the whole graph for them.
    witnesses_by_round: HashMap<u64, Vec<EventHash>>,
    /// Consensus Spec §3 — witnesses whose fame is still undecided, keyed
    /// by their round. Maintained incrementally (`record_witness` adds,
    /// `decide_fame` removes), so the fame-voting step (`fame.rs`) only
    /// ever considers witnesses that are still live elections, never
    /// rescanning the full graph.
    undecided_witnesses: HashMap<EventHash, u64>,
    /// Max key of `witnesses_by_round`, cached so a late-arriving candidate
    /// witness (fame.rs's backfill step) knows how far forward to look.
    highest_witness_round: u64,
    /// Consensus Spec §4 — every round whose witnesses all have a final,
    /// non-`Undecided` fame decision. When a new round joins this set,
    /// `order.rs` finalizes it and any earlier decided-but-unprocessed
    /// rounds (rounds are finalized in strictly increasing order).
    fully_decided_rounds: BTreeSet<u64>,
    /// Consensus Spec §4 — the lowest round whose `assignOrder` has not run
    /// yet. Rounds are finalized in strictly increasing order.
    next_round_to_order: u64,
}

impl Hashgraph {
    pub fn new(registry: &MembershipRegistry) -> Self {
        let member_ids = registry.member_ids();
        let member_count = member_ids.len();
        let member_index = member_ids.into_iter().zip(0..).collect();

        Self {
            events: HashMap::new(),
            children: HashMap::new(),
            first_child: HashMap::new(),
            by_creator_seq: HashMap::new(),
            latest_by_creator: HashMap::new(),
            member_index,
            member_count,
            roster_history: RosterHistory::new(registry.clone()),
            known_forkers: vec![false; member_count],
            witnesses_by_round: HashMap::new(),
            undecided_witnesses: HashMap::new(),
            highest_witness_round: 0,
            fully_decided_rounds: BTreeSet::new(),
            next_round_to_order: 1,
        }
    }

    pub fn insert(&mut self, verified: VerifiedEvent) -> Result<EventHash> {
        let event = verified.into_inner();
        let hash = event.hash();

        if self.events.contains_key(&hash) {
            return Err(InsertError::AlreadyPresent(hash));
        }

        let creator = *event.creator();
        let creator_idx = *self.member_index.get(&creator).ok_or(InsertError::UnknownCreator)?;

        let self_parent_record = match event.self_parent() {
            Some(h) => Some(self.events.get(h).ok_or(InsertError::MissingParent(*h))?),
            None => None,
        };
        let other_parent_record = match event.other_parent() {
            Some(h) => Some(self.events.get(h).ok_or(InsertError::MissingParent(*h))?),
            None => None,
        };

        let seq = self_parent_record.map_or(1, |r| r.seq + 1);

        // Incremental ancestor_seqs: elementwise max of both parents',
        // then bump in this event's own creator/seq. No re-traversal.
        let mut ancestor_seqs = vec![0u64; self.member_count];
        if let Some(r) = self_parent_record {
            ancestor_seqs.copy_from_slice(&r.ancestor_seqs);
        }
        if let Some(r) = other_parent_record {
            for (slot, &v) in ancestor_seqs.iter_mut().zip(r.ancestor_seqs.iter()) {
                *slot = (*slot).max(v);
            }
        }
        ancestor_seqs[creator_idx] = seq;

        // Branch detection (Consensus Spec §3.2 / §1.3).
        let branch_key = (creator, event.self_parent().copied());
        match self.first_child.get(&branch_key) {
            Some(existing) if *existing != hash => {
                self.known_forkers[creator_idx] = true;
            }
            _ => {
                self.first_child.entry(branch_key).or_insert(hash);
            }
        }
        self.by_creator_seq.entry((creator, seq)).or_insert(hash);

        match self.latest_by_creator.get(&creator) {
            Some(latest) => {
                let latest_seq = self.events.get(latest).map_or(0, |r| r.seq);
                if seq > latest_seq {
                    self.latest_by_creator.insert(creator, hash);
                }
            }
            None => {
                self.latest_by_creator.insert(creator, hash);
            }
        }

        for parent in [event.self_parent(), event.other_parent()].into_iter().flatten() {
            self.children.entry(*parent).or_default().push(hash);
        }

        let self_parent_round = self_parent_record.map(EventRecord::round);
        let other_parent_round = other_parent_record.map(EventRecord::round);
        let base_round = crate::round::base_round(self_parent_round, other_parent_round);

        // Stored with a provisional round so `finalize_round` (round.rs)
        // can query this event's own ancestor_seqs via `strongly_see`,
        // which needs the record to already be present. Mutated in place
        // immediately below — never read in this provisional state.
        self.events.insert(
            hash,
            EventRecord {
                event,
                seq,
                ancestor_seqs,
                round: base_round,
                is_witness: false,
                votes: HashMap::new(),
                fame_status: FameStatus::Undecided,
                round_received: None,
                consensus_timestamp: None,
            },
        );

        self.finalize_round(hash, base_round, self_parent_round)?;

        if self.get(&hash).is_some_and(EventRecord::is_witness) {
            self.vote_as_witness(hash)?;
        }

        Ok(hash)
    }

    pub fn get(&self, hash: &EventHash) -> Option<&EventRecord> {
        self.events.get(hash)
    }

    /// Consensus Spec §5 — the newest stored event created by `node`, if
    /// any. Maintained incrementally by `insert`, so the gossip layer can
    /// build per-creator frontier summaries without scanning the graph.
    pub fn latest_event_by(&self, node: &NodeId) -> Option<&EventHash> {
        self.latest_by_creator.get(node)
    }

    pub fn children(&self, hash: &EventHash) -> &[EventHash] {
        self.children.get(hash).map_or(&[], Vec::as_slice)
    }

    /// Crate-internal (§4): every event that has not yet been assigned a
    /// `roundReceived`, as owned hashes so the caller can mutate the graph
    /// afterward without holding a borrow over the event map.
    pub(crate) fn pending_order_events(&self) -> Vec<EventHash> {
        self.events
            .iter()
            .filter(|(_, record)| record.round_received().is_none())
            .map(|(&hash, _)| hash)
            .collect()
    }

    /// Every stored event hash. Used by `consensus_order` to look up an
    /// already-finalized round's events, and by the gossip integration
    /// tests to compare node views for convergence.
    pub fn all_event_hashes(&self) -> Vec<EventHash> {
        self.events.keys().copied().collect()
    }

    /// Crate-internal (§4): applies a `roundReceived` / `consensusTimestamp`
    /// assignment to an event, for `order.rs`'s `assign_order`.
    pub(crate) fn set_event_order(&mut self, hash: &EventHash, round: u64, timestamp: Timestamp) {
        if let Some(record) = self.events.get_mut(hash) {
            record.set_order(round, timestamp);
        }
    }

    /// Test-only: force a witness's fame status directly, bypassing the
    /// election machinery. Used by `order.rs`'s fork-dedup test to construct
    /// the "two Famous witnesses from one forking creator" edge case that the
    /// game cannot produce naturally (§3.2). Deliberately *does not* touch
    /// the undecided working set, so it cannot fire `assignOrder`.
    #[cfg(test)]
    pub(crate) fn mark_for_test_famous(&mut self, hash: &EventHash) {
        if let Some(record) = self.events.get_mut(hash) {
            record.fame_status = FameStatus::Famous;
        }
    }

    /// Consensus Spec §2.1 — witnesses of `round`, i.e. every event that
    /// was the first created by its creator in that round. Empty slice if
    /// `round` hasn't been reached yet (or has no witnesses recorded).
    pub fn witnesses_of_round(&self, round: u64) -> &[EventHash] {
        self.witnesses_by_round.get(&round).map_or(&[], Vec::as_slice)
    }

    /// Crate-internal: records `hash` as a witness of `round`. Only ever
    /// called from `round.rs`'s `finalize_round`, immediately after an
    /// event's final round is decided. Also enrolls the witness as a live,
    /// undecided fame election (§3).
    pub(crate) fn record_witness(&mut self, round: u64, hash: EventHash) {
        self.witnesses_by_round.entry(round).or_default().push(hash);
        self.undecided_witnesses.insert(hash, round);
        self.highest_witness_round = self.highest_witness_round.max(round);
    }

    /// Crate-internal: caches witness `voter`'s vote on candidate witness
    /// `candidate` (Consensus Spec §3). Only ever called from `fame.rs`.
    pub(crate) fn record_vote(&mut self, voter: &EventHash, candidate: &EventHash, vote: bool) {
        if let Some(record) = self.events.get_mut(voter) {
            record.votes.insert(*candidate, vote);
        }
    }

    /// Crate-internal: finalizes `candidate`'s fame election and removes it
    /// from the undecided working set. Only ever called from `fame.rs`.
    /// Decisions are immutable: nothing in the codebase calls this twice.
    ///
    /// If `candidate`'s round has now no undecided witnesses left, every
    /// witness of that round has a final fame decision — the round is
    /// "decided" and `order.rs` may finalize it (§4).
    pub(crate) fn decide_fame(&mut self, candidate: &EventHash, status: FameStatus) {
        if let Some(record) = self.events.get_mut(candidate) {
            record.fame_status = status;
        }
        self.undecided_witnesses.remove(candidate);
        let round = self.events.get(candidate).map_or(0, |record| record.round());
        self.note_round_decided_if_complete(round);
    }

    /// Crate-internal (§4): if `round` still has undecided witnesses it is
    /// not decided; otherwise it joins the decided set and every round that
    /// can now be finalized is finalized in order. Hooked from
    /// `decide_fame`, so it fires at whatever recursion depth a fame
    /// decision was actually produced — not just for the round of whatever
    /// witness triggered the election.
    pub(crate) fn note_round_decided_if_complete(&mut self, round: u64) {
        if round == 0 {
            return;
        }
        if self.undecided_witnesses.values().any(|&witness_round| witness_round == round) {
            return;
        }
        self.fully_decided_rounds.insert(round);
        self.order_decided_rounds();
    }

    /// Crate-internal (§4): finalizes every round that is safe to finalize.
    ///
    /// A round `r` is finalizable as soon as it is decided: at that point
    /// every witness of `r` has a final, immutable fame decision, so round
    /// `r`'s famous-witness set is final and `assignOrder(r)` can be run.
    /// Rounds are processed in strictly increasing order, each exactly once
    /// — `next_round_to_order` advances past a round only after it has been
    /// decided.
    pub(crate) fn order_decided_rounds(&mut self) {
        while self.fully_decided_rounds.contains(&self.next_round_to_order) {
            let round = self.next_round_to_order;
            self.next_round_to_order += 1;
            self.assign_order(round);
        }
    }

    /// Consensus Spec §3 — the fame decision for a witness, if one exists.
    /// Returns `None` for an unknown event *or* a non-witness (distinguish
    /// with `get()`/`is_witness()`), `Some(FameStatus::Undecided)` for a
    /// witness whose election has not terminated yet.
    pub fn fame_of(&self, witness: &EventHash) -> Option<FameStatus> {
        let record = self.events.get(witness)?;
        if !record.is_witness {
            return None;
        }
        Some(record.fame_status)
    }

    /// Crate-internal: the undecided-fame working set, keyed by witness
    /// hash with its round. Read by `fame.rs`'s per-insert voting step.
    pub(crate) fn undecided_witnesses(&self) -> &HashMap<EventHash, u64> {
        &self.undecided_witnesses
    }

    /// Crate-internal: highest witness round recorded so far.
    pub(crate) fn highest_witness_round(&self) -> u64 {
        self.highest_witness_round
    }

    /// Crate-internal: overwrites the provisional round/witness status a
    /// freshly inserted event was stored with. Only ever called from
    /// `round.rs`'s `finalize_round`, exactly once per event, immediately
    /// after insertion.
    pub(crate) fn set_event_round(&mut self, hash: &EventHash, round: u64, is_witness: bool) {
        if let Some(record) = self.events.get_mut(hash) {
            record.round = round;
            record.is_witness = is_witness;
        }
    }

    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Extends the hashgraph to include `node` as a new member. The supplied
    /// `new_registry` becomes active for quorum computations from round
    /// `activation_round + 1` onward; every round at or below
    /// `activation_round` keeps its existing roster, so no decided round's
    /// fame is ever recomputed under a changed denominator.
    ///
    /// Grows the four co-indexed structures atomically:
    /// - `member_index`: assigns the next slot index.
    /// - `member_count`: increments by 1 (the live width of the frozen
    ///   structures — new inserts immediately size `ancestor_seqs` and index
    ///   `known_forkers` for the new member).
    /// - `known_forkers`: appends `false` (no fork evidence yet).
    /// - `ancestor_seqs` on every stored `EventRecord`: appends `0`.
    ///
    /// The `0` backfill is correct: the new node created nothing before its
    /// activation round, so `ancestor_seqs[new_idx] == 0` on pre-join events
    /// is the accurate "no ancestor from this member" sentinel. Every site
    /// that reads `ancestor_seqs[idx]` already guards `if up_to == 0 {
    /// continue }`, so no special-casing is needed in `ancestry.rs`,
    /// `fame.rs`, or `order.rs`.
    ///
    /// The `roster_history.schedule(activation_round + 1, new_registry)` call
    /// is part of this method — not a separate call — so the structural
    /// extension and the quorum-denominator update are always applied
    /// together. Splitting them would leave the hashgraph in an inconsistent
    /// state if one succeeded and the other did not.
    ///
    /// # Panics
    /// Panics if `node` is already a registered member.
    pub fn add_member(
        &mut self,
        node: NodeId,
        activation_round: u64,
        new_registry: MembershipRegistry,
    ) {
        assert!(
            !self.member_index.contains_key(&node),
            "add_member called for already-registered node {node:?}"
        );

        let idx = self.member_count;
        self.member_index.insert(node, idx);
        self.member_count += 1;
        self.known_forkers.push(false);

        for record in self.events.values_mut() {
            record.ancestor_seqs.push(0);
        }

        // Atomic with structural growth: schedule the new registry one round
        // after `activation_round`, so events born at or below
        // `activation_round` keep the old quorum and only rounds strictly
        // above it use the expanded one.
        self.roster_history.schedule(activation_round + 1, new_registry);
    }

    /// The number of members active at `round`, for unit-stake supermajority
    /// checks. Equivalent to `roster_for_round(round).len()`.
    ///
    /// When JX adds stake weights, replace call sites with
    /// `roster_for_round(round).total_weight()` and
    /// `roster_for_round(round).weight_of(node)`.
    pub fn member_count_at_round(&self, round: u64) -> usize {
        self.roster_history.roster_for_round(round).len()
    }

    /// A copy of the membership registry active at `round`. Used by the
    /// gossip layer to build the post-join registry before calling
    /// [`Hashgraph::add_member`].
    pub fn registry_at_round(&self, round: u64) -> MembershipRegistry {
        self.roster_history.roster_for_round(round).clone()
    }

    /// Phase 3 — the checkpoint payload for `round`, once that round is fully
    /// decided. The caller supplies the SHA-256 of the deterministic state
    /// (`State::to_bytes()`); the roster snapshot and its hash are taken from
    /// this node's roster history at that round. Returns `None` while `round`
    /// is not yet decided.
    pub fn checkpoint_payload(
        &self,
        round: u64,
        state_hash: [u8; 32],
    ) -> Option<CheckpointPayload> {
        if !self.is_round_decided(round) {
            return None;
        }
        let roster_snapshot = self.registry_at_round(round);
        Some(CheckpointPayload::new(round, state_hash, roster_snapshot))
    }

    /// Phase 3 — removes every event with `round_received <
    /// prune_before_round` from the live graph, preserving any event that is
    /// the self- or other-parent of a *live* event (round `prune_before_round`
    /// or later, or not yet ordered) — the "border" anchors. Border anchors
    /// do **not** protect their own parents: history strictly below the
    /// confirmed checkpoint is dropped, while the last few live rounds stay
    /// intact so recent inserts and delta-syncs never hit a `MissingParent`.
    /// Also trims `roster_history` snapshots whose activation round is below
    /// `prune_before_round`, keeping the one immediately at-or-before so the
    /// live window stays self-consistent.
    ///
    /// Ordering is unaffected: pruning only removes rounds that have already
    /// been finalized by `assign_order`, and round_received is immutable once
    /// assigned, so `consensus_order(r)` for `r >= prune_before_round` is
    /// identical before and after.
    ///
    /// # Panics
    /// Panics if `prune_before_round` is not below `next_round_to_order`
    /// (i.e. you cannot prune a round that has not been ordered yet).
    pub fn prune_before_round(&mut self, prune_before_round: u64) {
        assert!(
            prune_before_round < self.next_round_to_order,
            "cannot prune a round that has not been ordered yet: \
             requested {prune_before_round}, ordered through {}",
            self.next_round_to_order - 1
        );

        let threshold = prune_before_round;

        let mut pruned: BTreeSet<EventHash> = self
            .events
            .iter()
            .filter(|(_, record)| record.round_received().is_some_and(|rr| rr < threshold))
            .map(|(&hash, _)| hash)
            .collect();
        if pruned.is_empty() {
            return;
        }

        // Border anchors: the parent of a live event (round >= threshold, or
        // not yet ordered) must survive, or future inserts would fail with
        // MissingParent. Border anchors themselves are kept but do not
        // protect their own parents.
        for record in self.events.values() {
            let live = record.round_received().is_none_or(|rr| rr >= threshold);
            if !live {
                continue;
            }
            for parent in
                [record.event().self_parent(), record.event().other_parent()].into_iter().flatten()
            {
                pruned.remove(parent);
            }
        }

        for hash in &pruned {
            let Some(record) = self.events.remove(hash) else { continue };
            let creator = *record.event().creator();
            let seq = record.seq();

            for parent in
                [record.event().self_parent(), record.event().other_parent()].into_iter().flatten()
            {
                if let Some(children) = self.children.get_mut(parent) {
                    children.retain(|child| child != hash);
                }
            }
            self.children.remove(hash);
            let self_parent = record.event().self_parent().copied();
            if self.first_child.get(&(creator, self_parent)) == Some(hash) {
                self.first_child.remove(&(creator, self_parent));
            }
            if self.by_creator_seq.get(&(creator, seq)) == Some(hash) {
                self.by_creator_seq.remove(&(creator, seq));
            }
            if self.latest_by_creator.get(&creator) == Some(hash) {
                self.latest_by_creator.remove(&creator);
            }
        }

        self.roster_history.prune_before(threshold);
    }

    /// Whether `node` is a registered member of the current frozen
    /// structures (`member_index`).
    pub fn is_member(&self, node: &NodeId) -> bool {
        self.member_index.contains_key(node)
    }

    /// Whether round `round` is fully decided — every witness of `round` has
    /// a final fame decision. Same set that drives `order_decided_rounds` /
    /// `assign_order`, i.e. the same finality notion `finalized_events`
    /// relies on.
    pub fn is_round_decided(&self, round: u64) -> bool {
        self.fully_decided_rounds.contains(&round)
    }

    pub fn member_index_of(&self, node: &NodeId) -> Option<usize> {
        self.member_index.get(node).copied()
    }

    pub(crate) fn member_index_iter(&self) -> impl Iterator<Item = (&NodeId, &usize)> {
        self.member_index.iter()
    }

    pub(crate) fn creator_has_known_fork(&self, member_idx: usize) -> bool {
        self.known_forkers[member_idx]
    }

    pub(crate) fn event_for_creator_seq(&self, creator: NodeId, seq: u64) -> Option<EventHash> {
        self.by_creator_seq.get(&(creator, seq)).copied()
    }

    /// Consensus Spec §3.2 — the first-seen event created by `creator` with
    /// the given `self_parent`, if any. This is the canonical branch for a
    /// forking creator: `order.rs` uses it to discard duplicate famous
    /// witnesses from the same creator in a round (at most the first-seen
    /// branch is carried forward).
    pub(crate) fn canonical_child(
        &self,
        creator: NodeId,
        self_parent: Option<EventHash>,
    ) -> Option<EventHash> {
        self.first_child.get(&(creator, self_parent)).copied()
    }
}

#[cfg(test)]
mod tests {
    use crypto::{
        Signable,
        Verifiable,
    };
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Timestamp,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;

    fn registry_of(nodes: &[(NodeId, &SigningKey)]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for (id, key) in nodes {
            registry.register(*id, key.verifying_key());
        }
        registry
    }

    fn verified_event(
        key: &SigningKey,
        creator: NodeId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        ts: u64,
    ) -> VerifiedEvent {
        let event =
            UnsignedEvent::new(creator, self_parent, other_parent, Timestamp::new(ts), Vec::new())
                .sign(key);
        event.verify(&registry_of(&[(creator, key)])).expect("test event should verify")
    }

    #[test]
    fn genesis_event_gets_seq_one() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let hash = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();

        let record = hg.get(&hash).unwrap();
        assert_eq!(record.seq(), 1);
    }

    #[test]
    fn children_of_leaf_event_is_empty() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let hash = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();

        assert_eq!(hg.children(&hash), &[]);
    }

    #[test]
    fn children_returns_all_children_for_multi_child_event() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let parent = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        let child1 = hg.insert(verified_event(&key, node, Some(parent), None, 101)).unwrap();
        let child2 = hg.insert(verified_event(&key, node, Some(parent), None, 102)).unwrap();

        assert_eq!(hg.children(&parent), &[child1, child2]);
    }

    #[test]
    fn insert_duplicate_event_returns_already_present() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let ve = verified_event(&key, node, None, None, 100);
        let hash = hg.insert(ve.clone()).unwrap();

        let err = hg.insert(ve).unwrap_err();
        assert_eq!(err, InsertError::AlreadyPresent(hash));
    }

    #[test]
    fn insert_missing_other_parent_returns_missing_parent() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let ghost = EventHash::new([9; 32]);
        let err = hg.insert(verified_event(&key, node, None, Some(ghost), 100)).unwrap_err();

        assert_eq!(err, InsertError::MissingParent(ghost));
    }

    #[test]
    fn insert_unregistered_creator_returns_unknown_creator() {
        let key1 = SigningKey::generate(&mut OsRng);
        let node1 = NodeId::new(1);
        let registry1 = registry_of(&[(node1, &key1)]);
        let mut hg = Hashgraph::new(&registry1);

        let key2 = SigningKey::generate(&mut OsRng);
        let node2 = NodeId::new(2);
        let ve = verified_event(&key2, node2, None, None, 100);

        let err = hg.insert(ve).unwrap_err();
        assert_eq!(err, InsertError::UnknownCreator);
    }

    #[test]
    fn three_event_self_parent_chain_seqs_and_ancestor_seqs() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let idx = hg.member_index_of(&node).unwrap();

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        let e2 = hg.insert(verified_event(&key, node, Some(e1), None, 101)).unwrap();
        let e3 = hg.insert(verified_event(&key, node, Some(e2), None, 102)).unwrap();

        let r1 = hg.get(&e1).unwrap();
        let r2 = hg.get(&e2).unwrap();
        let r3 = hg.get(&e3).unwrap();

        assert_eq!((r1.seq(), r2.seq(), r3.seq()), (1, 2, 3));
        assert_eq!(r1.ancestor_seq(idx), 1);
        assert_eq!(r2.ancestor_seq(idx), 2);
        assert_eq!(r3.ancestor_seq(idx), 3);
    }

    #[test]
    fn two_creator_graph_ancestor_seqs_tracks_both_creators() {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let node_a = NodeId::new(1);
        let node_b = NodeId::new(2);
        let registry = registry_of(&[(node_a, &key_a), (node_b, &key_b)]);
        let mut hg = Hashgraph::new(&registry);

        let idx_a = hg.member_index_of(&node_a).unwrap();
        let idx_b = hg.member_index_of(&node_b).unwrap();

        let event_a = hg.insert(verified_event(&key_a, node_a, None, None, 100)).unwrap();
        let event_b = hg.insert(verified_event(&key_b, node_b, None, None, 105)).unwrap();

        let event_c =
            hg.insert(verified_event(&key_a, node_a, Some(event_a), Some(event_b), 110)).unwrap();
        let record_c = hg.get(&event_c).unwrap();

        assert_eq!(record_c.ancestor_seq(idx_a), 2);
        assert_eq!(record_c.ancestor_seq(idx_b), 1);
    }

    #[test]
    fn rejects_insert_with_missing_parent() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let ghost = EventHash::new([9; 32]);
        let err = hg.insert(verified_event(&key, node, Some(ghost), None, 100)).unwrap_err();

        assert_eq!(err, InsertError::MissingParent(ghost));
    }

    #[test]
    fn detects_a_fork() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        hg.insert(verified_event(&key, node, Some(e1), None, 101)).unwrap();
        // Second, conflicting event with the *same* self_parent = a fork.
        hg.insert(verified_event(&key, node, Some(e1), None, 999)).unwrap();

        let idx = hg.member_index_of(&node).unwrap();
        assert!(hg.creator_has_known_fork(idx));
    }

    #[test]
    fn test_fork_same_self_parent_sets_known_forkers_true() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let idx = hg.member_index_of(&node).unwrap();

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        let _e2 = hg.insert(verified_event(&key, node, Some(e1), None, 101)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));

        // Second event from same creator with same self_parent (genuine fork)
        let _e3 = hg.insert(verified_event(&key, node, Some(e1), None, 102)).unwrap();
        assert!(hg.creator_has_known_fork(idx));
    }

    #[test]
    fn test_creator_without_forks_known_forkers_remains_false() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let idx = hg.member_index_of(&node).unwrap();

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));

        let e2 = hg.insert(verified_event(&key, node, Some(e1), None, 101)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));

        let e3 = hg.insert(verified_event(&key, node, Some(e2), None, 102)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));

        let _e4 = hg.insert(verified_event(&key, node, Some(e3), None, 103)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));
    }

    #[test]
    fn test_fork_by_one_creator_does_not_affect_other_creators() {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let key_c = SigningKey::generate(&mut OsRng);
        let node_a = NodeId::new(1);
        let node_b = NodeId::new(2);
        let node_c = NodeId::new(3);
        let registry = registry_of(&[(node_a, &key_a), (node_b, &key_b), (node_c, &key_c)]);
        let mut hg = Hashgraph::new(&registry);

        let idx_a = hg.member_index_of(&node_a).unwrap();
        let idx_b = hg.member_index_of(&node_b).unwrap();
        let idx_c = hg.member_index_of(&node_c).unwrap();

        let e_a1 = hg.insert(verified_event(&key_a, node_a, None, None, 100)).unwrap();
        let e_b1 = hg.insert(verified_event(&key_b, node_b, None, None, 100)).unwrap();
        let _e_c1 = hg.insert(verified_event(&key_c, node_c, None, None, 100)).unwrap();

        // Node B forks
        let _e_b2_1 = hg.insert(verified_event(&key_b, node_b, Some(e_b1), None, 101)).unwrap();
        let _e_b2_2 = hg.insert(verified_event(&key_b, node_b, Some(e_b1), None, 102)).unwrap();

        // Node A continues linearly
        let _e_a2 = hg.insert(verified_event(&key_a, node_a, Some(e_a1), None, 101)).unwrap();

        assert!(hg.creator_has_known_fork(idx_b));
        assert!(!hg.creator_has_known_fork(idx_a));
        assert!(!hg.creator_has_known_fork(idx_c));
    }

    #[test]
    fn test_genesis_fork_detected() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let idx = hg.member_index_of(&node).unwrap();

        let _e1_a = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));

        // Second event with self_parent = None from same creator
        let _e1_b = hg.insert(verified_event(&key, node, None, None, 200)).unwrap();
        assert!(hg.creator_has_known_fork(idx));
    }

    #[test]
    fn test_reinsert_exact_same_event_after_fork_returns_already_present() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let idx = hg.member_index_of(&node).unwrap();

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        let ve2 = verified_event(&key, node, Some(e1), None, 101);
        let hash2 = hg.insert(ve2.clone()).unwrap();

        let ve3 = verified_event(&key, node, Some(e1), None, 102);
        let hash3 = hg.insert(ve3.clone()).unwrap();

        assert!(hg.creator_has_known_fork(idx));

        // Re-inserting exact same event ve2 or ve3 should hit AlreadyPresent
        let err2 = hg.insert(ve2).unwrap_err();
        assert_eq!(err2, InsertError::AlreadyPresent(hash2));

        let err3 = hg.insert(ve3).unwrap_err();
        assert_eq!(err3, InsertError::AlreadyPresent(hash3));

        // State of known_forkers should remain true
        assert!(hg.creator_has_known_fork(idx));
    }

    fn three_member_graph() -> (Hashgraph, MembershipRegistry) {
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let nodes: Vec<NodeId> = (1..=3).map(NodeId::new).collect();
        let registry = registry_of(&nodes.iter().copied().zip(&keys).collect::<Vec<_>>());
        let hg = Hashgraph::new(&registry);
        (hg, registry)
    }

    fn registry_plus_fourth(registry: &MembershipRegistry) -> MembershipRegistry {
        let new_key = SigningKey::generate(&mut OsRng);
        let mut new_registry = registry.clone();
        new_registry.register(NodeId::new(4), new_key.verifying_key());
        new_registry
    }

    #[test]
    fn add_member_increases_member_count() {
        let (mut hg, registry) = three_member_graph();
        assert_eq!(hg.member_count(), 3);
        hg.add_member(NodeId::new(4), 10, registry_plus_fourth(&registry));
        assert_eq!(hg.member_count(), 4);
    }

    #[test]
    fn add_member_extends_known_forkers() {
        let (mut hg, registry) = three_member_graph();
        hg.add_member(NodeId::new(4), 10, registry_plus_fourth(&registry));
        let idx = hg.member_index_of(&NodeId::new(4)).unwrap();
        assert!(!hg.creator_has_known_fork(idx));
    }

    #[test]
    fn add_member_backfills_ancestor_seqs_with_zero() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);
        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();

        let new_key = SigningKey::generate(&mut OsRng);
        let new_node = NodeId::new(2);
        let mut new_registry = registry;
        new_registry.register(new_node, new_key.verifying_key());
        hg.add_member(new_node, 10, new_registry);

        let new_idx = hg.member_index_of(&new_node).unwrap();
        assert_eq!(hg.get(&e1).unwrap().ancestor_seq(new_idx), 0);
    }

    #[test]
    fn add_member_assigns_next_slot_index() {
        let (mut hg, registry) = three_member_graph();
        hg.add_member(NodeId::new(4), 10, registry_plus_fourth(&registry));
        assert_eq!(hg.member_index_of(&NodeId::new(4)), Some(3));
    }

    #[test]
    fn add_member_schedules_new_roster() {
        let (mut hg, registry) = three_member_graph();
        hg.add_member(NodeId::new(4), 10, registry_plus_fourth(&registry));
        // Rounds at or below the activation round keep the old roster.
        assert_eq!(hg.member_count_at_round(10), 3);
        // Rounds strictly above the activation round use the new roster.
        assert_eq!(hg.member_count_at_round(11), 4);
    }

    #[test]
    #[should_panic(expected = "already-registered")]
    fn add_member_panics_on_duplicate() {
        let (mut hg, registry) = three_member_graph();
        let new_registry = registry_plus_fourth(&registry);
        hg.add_member(NodeId::new(4), 10, new_registry.clone());
        hg.add_member(NodeId::new(4), 20, new_registry);
    }

    #[test]
    fn new_member_events_use_correct_ancestor_seqs_len() {
        let key_a = SigningKey::generate(&mut OsRng);
        let node_a = NodeId::new(1);
        let registry = registry_of(&[(node_a, &key_a)]);
        let mut hg = Hashgraph::new(&registry);
        let e1 = hg.insert(verified_event(&key_a, node_a, None, None, 100)).unwrap();

        let new_key = SigningKey::generate(&mut OsRng);
        let new_node = NodeId::new(2);
        let mut new_registry = registry;
        new_registry.register(new_node, new_key.verifying_key());
        hg.add_member(new_node, 10, new_registry);

        // A pre-join event's record was backfilled to the expanded width.
        assert_eq!(hg.get(&e1).unwrap().ancestor_seqs.len(), 2);

        // A post-join event from the new member sizes its row to the same width.
        let e2 = hg.insert(verified_event(&new_key, new_node, None, Some(e1), 101)).unwrap();
        assert_eq!(hg.get(&e2).unwrap().ancestor_seqs.len(), 2);
    }

    /// A small graph with an explicit, controlled `roundReceived`
    /// assignment, so the pruning tests can assert exactly which events are
    /// pruned, which survive as border anchors, and which are untouched.
    ///
    /// Topology:
    /// ```text
    /// A: a1 -> a2 -> a3 -> a4 -> a5
    /// B: b1 -> b2 -> b3            (b2 other-parent a3, b3 other-parent a5)
    /// C: c1                         (isolated, childless)
    /// ```
    ///
    /// Rounds: a1,a2,c1 -> 1; a3,b1 -> 2; a4,a5,b2,b3 -> 3. `a2` is the
    /// self-parent of the live `a3`, so it is the one round-1 border anchor.
    fn build_prune_graph() -> (Hashgraph, std::collections::HashMap<&'static str, EventHash>) {
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let nodes = [NodeId::new(1), NodeId::new(2), NodeId::new(3)];
        let registry = registry_of(&nodes.iter().copied().zip(&keys).collect::<Vec<_>>());
        let mut hg = Hashgraph::new(&registry);
        let mut events = std::collections::HashMap::new();
        let mut ts = 100u64;
        let mut step = |label: &'static str,
                        author: usize,
                        self_parent: Option<&'static str>,
                        other_parent: Option<&'static str>| {
            let self_parent = self_parent.map(|label| events[label]);
            let other_parent = other_parent.map(|label| events[label]);
            let ve = verified_event(&keys[author], nodes[author], self_parent, other_parent, ts);
            ts += 1;
            let hash = hg.insert(ve).expect("insert should succeed");
            events.insert(label, hash);
        };
        step("a1", 0, None, None);
        step("a2", 0, Some("a1"), None);
        step("a3", 0, Some("a2"), None);
        step("a4", 0, Some("a3"), None);
        step("a5", 0, Some("a4"), None);
        step("b1", 1, None, None);
        step("b2", 1, Some("b1"), Some("a3"));
        step("b3", 1, Some("b2"), Some("a5"));
        step("c1", 2, None, None);

        // Assign roundReceived directly (bypassing the fame machinery, which
        // would leave these small rounds unresolved) and mark rounds 1-3 as
        // ordered so the prune guard admits a threshold of 2.
        hg.set_event_order(&events["a1"], 1, Timestamp::new(100));
        hg.set_event_order(&events["a2"], 1, Timestamp::new(101));
        hg.set_event_order(&events["c1"], 1, Timestamp::new(102));
        hg.set_event_order(&events["a3"], 2, Timestamp::new(200));
        hg.set_event_order(&events["b1"], 2, Timestamp::new(201));
        hg.set_event_order(&events["a4"], 3, Timestamp::new(300));
        hg.set_event_order(&events["a5"], 3, Timestamp::new(301));
        hg.set_event_order(&events["b2"], 3, Timestamp::new(302));
        hg.set_event_order(&events["b3"], 3, Timestamp::new(303));
        hg.next_round_to_order = 4;
        (hg, events)
    }

    #[test]
    fn prune_before_round_removes_ordered_events() {
        let (mut hg, events) = build_prune_graph();
        let a1 = events["a1"];
        let c1 = events["c1"];
        assert!(hg.get(&a1).is_some());
        assert!(hg.get(&c1).is_some());

        hg.prune_before_round(2);

        assert!(hg.get(&a1).is_none(), "round-1 event that is not a border anchor is pruned");
        assert!(hg.get(&c1).is_none(), "childless round-1 event is pruned");
        assert!(hg.get(&events["a5"]).is_some(), "live round-3 event survives");
    }

    #[test]
    fn prune_preserves_border_anchor_events() {
        let (mut hg, events) = build_prune_graph();
        // a2 has rr=1 but is the self-parent of the live a3 (rr=2).
        let a2 = events["a2"];
        let a3 = events["a3"];
        assert_eq!(hg.get(&a2).unwrap().round_received(), Some(1));
        assert_eq!(hg.get(&a3).unwrap().round_received(), Some(2));

        hg.prune_before_round(2);

        assert!(hg.get(&a2).is_some(), "a2 must survive as a border anchor");
        assert!(hg.get(&a3).is_some(), "the live child survives too");
        // The border anchor's own parent (a1) is not protected.
        assert!(hg.get(&events["a1"]).is_none(), "a border anchor does not protect its parents");
    }

    #[test]
    fn prune_does_not_affect_consensus_order_after_checkpoint() {
        let (mut hg, events) = build_prune_graph();
        let before_r2 = hg.consensus_order(2);
        let before_r3 = hg.consensus_order(3);
        assert!(!before_r2.is_empty());
        assert!(!before_r3.is_empty());

        hg.prune_before_round(2);

        assert_eq!(hg.consensus_order(2), before_r2, "round-2 order is unchanged");
        assert_eq!(hg.consensus_order(3), before_r3, "round-3 order is unchanged");
        // The pruned round-1 history no longer contributes to ordering.
        assert_eq!(hg.consensus_order(1), vec![events["a2"]]);
    }

    #[test]
    #[should_panic(expected = "not been ordered")]
    fn prune_before_unordered_round_panics() {
        let (mut hg, _events) = build_prune_graph();
        // Rounds are ordered through 3; pruning at 4 is not allowed.
        hg.prune_before_round(4);
    }
}
