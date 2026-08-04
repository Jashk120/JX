use std::collections::HashMap;

use crypto::{
    Hashable,
    MembershipRegistry,
    VerifiedEvent,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
};

use crate::error::{
    ConsensusError,
    Result,
};

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

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn is_witness(&self) -> bool {
        self.is_witness
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
    member_index: HashMap<NodeId, usize>,
    member_count: usize,
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
            member_index,
            member_count,
            known_forkers: vec![false; member_count],
            witnesses_by_round: HashMap::new(),
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
        self.events.insert(hash, EventRecord { event, seq, ancestor_seqs, round: base_round, is_witness: false });

        self.finalize_round(hash, base_round, self_parent_round)?;

        Ok(hash)
    }

    pub fn get(&self, hash: &EventHash) -> Option<&EventRecord> {
        self.events.get(hash)
    }

    pub fn children(&self, hash: &EventHash) -> &[EventHash] {
        self.children.get(hash).map_or(&[], Vec::as_slice)
    }

    /// Consensus Spec §2.1 — witnesses of `round`, i.e. every event that
    /// was the first created by its creator in that round. Empty slice if
    /// `round` hasn't been reached yet (or has no witnesses recorded).
    pub fn witnesses_of_round(&self, round: u64) -> &[EventHash] {
        self.witnesses_by_round.get(&round).map_or(&[], Vec::as_slice)
    }

    /// Crate-internal: records `hash` as a witness of `round`. Only ever
    /// called from `round.rs`'s `finalize_round`, immediately after an
    /// event's final round is decided.
    pub(crate) fn record_witness(&mut self, round: u64, hash: EventHash) {
        self.witnesses_by_round.entry(round).or_default().push(hash);
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

    pub(crate) fn member_index_of(&self, node: &NodeId) -> Option<usize> {
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
}
