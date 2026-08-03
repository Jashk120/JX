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
use thiserror::Error;

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
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InsertError {
    #[error("event {0:?} is already present in the hashgraph")]
    AlreadyPresent(EventHash),
    #[error("parent {0:?} is not present in the hashgraph")]
    MissingParent(EventHash),
    #[error("event creator is not a registered member")]
    UnknownCreator,
}

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
        }
    }

    pub fn insert(&mut self, verified: VerifiedEvent) -> Result<EventHash, InsertError> {
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

        self.events.insert(hash, EventRecord { event, seq, ancestor_seqs });

        Ok(hash)
    }

    pub fn get(&self, hash: &EventHash) -> Option<&EventRecord> {
        self.events.get(hash)
    }

    pub fn children(&self, hash: &EventHash) -> &[EventHash] {
        self.children.get(hash).map_or(&[], Vec::as_slice)
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
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Timestamp,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;
    use crypto::{
        Signable,
        Verifiable,
    };

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
        let event = UnsignedEvent::new(creator, self_parent, other_parent, Timestamp::new(ts), Vec::new())
            .sign(key);
        event.verify(&registry_of(&[(creator, key)])).expect("test event should verify")
    }

    #[test]
    fn inserts_a_genesis_event() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let hash = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();

        let record = hg.get(&hash).unwrap();
        assert_eq!(record.seq(), 1);
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
    fn self_parent_chain_increments_sequence() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let e1 = hg.insert(verified_event(&key, node, None, None, 100)).unwrap();
        let e2 = hg.insert(verified_event(&key, node, Some(e1), None, 101)).unwrap();

        assert_eq!(hg.get(&e2).unwrap().seq(), 2);
        assert_eq!(hg.children(&e1), &[e2]);
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
}