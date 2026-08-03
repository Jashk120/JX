use std::collections::{
    HashMap,
    HashSet,
    VecDeque,
};

use primitives::{
    EventHash,
    NodeId,
};
use thiserror::Error;

use crate::hashgraph::Hashgraph;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AncestryError {
    #[error("event {0:?} is not present in the hashgraph")]
    UnknownEvent(EventHash),
}

impl Hashgraph {
    /// Ancestor, ignoring forks entirely (Consensus Spec §1.3's raw
    /// "ancestor" definition, not "see"). `x` is an ancestor of itself.
    pub fn is_ancestor(&self, x: &EventHash, y: &EventHash) -> Result<bool, AncestryError> {
        if x == y {
            return Ok(true);
        }
        let x_rec = self.get(x).ok_or(AncestryError::UnknownEvent(*x))?;
        let y_rec = self.get(y).ok_or(AncestryError::UnknownEvent(*y))?;
        let creator_idx = self
            .member_index_of(y_rec.event().creator())
            .ok_or(AncestryError::UnknownEvent(*y))?;

        Ok(y_rec.seq() <= x_rec.ancestor_seq(creator_idx))
    }

    /// Consensus Spec §1.3 — `x` can see `y`.
    ///
    /// Fast path: no evidence anywhere in this node's graph that `y`'s
    /// creator forked -> the ancestor check alone is sufficient. Slow
    /// path: `y`'s creator is a known equivocator somewhere -> fall back
    /// to a precise, observer-relative traversal of `x`'s real ancestry.
    pub fn see(&self, x: &EventHash, y: &EventHash) -> Result<bool, AncestryError> {
        if !self.is_ancestor(x, y)? {
            return Ok(false);
        }

        let y_rec = self.get(y).ok_or(AncestryError::UnknownEvent(*y))?;
        let creator = *y_rec.event().creator();
        let creator_idx = self.member_index_of(&creator).ok_or(AncestryError::UnknownEvent(*y))?;

        if !self.creator_has_known_fork(creator_idx) {
            return Ok(true);
        }

        Ok(!self.ancestry_contains_fork_of(x, &creator)?)
    }

    /// Consensus Spec §1.3 — `x` strongly sees `y`.
    ///
    /// NOTE (v1, intentionally unoptimized): for each member, walks that
    /// member's own self-parent chain — bounded by that member's
    /// sequence number, not a full graph traversal — looking for the
    /// earliest event that sees `y`. This is *not* the fully incremental
    /// technique from §7.5 (which would precompute, per witness, the
    /// earliest descendant-per-creator so this becomes O(n) array
    /// comparison with no walking at all). That optimization naturally
    /// belongs with Phase 4's round/witness machinery, since it only
    /// pays off once `strongly_see` is mostly called on witnesses rather
    /// than arbitrary event pairs. Flagging this rather than silently
    /// shipping a "final" version — worth revisiting once Phase 4 is
    /// underway.
    pub fn strongly_see(&self, x: &EventHash, y: &EventHash) -> Result<bool, AncestryError> {
        if !self.see(x, y)? {
            return Ok(false);
        }

        let x_rec = self.get(x).ok_or(AncestryError::UnknownEvent(*x))?;
        let mut supermajority_count = 0usize;

        let members: Vec<(NodeId, usize)> =
            self.member_index_iter().map(|(&id, &idx)| (id, idx)).collect();

        for (node_id, idx) in members {
            let latest_seq = x_rec.ancestor_seq(idx);
            if latest_seq == 0 {
                continue;
            }
            if self.member_chain_reaches(node_id, latest_seq, y)? {
                supermajority_count += 1;
            }
        }

        Ok(supermajority_count * 3 > self.member_count() * 2)
    }

    fn member_chain_reaches(
        &self,
        creator: NodeId,
        up_to_seq: u64,
        y: &EventHash,
    ) -> Result<bool, AncestryError> {
        let mut current = self.event_for_creator_seq(creator, up_to_seq);

        while let Some(hash) = current {
            if self.see(&hash, y)? {
                return Ok(true);
            }
            current = self.get(&hash).and_then(|r| r.event().self_parent().copied());
        }

        Ok(false)
    }

    /// Real ancestor-set traversal, restricted to one creator. Only
    /// invoked from the `see` slow path, i.e. only for creators with
    /// known fork evidence — meant to be rare (Byzantine-minority path),
    /// so correctness is prioritized over speed here.
    fn ancestry_contains_fork_of(
        &self,
        x: &EventHash,
        creator: &NodeId,
    ) -> Result<bool, AncestryError> {
        let mut seen_seqs: HashMap<u64, EventHash> = HashMap::new();
        let mut visited: HashSet<EventHash> = HashSet::new();
        let mut queue: VecDeque<EventHash> = VecDeque::from([*x]);

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current) {
                continue;
            }
            let rec = self.get(&current).ok_or(AncestryError::UnknownEvent(current))?;

            if rec.event().creator() == creator {
                match seen_seqs.get(&rec.seq()) {
                    Some(&existing) if existing != current => return Ok(true),
                    _ => {
                        seen_seqs.insert(rec.seq(), current);
                    }
                }
            }

            for parent in [rec.event().self_parent(), rec.event().other_parent()].into_iter().flatten() {
                queue.push_back(*parent);
            }
        }

        Ok(false)
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
    use crate::hashgraph::Hashgraph;
    use crypto::{
        MembershipRegistry,
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

    fn signed(
        registry: &MembershipRegistry,
        key: &SigningKey,
        creator: NodeId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        ts: u64,
    ) -> primitives::EventHash {
        unreachable!()
    }

    #[test]
    fn sees_direct_self_parent() {
        let a_key = SigningKey::generate(&mut OsRng);
        let a = NodeId::new(1);
        let registry = registry_of(&[(a, &a_key)]);
        let mut hg = Hashgraph::new(&registry);

        let e1 = UnsignedEvent::new(a, None, None, Timestamp::new(1), Vec::new()).sign(&a_key);
        let h1 = hg.insert(e1.verify(&registry).unwrap()).unwrap();

        let e2 = UnsignedEvent::new(a, Some(h1), None, Timestamp::new(2), Vec::new()).sign(&a_key);
        let h2 = hg.insert(e2.verify(&registry).unwrap()).unwrap();

        assert!(hg.see(&h2, &h1).unwrap());
        assert!(!hg.see(&h1, &h2).unwrap());
    }

    #[test]
    fn strongly_sees_requires_supermajority() {
        // 4 members: a genesis event from a single creator, seen only by
        // that creator, cannot be strongly seen (1/4 < 2/3).
        let a_key = SigningKey::generate(&mut OsRng);
        let b_key = SigningKey::generate(&mut OsRng);
        let c_key = SigningKey::generate(&mut OsRng);
        let d_key = SigningKey::generate(&mut OsRng);
        let (a, b, c, d) = (NodeId::new(1), NodeId::new(2), NodeId::new(3), NodeId::new(4));
        let registry = registry_of(&[(a, &a_key), (b, &b_key), (c, &c_key), (d, &d_key)]);
        let mut hg = Hashgraph::new(&registry);

        let ea = UnsignedEvent::new(a, None, None, Timestamp::new(1), Vec::new()).sign(&a_key);
        let ha = hg.insert(ea.verify(&registry).unwrap()).unwrap();

        let ea2 = UnsignedEvent::new(a, Some(ha), None, Timestamp::new(2), Vec::new()).sign(&a_key);
        let ha2 = hg.insert(ea2.verify(&registry).unwrap()).unwrap();

        // ha2 only descends from `a` — no other creator's chain reaches
        // `ha`, so strongly_see must be false.
        assert!(hg.see(&ha2, &ha).unwrap());
        assert!(!hg.strongly_see(&ha2, &ha).unwrap());
    }
}