use std::collections::{
    HashMap,
    HashSet,
    VecDeque,
};

use primitives::{
    EventHash,
    NodeId,
};

use crate::error::{
    ConsensusError,
    Result,
};
use crate::hashgraph::Hashgraph;

pub type AncestryError = ConsensusError;

impl Hashgraph {
    /// Ancestor, ignoring forks entirely (Consensus Spec §1.3's raw
    /// "ancestor" definition, not "see"). `x` is an ancestor of itself.
    pub fn is_ancestor(&self, x: &EventHash, y: &EventHash) -> Result<bool> {
        if x == y {
            return Ok(true);
        }
        let x_rec = self.get(x).ok_or(AncestryError::UnknownEvent(*x))?;
        let y_rec = self.get(y).ok_or(AncestryError::UnknownEvent(*y))?;
        let creator_idx =
            self.member_index_of(y_rec.event().creator()).ok_or(AncestryError::UnknownEvent(*y))?;

        if y_rec.seq() > x_rec.ancestor_seq(creator_idx) {
            return Ok(false);
        }

        if !self.creator_has_known_fork(creator_idx) {
            return Ok(true);
        }

        self.ancestry_contains_event(x, y)
    }

    /// Consensus Spec §1.3 — `x` can see `y`.
    ///
    /// Fast path: no evidence anywhere in this node's graph that `y`'s
    /// creator forked -> the ancestor check alone is sufficient. Slow
    /// path: `y`'s creator is a known equivocator somewhere -> fall back
    /// to a precise, observer-relative traversal of `x`'s real ancestry.
    pub fn see(&self, x: &EventHash, y: &EventHash) -> Result<bool> {
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
    pub fn strongly_see(&self, x: &EventHash, y: &EventHash) -> Result<bool> {
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
            if self.member_chain_reaches(x, node_id, idx, latest_seq, y)? {
                supermajority_count += 1;
            }
        }

        Ok(supermajority_count * 3 > self.member_count() * 2)
    }

    fn member_chain_reaches(
        &self,
        x: &EventHash,
        creator: NodeId,
        member_idx: usize,
        up_to_seq: u64,
        y: &EventHash,
    ) -> Result<bool> {
        let mut current = if self.creator_has_known_fork(member_idx) {
            self.ancestor_event_for_creator(x, &creator, up_to_seq)?
        } else {
            self.event_for_creator_seq(creator, up_to_seq)
        };

        while let Some(hash) = current {
            if self.see(&hash, y)? {
                return Ok(true);
            }
            current = self.get(&hash).and_then(|r| r.event().self_parent().copied());
        }

        Ok(false)
    }

    fn ancestor_event_for_creator(
        &self,
        x: &EventHash,
        creator: &NodeId,
        seq: u64,
    ) -> Result<Option<EventHash>> {
        let mut visited: HashSet<EventHash> = HashSet::new();
        let mut queue: VecDeque<EventHash> = VecDeque::from([*x]);

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current) {
                continue;
            }

            let rec = self.get(&current).ok_or(AncestryError::UnknownEvent(current))?;
            if rec.event().creator() == creator && rec.seq() == seq {
                return Ok(Some(current));
            }

            for parent in
                [rec.event().self_parent(), rec.event().other_parent()].into_iter().flatten()
            {
                queue.push_back(*parent);
            }
        }

        Ok(None)
    }

    fn ancestry_contains_event(&self, x: &EventHash, target: &EventHash) -> Result<bool> {
        let mut visited: HashSet<EventHash> = HashSet::new();
        let mut queue: VecDeque<EventHash> = VecDeque::from([*x]);

        while let Some(current) = queue.pop_front() {
            if current == *target {
                return Ok(true);
            }
            if !visited.insert(current) {
                continue;
            }
            let rec = self.get(&current).ok_or(AncestryError::UnknownEvent(current))?;

            for parent in
                [rec.event().self_parent(), rec.event().other_parent()].into_iter().flatten()
            {
                queue.push_back(*parent);
            }
        }

        Ok(false)
    }

    /// Real ancestor-set traversal, restricted to one creator. Only
    /// invoked from the `see` slow path, i.e. only for creators with
    /// known fork evidence — meant to be rare (Byzantine-minority path),
    /// so correctness is prioritized over speed here.
    fn ancestry_contains_fork_of(&self, x: &EventHash, creator: &NodeId) -> Result<bool> {
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

            for parent in
                [rec.event().self_parent(), rec.event().other_parent()].into_iter().flatten()
            {
                queue.push_back(*parent);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crypto::{
        MembershipRegistry,
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
    use crate::hashgraph::Hashgraph;

    fn registry_of(nodes: &[(NodeId, &SigningKey)]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for (id, key) in nodes {
            registry.register(*id, key.verifying_key());
        }
        registry
    }

    struct SwimlaneGraph {
        hg: Hashgraph,
        a1: EventHash,
        b1: EventHash,
        c1: EventHash,
        a2: EventHash,
        b2: EventHash,
        c2: EventHash,
        a3: EventHash,
    }

    impl SwimlaneGraph {
        fn debug_info(&self) -> String {
            format!(
                "Constructed EventHashes:\n  A1: {:?}\n  B1: {:?}\n  C1: {:?}\n  A2: {:?}\n  B2: {:?}\n  C2: {:?}\n  A3: {:?}",
                self.a1, self.b1, self.c1, self.a2, self.b2, self.c2, self.a3
            )
        }
    }

    fn build_shared_graph() -> SwimlaneGraph {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let key_c = SigningKey::generate(&mut OsRng);
        let node_a = NodeId::new(1);
        let node_b = NodeId::new(2);
        let node_c = NodeId::new(3);
        let registry = registry_of(&[(node_a, &key_a), (node_b, &key_b), (node_c, &key_c)]);
        let mut hg = Hashgraph::new(&registry);

        let mut create_event = |key: &SigningKey,
                                creator: NodeId,
                                self_parent: Option<EventHash>,
                                other_parent: Option<EventHash>,
                                ts: u64|
         -> EventHash {
            let unsigned = UnsignedEvent::new(
                creator,
                self_parent,
                other_parent,
                Timestamp::new(ts),
                Vec::new(),
            );
            let signed = unsigned.sign(key);
            let verified = signed.verify(&registry).expect("test event should verify");
            hg.insert(verified).expect("test event insertion should succeed")
        };

        let a1 = create_event(&key_a, node_a, None, None, 1);
        let b1 = create_event(&key_b, node_b, None, None, 1);
        let c1 = create_event(&key_c, node_c, None, None, 1);

        let a2 = create_event(&key_a, node_a, Some(a1), Some(b1), 2);
        let b2 = create_event(&key_b, node_b, Some(b1), Some(a1), 2);
        let c2 = create_event(&key_c, node_c, Some(c1), Some(a2), 3);
        let a3 = create_event(&key_a, node_a, Some(a2), Some(c2), 4);

        SwimlaneGraph { hg, a1, b1, c1, a2, b2, c2, a3 }
    }

    #[test]
    fn sees_direct_self_parent() {
        let g = build_shared_graph();
        assert!(g.hg.see(&g.a2, &g.a1).unwrap(), "see(A2, A1) should be true. {}", g.debug_info());
        assert!(
            !g.hg.see(&g.a1, &g.a2).unwrap(),
            "see(A1, A2) should be false. {}",
            g.debug_info()
        );
    }

    #[test]
    fn strongly_sees_requires_supermajority() {
        let g = build_shared_graph();
        assert!(g.hg.see(&g.a2, &g.a1).unwrap());
        assert!(
            !g.hg.strongly_see(&g.a2, &g.a1).unwrap(),
            "strongly_see(A2, A1) should be false due to lack of supermajority. {}",
            g.debug_info()
        );
        assert!(
            g.hg.strongly_see(&g.a3, &g.b1).unwrap(),
            "strongly_see(A3, B1) should be true. {}",
            g.debug_info()
        );
    }

    struct FourMemberGraph {
        hg: Hashgraph,
        node_a: NodeId,
        node_b: NodeId,
        node_c: NodeId,
        node_d: NodeId,
        a1: EventHash,
        a2: EventHash,
        a3: EventHash,
        c3: EventHash,
    }

    fn build_four_member_graph() -> FourMemberGraph {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let key_c = SigningKey::generate(&mut OsRng);
        let key_d = SigningKey::generate(&mut OsRng);
        let node_a = NodeId::new(1);
        let node_b = NodeId::new(2);
        let node_c = NodeId::new(3);
        let node_d = NodeId::new(4);
        let registry =
            registry_of(&[(node_a, &key_a), (node_b, &key_b), (node_c, &key_c), (node_d, &key_d)]);
        let mut hg = Hashgraph::new(&registry);

        let mut create_event = |key: &SigningKey,
                                creator: NodeId,
                                self_parent: Option<EventHash>,
                                other_parent: Option<EventHash>,
                                ts: u64|
         -> EventHash {
            let unsigned = UnsignedEvent::new(
                creator,
                self_parent,
                other_parent,
                Timestamp::new(ts),
                Vec::new(),
            );
            let signed = unsigned.sign(key);
            let verified = signed.verify(&registry).expect("test event should verify");
            hg.insert(verified).expect("test event insertion should succeed")
        };

        let a1 = create_event(&key_a, node_a, None, None, 1);
        let b1 = create_event(&key_b, node_b, None, None, 1);
        let c1 = create_event(&key_c, node_c, None, None, 1);
        let d1 = create_event(&key_d, node_d, None, None, 1);

        // Each second event has A1 as its other parent; D never references A1.
        let a2 = create_event(&key_a, node_a, Some(a1), Some(a1), 2);
        let b2 = create_event(&key_b, node_b, Some(b1), Some(a1), 2);
        let c2 = create_event(&key_c, node_c, Some(c1), Some(a1), 2);
        let a3 = create_event(&key_a, node_a, Some(a2), Some(b2), 3);
        let c3 = create_event(&key_c, node_c, Some(c2), Some(a3), 4);
        let _d2 = create_event(&key_d, node_d, Some(d1), None, 2);

        FourMemberGraph { hg, node_a, node_b, node_c, node_d, a1, a2, a3, c3 }
    }

    #[test]
    fn strongly_sees_three_of_four_independent_chains() {
        let g = build_four_member_graph();
        let a_idx = g.hg.member_index_of(&g.node_a).unwrap();
        let b_idx = g.hg.member_index_of(&g.node_b).unwrap();
        let c_idx = g.hg.member_index_of(&g.node_c).unwrap();
        let d_idx = g.hg.member_index_of(&g.node_d).unwrap();
        let x_rec = g.hg.get(&g.c3).unwrap();

        // By hand for x = C3 and target A1:
        // A: ancestor_seqs = 3 (A3), and member_chain_reaches(A, 3, A1) = true.
        // B: ancestor_seqs = 2 (B2), and member_chain_reaches(B, 2, A1) = true.
        // C: ancestor_seqs = 3 (C3), and member_chain_reaches(C, 3, A1) = true.
        // D: ancestor_seqs = 0 (no D event is an ancestor), so no path to A1.
        // Thus supermajority_count = 3; 3 * 3 = 9 > 4 * 2 = 8 (2n/3).
        assert_eq!(x_rec.ancestor_seq(a_idx), 3);
        assert_eq!(x_rec.ancestor_seq(b_idx), 2);
        assert_eq!(x_rec.ancestor_seq(c_idx), 3);
        assert_eq!(x_rec.ancestor_seq(d_idx), 0);
        assert!(g.hg.member_chain_reaches(&g.c3, g.node_a, 0, 3, &g.a1).unwrap());
        assert!(g.hg.member_chain_reaches(&g.c3, g.node_b, 1, 2, &g.a1).unwrap());
        assert!(g.hg.member_chain_reaches(&g.c3, g.node_c, 2, 3, &g.a1).unwrap());
        assert!(!g.hg.member_chain_reaches(&g.c3, g.node_d, 3, 0, &g.a1).unwrap());
        assert!(g.hg.strongly_see(&g.c3, &g.a1).unwrap());
    }

    #[test]
    fn strongly_sees_one_of_four_is_false() {
        let g = build_four_member_graph();

        assert!(!g.hg.strongly_see(&g.a2, &g.a1).unwrap());
    }

    #[test]
    fn strongly_sees_exactly_two_of_four_is_false() {
        let g = build_four_member_graph();

        // A3 reaches A1 through A2, and B2 reaches A1; C and D do not.
        // Thus supermajority_count = 2; 2 * 3 = 6 is not > 4 * 2 = 8.
        assert!(!g.hg.strongly_see(&g.a3, &g.a1).unwrap());
    }

    #[test]
    fn test_is_ancestor_self_ancestor() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.a3, &g.a3).unwrap();
        assert!(res, "1. is_ancestor(A3, A3) expected true, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_is_ancestor_transitive_self_parent() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.a3, &g.a1).unwrap();
        assert!(res, "2. is_ancestor(A3, A1) expected true, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_is_ancestor_via_other_parent() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.a3, &g.b1).unwrap();
        assert!(res, "3. is_ancestor(A3, B1) expected true, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_is_ancestor_via_c2_other_parent() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.a3, &g.c1).unwrap();
        assert!(res, "4. is_ancestor(A3, C1) expected true, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_is_ancestor_predates_false() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.a1, &g.a2).unwrap();
        assert!(!res, "5. is_ancestor(A1, A2) expected false, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_is_ancestor_unrelated_genesis_false() {
        let g = build_shared_graph();
        let res = g.hg.is_ancestor(&g.b1, &g.a1).unwrap();
        assert!(!res, "6. is_ancestor(B1, A1) expected false, got {res}. {}", g.debug_info());
    }

    #[test]
    fn test_see_matches_is_ancestor_for_all_pairs() {
        let g = build_shared_graph();
        let pairs = [
            ("A3", g.a3, "A3", g.a3),
            ("A3", g.a3, "A1", g.a1),
            ("A3", g.a3, "B1", g.b1),
            ("A3", g.a3, "C1", g.c1),
            ("A1", g.a1, "A2", g.a2),
            ("B1", g.b1, "A1", g.a1),
        ];

        for (x_name, x, y_name, y) in pairs {
            let ancestor_res = g.hg.is_ancestor(&x, &y).unwrap();
            let see_res = g.hg.see(&x, &y).unwrap();
            assert_eq!(
                see_res,
                ancestor_res,
                "7. see({x_name}, {y_name}) ({see_res}) does not match is_ancestor({x_name}, {y_name}) ({ancestor_res}). {}",
                g.debug_info()
            );
        }
    }

    mod observer_relative_fork_tests {
        use super::*;

        struct ForkGraph {
            hg: Hashgraph,
            node_f: NodeId,
            f1: EventHash,
            f2a: EventHash,
            f2b: EventHash,
            x2: EventHash,
        }

        fn build_observer_relative_fork_graph() -> ForkGraph {
            let key_f = SigningKey::generate(&mut OsRng);
            let key_x = SigningKey::generate(&mut OsRng);
            let node_f = NodeId::new(10);
            let node_x = NodeId::new(20);
            let registry = registry_of(&[(node_f, &key_f), (node_x, &key_x)]);
            let mut hg = Hashgraph::new(&registry);

            let mut create_event = |key: &SigningKey,
                                    creator: NodeId,
                                    self_parent: Option<EventHash>,
                                    other_parent: Option<EventHash>,
                                    ts: u64|
             -> EventHash {
                let unsigned = UnsignedEvent::new(
                    creator,
                    self_parent,
                    other_parent,
                    Timestamp::new(ts),
                    Vec::new(),
                );
                let signed = unsigned.sign(key);
                let verified = signed.verify(&registry).expect("test event should verify");
                hg.insert(verified).expect("test event insertion should succeed")
            };

            // F1 (genesis for F, seq 1)
            let f1 = create_event(&key_f, node_f, None, None, 1);

            // F2a (seq 2 for F, branch A)
            let f2a = create_event(&key_f, node_f, Some(f1), None, 2);

            // F2b (seq 2 for F, branch B — same self_parent F1, different timestamp creates a distinct event hash = fork!)
            let f2b = create_event(&key_f, node_f, Some(f1), None, 3);

            // X1 (genesis for X, seq 1)
            let x1 = create_event(&key_x, node_x, None, None, 1);

            // X2 (seq 2 for X, self_parent X1, other_parent F2a — descends from F2a branch only, never touches F2b)
            let x2 = create_event(&key_x, node_x, Some(x1), Some(f2a), 4);

            ForkGraph { hg, node_f, f1, f2a, f2b, x2 }
        }

        #[test]
        fn known_forkers_set_for_forking_creator() {
            let g = build_observer_relative_fork_graph();
            let f_idx =
                g.hg.member_index_of(&g.node_f)
                    .expect("creator F should be registered in member_index");
            assert!(
                g.hg.creator_has_known_fork(f_idx),
                "known_forkers should be true for creator F after inserting F1, F2a, and F2b"
            );
        }

        #[test]
        fn see_x2_f2a_returns_true() {
            let g = build_observer_relative_fork_graph();
            assert!(
                g.hg.see(&g.x2, &g.f2a).unwrap(),
                "see(X2, F2a) should be true because X2 genuinely descends from F2a"
            );
        }

        #[test]
        fn see_x2_f2b_returns_false() {
            let g = build_observer_relative_fork_graph();
            assert!(
                !g.hg.see(&g.x2, &g.f2b).unwrap(),
                "see(X2, F2b) should be false because X2 never saw F2b, even though F is a known forker globally"
            );
        }

        /// Reasoning according to Consensus Spec §1.3 / Definition 5.6:
        /// Definition 5.6 states that event x can see event y created by node k iff:
        ///   1. y is an ancestor of x.
        ///   2. x's ancestry does not contain two distinct events created by node k
        ///      with the same sequence number (i.e. no fork evidence by k in x's ancestry).
        ///
        /// Evaluated for see(X2, F1):
        /// - y = F1 (created by F, seq 1).
        /// - F1 is an ancestor of X2 (via X2 -> F2a -> F1).
        /// - The traversal of X2's ancestry yields events {X2, X1, F2a, F1}.
        /// - Within X2's ancestry, events created by F are {F1 (seq 1), F2a (seq 2)}.
        /// - F2b (seq 2, fork branch B) is NOT an ancestor of X2 and is NOT present in X2's ancestry.
        /// - Therefore, X2's ancestry contains exactly one event for seq 1 (F1) and one event for seq 2 (F2a)
        ///   from creator F. It contains NO evidence that creator F ever forked.
        /// - Consequently, X2 CAN see F1, so see(X2, F1) must return true.
        ///
        /// This test confirms that global fork detection on creator F does not naively taint
        /// pre-fork ancestors (or un-forked branches) from creator F when viewed by an observer
        /// whose ancestry contains no fork evidence.
        #[test]
        fn see_x2_f1_returns_true() {
            let g = build_observer_relative_fork_graph();
            assert!(
                g.hg.see(&g.x2, &g.f1).unwrap(),
                "see(X2, F1) should be true because X2's ancestry contains F1 and no evidence of F's fork"
            );
        }
    }
}
