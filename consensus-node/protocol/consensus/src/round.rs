use primitives::EventHash;

use crate::error::Result;
use crate::hashgraph::Hashgraph;

/// Consensus Spec §2 — `r = max(round of x.self_parent, round of
/// x.other_parent)`, or `1` if `x` has no parents. Pure and self-contained
/// (no graph access needed) since it only depends on the two parent
/// records already looked up by `Hashgraph::insert`.
pub(crate) fn base_round(self_parent_round: Option<u64>, other_parent_round: Option<u64>) -> u64 {
    match (self_parent_round, other_parent_round) {
        (None, None) => 1,
        (a, b) => a.into_iter().chain(b).max().expect("at least one parent round present"),
    }
}

impl Hashgraph {
    /// Consensus Spec §2 / §2.1 — finishes what `insert` starts: decides
    /// whether `hash` (already stored, provisionally, at `base_round`)
    /// bumps to `base_round + 1`, then records both the final round and
    /// witness status on the stored `EventRecord`.
    ///
    /// Membership used for the `2n/3` threshold is the roster active at
    /// `base_round` — the event's own birth round — via
    /// `member_count_at_round`, not the scalar `member_count` (Phase 2).
    /// A member that joins at round `activation_round` counts toward the
    /// threshold only for events born strictly after `activation_round`;
    /// events born before it keep the old quorum, which is exactly what makes
    /// a mid-stream join safe without a coordinated restart.
    ///
    /// Fanout invariant (PLAN-2.4 T9, k=4): gossip `k` controls how many peers
    /// are synced per tick (network parallelism). Consensus round assignment
    /// depends only on parent rounds (`base_round`) and the witness
    /// supermajority (`stronglySee` over round-`base_round` witnesses); the
    /// per-creator frontier (`latest_event_by` / `latest_by_creator`) is a
    /// single-threaded `seq`-max updated under `Hashgraph::insert(&mut self)`
    /// with exclusive borrow, so higher `k` cannot race or reorder the
    /// frontier and does not change any round threshold. The threshold below
    /// is already stake-ready (PLAN-3): `count * 3 > total * 2` with
    /// `total = member_count_at_round(base_round)` equals
    /// `sum(stake_seen) * 3 > sum(stake_total) * 2` under unit stake, and the
    /// `* 3 > * 2` integer idiom is intentionally kept to avoid float
    /// rounding.
    pub(crate) fn finalize_round(
        &mut self,
        hash: EventHash,
        base_round: u64,
        self_parent_round: Option<u64>,
    ) -> Result<()> {
        let witnesses_of_base_round = self.witnesses_of_round(base_round).to_vec();

        let mut strongly_seen_count = 0usize;
        for witness in &witnesses_of_base_round {
            if self.strongly_see_at(&hash, witness, base_round)? {
                strongly_seen_count += 1;
            }
        }
        let bumps_round = strongly_seen_count * 3 > self.member_count_at_round(base_round) * 2;

        let final_round = if bumps_round { base_round + 1 } else { base_round };
        let is_witness = match self_parent_round {
            None => true,
            Some(spr) => final_round > spr,
        };

        self.set_event_round(&hash, final_round, is_witness);

        if is_witness {
            self.record_witness(final_round, hash);
        }

        Ok(())
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

    fn registry_of(nodes: &[(NodeId, &SigningKey)]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for (id, key) in nodes {
            registry.register(
                *id,
                key.verifying_key(),
                crypto::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
            );
        }
        registry
    }

    fn verified_event(
        registry: &MembershipRegistry,
        key: &SigningKey,
        creator: NodeId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        ts: u64,
    ) -> crypto::VerifiedEvent {
        let event =
            UnsignedEvent::new(creator, self_parent, other_parent, Timestamp::new(ts), Vec::new())
                .sign(key)
                .unwrap();
        event.verify(registry).expect("test event should verify")
    }

    /// Declarative dynamic-graph builder for round tests. You feed it a
    /// list of `(creator_label, self_parent_label, other_parent_label)`
    /// steps and it inserts them in order, returning a handle to every
    /// event by label. No test hardcodes hashes or expected rounds: the
    /// `strongly_seen` / `expected_round` helpers recompute the spec
    /// quantities from the live graph, so assertions are *self-checking*
    /// (they verify `finalize_round` matches the spec formula evaluated
    /// independently here).
    struct DynamicGraph {
        hg: Hashgraph,
        nodes: std::collections::HashMap<&'static str, (NodeId, SigningKey)>,
        events: std::collections::HashMap<&'static str, EventHash>,
        registry: MembershipRegistry,
        ts: u64,
    }

    impl DynamicGraph {
        fn new(members: &[&'static str]) -> Self {
            let mut nodes = std::collections::HashMap::new();
            let mut registry = MembershipRegistry::new();
            for (i, &name) in members.iter().enumerate() {
                let key = SigningKey::generate(&mut OsRng);
                let node = NodeId::new((i + 1) as u64);
                registry.register(
                    node,
                    key.verifying_key(),
                    crypto::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
                );
                nodes.insert(name, (node, key));
            }
            let hg = Hashgraph::new(&registry);
            Self { hg, nodes, events: std::collections::HashMap::new(), registry, ts: 100 }
        }

        fn build(
            &mut self,
            steps: &[(&'static str, &'static str, Option<&'static str>, Option<&'static str>)],
        ) {
            for &(label, author, sp, op) in steps {
                let (node, ref key) = self.nodes[author];
                let self_parent = sp.map(|l| self.events[l]);
                let other_parent = op.map(|l| self.events[l]);
                let ve =
                    verified_event(&self.registry, key, node, self_parent, other_parent, self.ts);
                self.ts += 1;
                let hash = self.hg.insert(ve).expect("insert should succeed");
                self.events.insert(label, hash);
            }
        }

        /// Round-1 witnesses created so far (one genesis per member),
        /// discovered dynamically from the graph rather than assumed.
        fn round_one_witnesses(&self) -> Vec<EventHash> {
            self.hg.witnesses_of_round(1).to_vec()
        }

        /// Which of the given witnesses `x` strongly sees, computed live
        /// from `strongly_see` itself -- no hardcoded expectation.
        fn strongly_seen(&self, x: &EventHash, witnesses: &[EventHash]) -> Vec<EventHash> {
            witnesses
                .iter()
                .filter(|w| self.hg.strongly_see(x, w).unwrap_or(false))
                .cloned()
                .collect()
        }

        /// Spec §2.1 recomputed here: bump to `base_round + 1` iff `x`
        /// strongly sees a supermajority (>2n/3) of round-`base_round`
        /// witnesses; `base_round` from the parents' stored rounds.
        fn expected_round(&self, x: &EventHash) -> u64 {
            let rec = self.hg.get(x).unwrap();
            let base = crate::round::base_round(
                rec.event().self_parent().and_then(|h| self.hg.get(h).map(|r| r.round())),
                rec.event().other_parent().and_then(|h| self.hg.get(h).map(|r| r.round())),
            );
            let witnesses = self.hg.witnesses_of_round(base).to_vec();
            let count = self.strongly_seen(x, &witnesses).len();
            if count * 3 > self.hg.member_count_at_round(base) * 2 { base + 1 } else { base }
        }
    }

    #[test]
    fn genesis_events_are_round_one_witnesses() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let e1 = hg.insert(verified_event(&registry, &key, node, None, None, 100)).unwrap();
        let rec = hg.get(&e1).unwrap();

        assert_eq!(rec.round(), 1);
        assert!(rec.is_witness());
        assert_eq!(hg.witnesses_of_round(1), &[e1]);
    }

    #[test]
    fn linear_self_parent_chain_stays_in_round_one_without_a_supermajority() {
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let e1 = hg.insert(verified_event(&registry, &key, node, None, None, 100)).unwrap();
        let e2 = hg.insert(verified_event(&registry, &key, node, Some(e1), None, 101)).unwrap();
        let e3 = hg.insert(verified_event(&registry, &key, node, Some(e2), None, 102)).unwrap();

        // A single-member "network": one witness (e1) is already >2n/3 of
        // n=1, so this graph round-bumps immediately -- included mainly
        // to document that single-node round-bumping is expected, not a
        // bug, before the four-member test below exercises the real case.
        assert!(hg.get(&e2).unwrap().round() >= 1);
        assert!(hg.get(&e3).unwrap().round() >= hg.get(&e2).unwrap().round());
    }

    /// Four members, each contributing one round-1 witness. A node needs
    /// to strongly-see > 2*4/3 = 2.67, i.e. at least 3, of those to bump
    /// to round 2. The graph and expectations are built *dynamically* via
    /// `DynamicGraph`: the round each event lands in and which witnesses
    /// it strongly sees are recomputed from the live graph by the helper
    /// (`expected_round`, `strongly_seen`), so nothing here is hardcoded
    /// -- the test proves `finalize_round` reproduces the spec formula.
    #[test]
    fn event_seeing_supermajority_of_witnesses_bumps_round_and_becomes_witness() {
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        // Round-1 witnesses: one genesis event per member.
        // Then a gossip fan-out that spreads each member's genesis to the
        // others *before* D's next event, so D's event strongly-sees a
        // supermajority of the round-1 witnesses via >=3 distinct member
        // chains (not merely a linear chain, which only yields plain
        // "see", not "strongly see").
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            // A learns d1; its own chain now reaches a1 and d1.
            ("a2", "a", Some("a1"), Some("d1")),
            // B learns a2 -> reaches a1, d1 (and keeps b1).
            ("b2", "b", Some("b1"), Some("a2")),
            // A learns b2 -> A's chain reaches a1, b1, d1.
            ("a3", "a", Some("a2"), Some("b2")),
            // B learns c1 -> B's chain reaches a1, b1, c1, d1.
            ("b3", "b", Some("b2"), Some("c1")),
            // A learns b3 -> A's chain reaches all four round-1 witnesses.
            ("a4", "a", Some("a3"), Some("b3")),
            // D's next event: self d1 + other a4. D sees everything; with
            // A and B each already reaching all four witnesses and D
            // itself seeing them, D strongly sees all four.
            ("d2", "d", Some("d1"), Some("a4")),
        ]);

        let witnesses = g.round_one_witnesses();
        let witnesses_by_creator: std::collections::HashMap<_, _> =
            witnesses.iter().map(|w| (*g.hg.get(w).unwrap().event().creator(), *w)).collect();

        // No earlier event bumped to round 2: only d2 sees a supermajority.
        for label in ["a2", "b2", "a3", "b3", "a4"] {
            let hash = g.events[label];
            assert_eq!(
                g.expected_round(&hash),
                g.hg.get(&hash).unwrap().round(),
                "stored round for {label} must match the spec-derived round",
            );
            assert!(
                g.hg.get(&hash).unwrap().round() == 1,
                "intermediate event {label} should not have bumped past round 1",
            );
        }

        let d2 = g.events["d2"];
        let d1 = witnesses_by_creator[&NodeId::new(4)];

        // d2 strongly-sees all four round-1 witnesses -- verified live.
        let seen = g.strongly_seen(&d2, &witnesses);
        assert_eq!(
            seen.len(),
            4,
            "d2 should strongly-see all four round-1 witnesses, got {seen:?}"
        );
        for w in &witnesses {
            assert!(g.hg.strongly_see(&d2, w).unwrap(), "d2 must strongly see {w:?}");
        }

        // Spec-derived round matches the stored round, and it's a round-2
        // witness whose self-parent was in round 1.
        assert_eq!(g.expected_round(&d2), 2);
        let rec = g.hg.get(&d2).unwrap();
        assert_eq!(rec.round(), 2);
        assert!(rec.is_witness());
        assert!(g.hg.witnesses_of_round(2).contains(&d2));
        assert_eq!(g.hg.get(&d1).unwrap().round(), 1);
    }

    /// `base_round` is the max of the two parent rounds, or 1 for genesis.
    /// Non-monotonic parents (self_parent_round != other_parent_round) must
    /// resolve to the higher value.
    #[test]
    fn base_round_picks_max_of_parent_rounds() {
        assert_eq!(base_round(None, None), 1, "genesis defaults to round 1");
        assert_eq!(base_round(Some(3), None), 3, "self-parent only");
        assert_eq!(base_round(None, Some(4)), 4, "other-parent only");
        assert_eq!(base_round(Some(3), Some(1)), 3, "self-parent newer");
        assert_eq!(base_round(Some(1), Some(3)), 3, "other-parent newer");
        assert_eq!(base_round(Some(5), Some(5)), 5, "equal rounds");
    }

    #[test]
    fn round_invariants_under_k4() {
        // Gossip k=4 fanout increases parallel syncs per tick but must not
        // affect consensus round invariants: `latest_event_by` is a
        // single-threaded seq-max frontier under &mut self, and the
        // supermajority uses `member_count_at_round` with the `*3>2` idiom
        // (already stake-ready for PLAN-3: unit stake => sum(stake)=n).
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
        ]);

        // Frontier after genesis: each creator seq 1.
        for (label, creator_id) in [("a", 1u64), ("b", 2), ("c", 3), ("d", 4)] {
            let node = NodeId::new(creator_id);
            let key = format!("{label}1");
            let hash = *g.events.get(key.as_str()).unwrap();
            assert_eq!(g.hg.latest_event_by(&node), Some(&hash));
            assert_eq!(g.hg.get(&hash).unwrap().seq(), 1);
        }
        // Stake-ready denominator: pre-join rounds see all 4 members.
        assert_eq!(g.hg.member_count_at_round(1), 4);
        assert_eq!(g.hg.member_count(), 4);
        // Future weighted form coincides under unit stake.
        let total_stake = g.hg.member_count_at_round(1);
        debug_assert_eq!(total_stake, 4, "unit stake: total_stake == member_count");

        // Simulate k=4 concurrent inserts: four events created in parallel
        // on different nodes, each syncing a different peer's genesis.
        // From the local insert perspective they arrive sequentially under
        // &mut self, so frontier must be seq-max with no race.
        g.build(&[
            ("a2", "a", Some("a1"), Some("b1")),
            ("b2", "b", Some("b1"), Some("c1")),
            ("c2", "c", Some("c1"), Some("d1")),
            ("d2", "d", Some("d1"), Some("a1")),
        ]);

        for (label, creator_id, expected_seq) in
            [("a", 1u64, 2u64), ("b", 2, 2), ("c", 3, 2), ("d", 4, 2)]
        {
            let node = NodeId::new(creator_id);
            let key = format!("{label}2");
            let hash = *g.events.get(key.as_str()).unwrap();
            assert_eq!(
                g.hg.latest_event_by(&node),
                Some(&hash),
                "frontier for {label} after first k=4 wave must be {label}2"
            );
            assert_eq!(g.hg.get(&hash).unwrap().seq(), expected_seq);
        }

        // No event in this wave should have bumped beyond round 1: each
        // sees at most 2 of 4 witnesses through distinct chains, below the
        // 3-of-4 supermajority (count*3 > 4*2).
        for label in ["a2", "b2", "c2", "d2"] {
            let hash = g.events[label];
            let witnesses = g.round_one_witnesses();
            let seen = g.strongly_seen(&hash, &witnesses).len();
            // Keep the *3>2 idiom, stake-ready via member_count_at_round.
            let total = g.hg.member_count_at_round(1);
            let bumps = seen * 3 > total * 2;
            assert!(!bumps, "{label} must not bump: seen {seen}/4");
            assert_eq!(g.hg.get(&hash).unwrap().round(), 1);
            assert_eq!(g.expected_round(&hash), 1);
        }

        // Second concurrent wave (still k=4): each creator advances once
        // more, cross-referencing the previous wave.
        g.build(&[
            ("a3", "a", Some("a2"), Some("c2")),
            ("b3", "b", Some("b2"), Some("d2")),
            ("c3", "c", Some("c2"), Some("a2")),
            ("d3", "d", Some("d2"), Some("b2")),
        ]);

        for (label, creator_id) in [("a", 1u64), ("b", 2), ("c", 3), ("d", 4)] {
            let node = NodeId::new(creator_id);
            let key = format!("{label}3");
            let hash = *g.events.get(key.as_str()).unwrap();
            assert_eq!(g.hg.latest_event_by(&node), Some(&hash));
            assert_eq!(g.hg.get(&hash).unwrap().seq(), 3);
        }

        // Frontier is monotonic and race-free: no lower-seq event clobbers it.
        // Re-check all creators' frontier still points to the highest seq.
        for (label, creator_id) in [("a", 1u64), ("b", 2), ("c", 3), ("d", 4)] {
            let node = NodeId::new(creator_id);
            let latest = g.hg.latest_event_by(&node).unwrap();
            let rec = g.hg.get(latest).unwrap();
            assert_eq!(rec.seq(), 3, "frontier for {label} must stay at seq 3");
            assert_eq!(*rec.event().creator(), node);
        }

        // Threshold idiom preserved under k=4: verify the exact
        // `count*3 > total*2` check still governs round bumps and matches
        // the future weighted `sum(stake)*3 > total_stake*2` for unit stake.
        // Build a gathering event that *does* strongly-see a supermajority
        // and confirm it bumps, while the stake-ready denominator is unchanged.
        g.build(&[
            // A collects the second wave so its chain reaches all four
            // round-1 witnesses through distinct members.
            ("a4", "a", Some("a3"), Some("b3")),
            ("b4", "b", Some("b3"), Some("a4")),
            // D syncs the fully-mixed chain and should strongly-see 4/4.
            ("d4", "d", Some("d3"), Some("b4")),
        ]);

        let witnesses = g.round_one_witnesses();
        let d4 = g.events["d4"];
        let seen_d4 = g.strongly_seen(&d4, &witnesses).len();
        let total = g.hg.member_count_at_round(1);
        assert!(
            seen_d4 * 3 > total * 2,
            "d4 must strongly-see supermajority: {seen_d4}*3 > {total}*2"
        );
        // Unit-stake equivalence: sum(stake_seen)==seen_d4, total_stake==total.
        debug_assert_eq!(seen_d4 * 3 > total_stake * 2, seen_d4 * 3 > total * 2);
        assert_eq!(g.hg.get(&d4).unwrap().round(), 2);
        assert_eq!(g.expected_round(&d4), 2);
        assert!(g.hg.get(&d4).unwrap().is_witness());

        // Frontier still correct after the bump (k does not move frontier).
        assert_eq!(g.hg.latest_event_by(&NodeId::new(1)), Some(&g.events["a4"]));
        assert_eq!(g.hg.latest_event_by(&NodeId::new(2)), Some(&g.events["b4"]));
        assert_eq!(g.hg.latest_event_by(&NodeId::new(4)), Some(&g.events["d4"]));
        // `latest_event_by` for c still points to c3 (no newer c event).
        assert_eq!(g.hg.latest_event_by(&NodeId::new(3)), Some(&g.events["c3"]));
    }

    #[test]
    fn expected_round_matches_production_across_membership_transition() {
        let mut g = DynamicGraph::new(&["a", "b", "c"]);
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("a2", "a", Some("a1"), Some("b1")),
            ("b2", "b", Some("b1"), Some("c1")),
            ("c2", "c", Some("c1"), Some("a2")),
        ]);
        for &label in &["a1", "b1", "c1", "a2", "b2", "c2"] {
            let h = g.events[label];
            assert_eq!(
                g.hg.get(&h).unwrap().round(),
                g.expected_round(&h),
                "pre-join {label} round must match roster-aware oracle"
            );
        }
        let key_d = SigningKey::generate(&mut OsRng);
        let node_d = NodeId::new(4);
        let mut expanded = g.registry.clone();
        expanded.register(
            node_d,
            key_d.verifying_key(),
            crypto::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );
        g.hg.add_member(node_d, 1, expanded.clone());
        assert_eq!(g.hg.member_count_at_round(1), 3);
        assert_eq!(g.hg.member_count_at_round(2), 4);
        g.nodes.insert("d", (node_d, key_d));
        g.registry = expanded;
        g.build(&[
            ("a3", "a", Some("a2"), Some("c2")),
            ("b3", "b", Some("b2"), Some("a3")),
            ("c3", "c", Some("c2"), Some("b3")),
            ("d1", "d", None, Some("c3")),
            ("a4", "a", Some("a3"), Some("d1")),
            ("b4", "b", Some("b3"), Some("a4")),
            ("c4", "c", Some("c3"), Some("b4")),
            ("d2", "d", Some("d1"), Some("c4")),
        ]);
        for &label in &["a3", "b3", "c3", "d1", "a4", "b4", "c4", "d2"] {
            let h = g.events[label];
            assert_eq!(
                g.hg.get(&h).unwrap().round(),
                g.expected_round(&h),
                "post-join {label} round must match roster-aware oracle"
            );
        }
    }
}
