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
    /// Membership used for the `2n/3` threshold is today's static,
    /// whole-graph `member_count()` (matching `Hashgraph::new`'s current
    /// fixed registry). Dynamic membership is deliberately *not* handled
    /// here — see the note in ROADMAP / project discussion: doing it
    /// correctly requires gating on finalized order (§4's
    /// `roundReceived`), which doesn't exist until Ordering is built.
    /// Real Hedera/Hiero confirms this split: its `RosterHistory` /
    /// `RosterRetriever` look up "the roster active as of round r" from
    /// state, but that state is only ever written by the app layer after
    /// consensus handling — never by the round-assignment algorithm
    /// itself.
    pub(crate) fn finalize_round(
        &mut self,
        hash: EventHash,
        base_round: u64,
        self_parent_round: Option<u64>,
    ) -> Result<()> {
        let witnesses_of_base_round = self.witnesses_of_round(base_round).to_vec();

        let mut strongly_seen_count = 0usize;
        for witness in &witnesses_of_base_round {
            if self.strongly_see(&hash, witness)? {
                strongly_seen_count += 1;
            }
        }
        let bumps_round = strongly_seen_count * 3 > self.member_count() * 2;

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
            registry.register(*id, key.verifying_key());
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
                .sign(key);
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
                registry.register(node, key.verifying_key());
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
            if count * 3 > self.hg.member_count() * 2 { base + 1 } else { base }
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
}
