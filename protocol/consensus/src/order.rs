//! Consensus Spec §4 — Order Finalization (`assignOrder`).
//!
//! Once every witness of a round has a final fame decision, that round is
//! *decided*, and every not-yet-ordered event whose ancestry is now fully
//! resolved gets an immutable `roundReceived` and `consensusTimestamp`:
//!
//! ```text
//! procedure assignOrder(x):
//!     x.roundReceived = the first round r such that all famous witnesses of round r
//!                        can see (or are descendants of) x
//!     x.consensusTimestamp = median of the timestamps that each famous witness of
//!                             round x.roundReceived first received x (i.e., the
//!                             timestamp of the earliest event, in each famous
//!                             witness's ancestry, that can see x)
//! ```
//!
//! The final total order sorts by `roundReceived`, then `consensusTimestamp`,
//! then a deterministic signature-derived tie-break (see
//! [`signature_tie_break`]).
//!
//! # When a round is finalized
//!
//! A round `r` is *decided* once every witness of `r` has a final, immutable
//! fame decision **and** this node's view of `r` is complete: every member
//! active at `r` has contributed an event born after `r`
//! ([`Hashgraph::round_view_complete`]). The view-completeness gate exists
//! because a fame-complete round against a partial witness set would produce an
//! order that a better-synced peer computes differently for the same round —
//! and ordering is immutable, so the divergence would never heal. At that point
//! round `r`'s famous-witness set is final (a witness's fame never changes once
//! decided), so `assignOrder(r)` can be run immediately.
//! `Hashgraph::order_decided_rounds` processes decided rounds in strictly
//! increasing order, each exactly once. Note that a round is not decided until
//! the election has run *past* it — a round-`r` witness's fame is produced by
//! round-`(r+1)` voters — so by the time round `r` is decided, the information
//! needed to compute its ordering is already present.
//!
//! # Eager, incremental, no full rescans
//!
//! The whole entry point is `Hashgraph::note_round_decided_if_complete`,
//! called from `Hashgraph::decide_fame` (see `fame.rs`). Because fame
//! decisions can be produced at any recursion depth inside the election, this
//! is the *only* place the "is a round now decided?" question is asked —
//! never at the top of `insert` for just the newly inserted witness's round.
//! `assign_order` scans the stored events once per finalized round (not per
//! insertion), and events that are already ordered are skipped.

use primitives::{
    EventHash,
    NodeId,
    Signature,
    Timestamp,
};

use crate::hashgraph::{
    FameStatus,
    Hashgraph,
};

/// Consensus Spec §4 — the deterministic final tie-break for two events with
/// the *same* `roundReceived` *and* the *same* `consensusTimestamp`
/// `[DECISION NEEDED]`.
///
/// The spec suggests a signature-derived value; the specific construction is
/// left to the implementer as long as every honest node applies the same
/// deterministic rule. Chosen here: XOR-fold the event's own 64-byte Ed25519
/// signature (`Signature::as_bytes()`) down to a single `u64` by XORing its
/// eight 8-byte chunks together, and break ties by that value ascending.
///
/// This is a simplicity/determinism choice, not something the papers
/// mandate — any deterministic function of the event's own bytes would do,
/// since all honest nodes hold the identical event and therefore compute the
/// identical value. Exact timestamp ties across independently-clocked
/// members are rare in practice, but silently mis-ordering on one would
/// break the "all honest nodes compute identical order" property that is the
/// entire point of this phase.
fn signature_tie_break(signature: &Signature) -> u64 {
    let bytes = signature.as_bytes();
    bytes.chunks_exact(8).fold(0u64, |acc, chunk| {
        acc ^ u64::from_le_bytes(chunk.try_into().expect("chunks_exact yields 8 bytes"))
    })
}

impl Hashgraph {
    /// Consensus Spec §4 — the famous witnesses of `round`, deduplicated per
    /// §3.2: if a forking creator contributed more than one `Famous` witness
    /// to the same round, only the canonical first-seen branch participates
    /// in `assignOrder`; the rest are excluded.
    ///
    /// "Canonical" is the `first_child` first-seen policy (see
    /// [`Hashgraph::canonical_child`]) — the same policy `see`'s slow path
    /// uses for the fork case, so a witness that was never cleanly seeable
    /// is also never carried forward here.
    pub(crate) fn famous_witnesses_of_round(&self, round: u64) -> Vec<EventHash> {
        let mut canonical = Vec::new();
        for &witness in self.witnesses_of_round(round) {
            if self.fame_of(&witness) != Some(FameStatus::Famous) {
                continue;
            }
            let record = match self.get(&witness) {
                Some(record) => record,
                None => continue,
            };
            let creator = *record.event().creator();
            let self_parent = record.event().self_parent().copied();
            // Spec §3.2: keep only the first-seen branch of a forking
            // creator; any other `Famous` witness from the same creator in
            // this round is a discarded fork branch.
            if self.canonical_child(creator, self_parent) == Some(witness) {
                canonical.push(witness);
            }
        }
        canonical
    }

    /// Consensus Spec §4 — finalizes round `round`: every not-yet-ordered
    /// event that all (canonical) famous witnesses of `round` can see is
    /// assigned `roundReceived = round` and a median `consensusTimestamp`.
    ///
    /// Only called from `order_decided_rounds`, once per round, in
    /// increasing order. Events assigned here are never revisited: a famous
    /// witness of a later round that can see `x` does not change `x`'s
    /// already-final earlier `roundReceived`.
    pub(crate) fn assign_order(&mut self, round: u64) {
        let famous: Vec<EventHash> = self.famous_witnesses_of_round(round);
        if famous.is_empty() {
            return;
        }

        let pending = self.pending_order_events();

        for event in pending {
            let all_famous_see_event =
                famous.iter().all(|witness| self.see(witness, &event).unwrap_or(false));
            if !all_famous_see_event {
                continue;
            }

            let mut first_seen: Vec<u64> = Vec::with_capacity(famous.len());
            for witness in &famous {
                if let Some(timestamp) = self.first_seen_timestamp(witness, &event) {
                    first_seen.push(timestamp);
                }
            }
            let consensus_timestamp = median_timestamp(&mut first_seen);

            self.set_event_order(&event, round, consensus_timestamp);
        }
    }

    /// Consensus Spec §4 — the timestamp at which `witness` first received
    /// `target`: the declared timestamp of the earliest event in `witness`'s
    /// ancestry that can see `target`. Returns `None` if no such event
    /// exists (`witness` cannot see `target`).
    ///
    /// `[DECISION NEEDED]` — "earliest" is defined *structurally*: the event
    /// lowest in causal order (lowest per-creator sequence number), **not**
    /// the one with the minimum declared `Timestamp` value. Using raw
    /// timestamp values would let a single member whose clock runs fast (or
    /// backdated, or malicious) skew the median by attaching an artificially
    /// early timestamp to a later event. Structural order avoids that: it
    /// picks *which* event a member first received the target through, and
    /// that event's own declared timestamp is still the value contributed to
    /// the median.
    ///
    /// Along a single creator's self-parent chain, "can see `target`" is
    /// monotone — once a chain event descends from `target`, every later
    /// event in that chain does too — so per creator the search is a binary
    /// search over `seq` using [`Hashgraph::event_for_creator_seq`]
    /// (O(log seq)), and the result is the minimum over every creator
    /// represented in the witness's ancestry.
    fn first_seen_timestamp(&self, witness: &EventHash, target: &EventHash) -> Option<u64> {
        let witness_record = self.get(witness)?;

        // The earliest candidate: smallest per-creator sequence, then the
        // event hash as a deterministic tie-break for identical sequences.
        let mut earliest: Option<(u64, EventHash)> = None;

        for (node_id, idx) in self.member_index_iter() {
            let up_to = witness_record.ancestor_seq(*idx);
            if up_to == 0 {
                continue;
            }

            // Skip the binary search entirely when even the latest event
            // from this creator cannot see the target.
            let latest = self.creator_chain_event(witness, *node_id, *idx, up_to);
            if !latest.is_some_and(|event| self.see(&event, target).unwrap_or(false)) {
                continue;
            }

            let mut low = 1u64;
            let mut high = up_to;
            while low < high {
                let mid = low + (high - low) / 2;
                let event = self.creator_chain_event(witness, *node_id, *idx, mid);
                if event.is_some_and(|event| self.see(&event, target).unwrap_or(false)) {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }

            let event = self.creator_chain_event(witness, *node_id, *idx, low)?;
            let replace = match earliest {
                None => true,
                Some((best_seq, best_event)) => {
                    low < best_seq || (low == best_seq && event < best_event)
                }
            };
            if replace {
                earliest = Some((low, event));
            }
        }

        let (_, event) = earliest?;
        Some(self.get(&event)?.event().timestamp().get())
    }

    /// The event at `(creator, seq)` as seen through `witness`'s ancestry:
    /// the fast canonical lookup when `creator` has no known fork evidence,
    /// otherwise the observer-relative traversal (same split as `ancestry.rs`
    ///'s `member_chain_reaches`). `idx` is that creator's member index.
    fn creator_chain_event(
        &self,
        witness: &EventHash,
        creator: NodeId,
        idx: usize,
        seq: u64,
    ) -> Option<EventHash> {
        if self.creator_has_known_fork(idx) {
            self.ancestor_event_for_creator(witness, &creator, seq).ok().flatten()
        } else {
            self.event_for_creator_seq(creator, seq)
        }
    }

    /// Consensus Spec §4 — an event's finalized `roundReceived`, if it has
    /// been ordered.
    pub fn round_received(&self, hash: &EventHash) -> Option<u64> {
        self.get(hash)?.round_received()
    }

    /// Consensus Spec §4 — a witness's consensus timestamp, i.e. the median
    /// of the timestamps at which each famous witness of its
    /// `roundReceived` first received it.
    pub fn consensus_timestamp(&self, hash: &EventHash) -> Option<Timestamp> {
        self.get(hash)?.consensus_timestamp()
    }

    /// Consensus Spec §4 — the finalized total order of every event with
    /// `roundReceived == round`, sorted by the spec's three keys:
    /// `consensusTimestamp` ascending (all events in the slice share the
    /// same `roundReceived`, so that key is constant), then the
    /// signature-XOR tie-break ascending, then event hash as the final
    /// determinism guarantee.
    pub fn consensus_order(&self, round: u64) -> Vec<EventHash> {
        let mut ordered: Vec<EventHash> = self
            .all_event_hashes()
            .into_iter()
            .filter(|hash| self.round_received(hash) == Some(round))
            .collect();

        ordered.sort_by(|a, b| {
            let a_record = self.get(a).expect("ordering reads only present events");
            let b_record = self.get(b).expect("ordering reads only present events");
            a_record
                .consensus_timestamp()
                .cmp(&b_record.consensus_timestamp())
                .then_with(|| {
                    let a_tie = signature_tie_break(a_record.event().signature());
                    let b_tie = signature_tie_break(b_record.event().signature());
                    a_tie.cmp(&b_tie)
                })
                .then_with(|| a.cmp(b))
        });

        ordered
    }
}

/// Median of the given first-seen timestamps. `[DECISION NEEDED]` — for an
/// even-length list the median is defined here as the **average of the two
/// middle values** (integer division, truncating toward zero), not the lower
/// middle. The spec does not pin this down; averaged-pair is the
/// conventional definition, and the sub-nanosecond truncation is only ever
/// a tie that the next sort key resolves deterministically.
fn median_timestamp(first_seen: &mut [u64]) -> Timestamp {
    first_seen.sort_unstable();
    let len = first_seen.len();
    assert!(len > 0, "a roundReceived event is seen by at least one famous witness");
    let median = if len % 2 == 1 {
        first_seen[len / 2]
    } else {
        let mid = len / 2;
        let sum = u128::from(first_seen[mid - 1]) + u128::from(first_seen[mid]);
        (sum / 2) as u64
    };
    Timestamp::new(median)
}

#[cfg(test)]
mod tests {
    use std::collections::{
        HashMap,
        HashSet,
    };

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

    /// Declarative dynamic-graph builder, adapted from `round.rs` / `fame.rs`
    /// (same shape). Feeds `(label, author, self_parent, other_parent)` steps
    /// and inserts them in order, returning handles by label.
    struct DynamicGraph {
        hg: Hashgraph,
        nodes: HashMap<&'static str, (NodeId, SigningKey)>,
        events: HashMap<&'static str, EventHash>,
        registry: MembershipRegistry,
        ts: u64,
    }

    impl DynamicGraph {
        fn new(members: &[&'static str]) -> Self {
            let mut nodes = HashMap::new();
            let mut registry = MembershipRegistry::new();
            for (i, &name) in members.iter().enumerate() {
                let key = SigningKey::generate(&mut OsRng);
                let node = NodeId::new((i + 1) as u64);
                registry.register(node, key.verifying_key());
                nodes.insert(name, (node, key));
            }
            let hg = Hashgraph::new(&registry);
            Self { hg, nodes, events: HashMap::new(), registry, ts: 100 }
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
    }

    /// The 4-member gossip graph used by `fame.rs`'s
    /// `famous_via_direct_can_see`: a/b alternate gossip to spread every
    /// genesis through the ring, producing four round-2 witnesses (a5, b4,
    /// c2, d2) that all see the round-1 events, then four round-3 witnesses
    /// (c3, d3, a6, b5) and four round-4 witnesses (c4, d4, a7, b6).
    ///
    /// The graph is deliberately built *past* the rounds whose ordering the
    /// tests inspect: a round is only decided once the election has run past
    /// it (round-`r` fame is produced by round-`(r+1)` voters), so the
    /// round-1/round-2 ordering the tests assert on is triggered by the
    /// round-3/round-4 gossip below.
    fn build_deep_clique() -> DynamicGraph {
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("a2", "a", Some("a1"), Some("d1")),
            ("b2", "b", Some("b1"), Some("a2")),
            ("a3", "a", Some("a2"), Some("b2")),
            ("b3", "b", Some("b2"), Some("c1")),
            ("a4", "a", Some("a3"), Some("b3")),
            ("d2", "d", Some("d1"), Some("a4")),
            ("c2", "c", Some("c1"), Some("d2")),
            ("a5", "a", Some("a4"), Some("c2")),
            ("b4", "b", Some("b3"), Some("a5")),
            ("c3", "c", Some("c2"), Some("b4")),
            ("d3", "d", Some("d2"), Some("c3")),
            ("a6", "a", Some("a5"), Some("d3")),
            ("b5", "b", Some("b4"), Some("a6")),
            ("c4", "c", Some("c3"), Some("b5")),
            ("d4", "d", Some("d3"), Some("c4")),
            ("a7", "a", Some("a6"), Some("d4")),
            ("b6", "b", Some("b5"), Some("a7")),
        ]);
        g
    }

    /// Exhaustive ancestry walk of `root` (self + every parent, transitively),
    /// used by the first-seen oracle below.
    fn walk_ancestors(hg: &Hashgraph, root: &EventHash) -> Vec<EventHash> {
        let mut out = Vec::new();
        let mut stack = vec![*root];
        while let Some(hash) = stack.pop() {
            if out.contains(&hash) {
                continue;
            }
            out.push(hash);
            let record = hg.get(&hash).unwrap();
            for parent in
                [record.event().self_parent(), record.event().other_parent()].into_iter().flatten()
            {
                stack.push(*parent);
            }
        }
        out
    }

    /// Reference first-seen computation: the declared timestamp of the
    /// lowest-`seq` event in `witness`'s ancestry that can see `target` —
    /// the spec's "earliest event ... that can see x", evaluated by an
    /// exhaustive walk, independent of the binary-search production code.
    fn reference_first_seen(
        hg: &Hashgraph,
        witness: &EventHash,
        target: &EventHash,
    ) -> Option<u64> {
        let mut best: Option<(u64, EventHash)> = None;
        for ancestor in walk_ancestors(hg, witness) {
            if !hg.see(&ancestor, target).unwrap() {
                continue;
            }
            let seq = hg.get(&ancestor).unwrap().seq();
            let replace = match best {
                None => true,
                Some((best_seq, best_event)) => {
                    seq < best_seq || (seq == best_seq && ancestor < best_event)
                }
            };
            if replace {
                best = Some((seq, ancestor));
            }
        }
        best.map(|(_, event)| hg.get(&event).unwrap().event().timestamp().get())
    }

    /// Reference `assignOrder(x)`, evaluated from scratch against the fully
    /// built graph: the first round whose (canonical, §3.2-deduped) famous
    /// witnesses all see `x`, and the median of those witnesses' first-seen
    /// timestamps. Independent of the incremental machinery under test.
    fn reference_order(hg: &Hashgraph, x: &EventHash) -> Option<(u64, Timestamp)> {
        for round in 1..=hg.highest_witness_round() {
            let famous = hg.famous_witnesses_of_round(round);
            if famous.is_empty() {
                continue;
            }
            if !famous.iter().all(|w| hg.see(w, x).unwrap()) {
                continue;
            }
            let mut first_seen: Vec<u64> =
                famous.iter().filter_map(|w| reference_first_seen(hg, w, x)).collect();
            if first_seen.is_empty() {
                continue;
            }
            return Some((round, median_timestamp(&mut first_seen)));
        }
        None
    }

    /// Spec §8 test 1 — simple case. The round-1 event `a1` is directly seen
    /// by every famous witness of round 2 (its `roundReceived`): every one of
    /// them has `a1` at seq 1 of member `a`'s chain, so the median is `a1`'s
    /// own timestamp. Verified against the reference `assignOrder`, not
    /// hardcoded.
    #[test]
    fn simple_round_received_and_consensus_timestamp() {
        let g = build_deep_clique();

        let famous_r1 = g.hg.famous_witnesses_of_round(1);
        let famous_r2 = g.hg.famous_witnesses_of_round(2);
        assert_eq!(famous_r1.len(), 4);
        assert_eq!(famous_r2.len(), 4);

        let a1 = g.events["a1"];
        let (round, timestamp) = reference_order(&g.hg, &a1).expect("a1 must order");

        // Sanity: this is exactly the "first round whose famous witnesses all
        // see a1".
        assert!(round >= 2);
        assert_eq!(g.hg.round_received(&a1), Some(round));
        assert_eq!(g.hg.consensus_timestamp(&a1), Some(timestamp));

        // The median is the median of the four famous witnesses' first-seen
        // timestamps; in this dense graph all four resolve to a1's own ts.
        let ts = g.hg.get(&a1).unwrap().event().timestamp();
        for witness in &famous_r2 {
            assert_eq!(g.hg.first_seen_timestamp(witness, &a1), Some(ts.get()));
        }
        assert_eq!(g.hg.consensus_timestamp(&a1), Some(ts));
    }

    /// Spec §8 test 2 — even-median case. `a3` is seen by all four round-2
    /// famous witnesses (an even count), so its `consensusTimestamp` is the
    /// median of four first-seen values. The expected value is recomputed
    /// with the documented median definition (average of the two middle
    /// values for even counts) from the exhaustive-walk oracle, then checked
    /// against production; the averaging behavior itself is pinned down
    /// exactly by the `median_definition` unit test below.
    #[test]
    fn even_median_uses_average_of_two_middle_values() {
        let g = build_deep_clique();

        let a3 = g.events["a3"];
        let (round, reference_ts) = reference_order(&g.hg, &a3).expect("a3 must order");
        assert_eq!(round, 2);

        let famous = g.hg.famous_witnesses_of_round(round);
        assert_eq!(famous.len(), 4, "four famous witnesses for an even median");

        let first_seen: Vec<u64> = famous
            .iter()
            .map(|w| {
                let expected =
                    reference_first_seen(&g.hg, w, &a3).expect("every famous witness sees a3");
                let actual = g.hg.first_seen_timestamp(w, &a3).unwrap();
                assert_eq!(actual, expected, "production first-seen must match the oracle");
                actual
            })
            .collect();

        // Even median = average of the two middle values (documented choice).
        let mid = first_seen.len() / 2;
        let expected = (u128::from(first_seen[mid - 1]) + u128::from(first_seen[mid])) / 2;
        assert_eq!(g.hg.consensus_timestamp(&a3), Some(Timestamp::new(expected as u64)));
        assert_eq!(reference_ts, Timestamp::new(expected as u64));
        assert_eq!(g.hg.round_received(&a3), Some(2));
    }

    /// Spec §8 test 3 — an event not seen by all famous witnesses of a round
    /// stays unordered until a round whose famous witnesses all see it.
    /// `a1` is confined to the a/b side of the ring and never gossiped to the
    /// c/d side, so no round's famous-witness set ever uniformly sees it: it
    /// stays `None` even after later rounds are decided.
    #[test]
    fn event_stays_unordered_when_no_round_sees_it() {
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            // a1/b1 are only gossiped into the a/b side; c and d never see them.
            ("a2", "a", Some("a1"), Some("b1")),
            ("b2", "b", Some("b1"), Some("a2")),
            ("a3", "a", Some("a2"), Some("b2")),
            ("b3", "b", Some("b2"), Some("a3")),
            ("a4", "a", Some("a3"), Some("b3")),
            ("d2", "d", Some("d1"), Some("a4")),
            ("c2", "c", Some("c1"), Some("d2")),
            ("a5", "a", Some("a4"), Some("c2")),
            ("b4", "b", Some("b3"), Some("a5")),
            // Later rounds — fully decided — still cannot see a1.
            ("c3", "c", Some("c2"), Some("b4")),
            ("d3", "d", Some("d2"), Some("c3")),
            ("a6", "a", Some("a5"), Some("d3")),
            ("b5", "b", Some("b4"), Some("a6")),
        ]);

        let a1 = g.events["a1"];
        assert_eq!(g.hg.round_received(&a1), None, "a1 must stay unordered");
        assert_eq!(g.hg.consensus_timestamp(&a1), None);
        assert_eq!(reference_order(&g.hg, &a1), None);

        // Sanity: round 1's famous witnesses really do split on a1.
        let famous = g.hg.famous_witnesses_of_round(1);
        let see_a1 = famous.iter().filter(|w| g.hg.see(w, &a1).unwrap()).count();
        assert!(see_a1 < famous.len(), "some famous witness must not see a1");
    }

    /// Spec §8 test 4 — fork dedup. A forking creator's two same-round
    /// witnesses are both `Famous`; per §3.2 only the canonical first-seen
    /// branch participates in `assignOrder`.
    #[test]
    fn forked_witnesses_are_deduplicated_to_the_canonical_branch() {
        let mut g = DynamicGraph::new(&["a", "b"]);
        g.build(&[("a1", "a", None, None), ("a1b", "a", None, None), ("b1", "b", None, None)]);

        let a1 = g.events["a1"];
        let a1b = g.events["a1b"];
        let a_idx = g.hg.member_index_of(&NodeId::new(1)).unwrap();
        assert!(g.hg.creator_has_known_fork(a_idx), "a forked when it created a1 and a1b");
        assert!(g.hg.get(&a1).unwrap().is_witness());
        assert!(g.hg.get(&a1b).unwrap().is_witness());

        // Both branches are same-round witnesses; force both to Famous.
        let creator_a = NodeId::new(1);
        let canonical = g.hg.canonical_child(creator_a, None).expect("a has a first child");
        let non_canonical = if canonical == a1 { a1b } else { a1 };
        assert_ne!(canonical, non_canonical);

        g.hg.mark_for_test_famous(&canonical);
        g.hg.mark_for_test_famous(&non_canonical);

        let famous = g.hg.famous_witnesses_of_round(1);
        assert!(
            famous.contains(&canonical) && !famous.contains(&non_canonical),
            "non-canonical fork branch must be excluded, got {famous:?}"
        );
        assert_eq!(
            famous.iter().filter(|w| g.hg.get(w).unwrap().event().creator() == &creator_a).count(),
            1,
            "exactly one witness from the forking creator participates"
        );
    }

    /// Spec §8 test 5 — exact-timestamp tie. Two events with identical
    /// `roundReceived` and `consensusTimestamp` are ordered by the
    /// signature-XOR fold (ascending), and a repeated call yields the same
    /// order.
    #[test]
    fn exact_timestamp_tie_breaks_by_signature_fold() {
        let mut g = DynamicGraph::new(&["a", "b"]);
        g.build(&[("a1", "a", None, None), ("b1", "b", None, None)]);

        let a1 = g.events["a1"];
        let b1 = g.events["b1"];
        g.hg.set_event_order(&a1, 2, Timestamp::new(5000));
        g.hg.set_event_order(&b1, 2, Timestamp::new(5000));

        let order = g.hg.consensus_order(2);
        assert_eq!(order.len(), 2);
        let (x, y) = (order[0], order[1]);

        let fold_x = signature_tie_break(g.hg.get(&x).unwrap().event().signature());
        let fold_y = signature_tie_break(g.hg.get(&y).unwrap().event().signature());
        assert!(
            fold_x < fold_y || (fold_x == fold_y && x < y),
            "tie must be broken by signature fold ascending"
        );

        assert_eq!(g.hg.consensus_order(2), order, "ordering must be deterministic");
    }

    /// Spec §8 test 6 — end-to-end. A multi-round graph yields a
    /// `consensus_order` that is a valid total order per §4's three keys:
    /// `roundReceived` ascending, then `consensusTimestamp` ascending (within
    /// a round), then signature-fold ascending. Also cross-checks every
    /// event's ordering against the from-scratch reference.
    #[test]
    fn end_to_end_ordering_is_a_valid_total_order() {
        let g = build_deep_clique();

        // Cross-check the incremental machinery against the reference for
        // every event that the reference can order.
        for (label, hash) in &g.events {
            match reference_order(&g.hg, hash) {
                Some((round, ts)) => {
                    assert_eq!(g.hg.round_received(hash), Some(round), "{label}");
                    assert_eq!(g.hg.consensus_timestamp(hash), Some(ts), "{label}");
                }
                None => {
                    assert_eq!(g.hg.round_received(hash), None, "{label}");
                }
            }
        }

        // Walk the rounds that are finalized and validate §4's three keys.
        let mut prev_rr = 0u64;
        let mut prev_ts = Timestamp::new(0);
        let mut prev_fold = 0u64;
        let mut total = 0usize;
        for round in 1..=4 {
            for &h in &g.hg.consensus_order(round) {
                let record = g.hg.get(&h).unwrap();
                let rr = record.round_received().unwrap();
                let ts = record.consensus_timestamp().unwrap();
                assert_eq!(rr, round, "consensus_order must only return events of its round");
                assert!(rr >= prev_rr, "roundReceived must be non-decreasing");
                if rr > prev_rr {
                    prev_ts = Timestamp::new(0);
                    prev_fold = 0;
                }
                assert!(ts >= prev_ts, "consensusTimestamp must be non-decreasing within a round");
                let fold = signature_tie_break(record.event().signature());
                if ts == prev_ts {
                    assert!(fold >= prev_fold, "signature fold must break timestamp ties");
                }
                prev_rr = rr;
                prev_ts = ts;
                prev_fold = fold;
                total += 1;
            }
        }
        assert!(total > 0, "the graph must actually order events");

        // §3.2 dedup never duplicates: one famous witness per creator.
        for round in 1..=2 {
            let famous = g.hg.famous_witnesses_of_round(round);
            let creators: HashSet<NodeId> =
                famous.iter().map(|w| *g.hg.get(w).unwrap().event().creator()).collect();
            assert_eq!(
                creators.len(),
                famous.len(),
                "round {round}: one famous witness per creator"
            );
            assert_eq!(famous.len(), 4);
        }
    }

    /// Unit check of the even-median definition: the two middle values are
    /// averaged (integer division truncates toward zero), and odd-length
    /// lists take the middle value.
    #[test]
    fn median_definition_matches_documented_choice() {
        assert_eq!(median_timestamp(&mut [10, 30, 50]), Timestamp::new(30));
        assert_eq!(median_timestamp(&mut [10, 20, 30, 40]), Timestamp::new(25));
        assert_eq!(median_timestamp(&mut [10, 10, 40, 40]), Timestamp::new(25));
        assert_eq!(median_timestamp(&mut [5]), Timestamp::new(5));
    }

    /// `assign_order` is structurally idempotent: `pending_order_events`
    /// excludes events with `round_received != None`, so a second call on
    /// the same round is a no-op. This documents the property and guards
    /// against refactors that might break it.
    #[test]
    fn assign_order_is_idempotent_on_same_round() {
        let mut g = build_deep_clique();

        // Find the first round that actually has ordered events.
        // Genesis witnesses can't all see each other, so round 1 is
        // typically empty — ordering starts at round 2+.
        let mut ordered_round = 0u64;
        for round in 1..=4 {
            if !g.hg.consensus_order(round).is_empty() {
                ordered_round = round;
                break;
            }
        }
        assert!(ordered_round > 0, "deep clique must have at least one ordered round");

        let first_order = g.hg.consensus_order(ordered_round);

        let first_details: Vec<_> = first_order
            .iter()
            .map(|h| {
                let r = g.hg.get(h).unwrap();
                (*h, r.round_received(), r.consensus_timestamp())
            })
            .collect();

        // Re-assigning the same round is a structural no-op.
        g.hg.assign_order(ordered_round);

        assert_eq!(g.hg.consensus_order(ordered_round), first_order);
        for (hash, rr, ts) in &first_details {
            assert_eq!(g.hg.round_received(hash), *rr);
            assert_eq!(g.hg.consensus_timestamp(hash), *ts);
        }
    }

    /// Events ordered by `assign_order(round)` must not be reordered when
    /// a later round's `assign_order` runs. Regression guard: the
    /// `pending_order_events` filter excludes events with an assigned
    /// `roundReceived`, so earlier-round events are invisible to later
    /// rounds' scans.
    #[test]
    fn already_ordered_events_not_reordered_by_later_assign_order() {
        let mut g = build_deep_clique();

        // Find a round with ordered events.
        let mut ordered_round = 0u64;
        for round in 1..=4 {
            if !g.hg.consensus_order(round).is_empty() {
                ordered_round = round;
                break;
            }
        }
        assert!(ordered_round > 0, "deep clique must have ordered events");

        let round_a_order = g.hg.consensus_order(ordered_round);
        let round_a_details: Vec<_> = round_a_order
            .iter()
            .map(|h| {
                let r = g.hg.get(h).unwrap();
                (*h, r.round_received(), r.consensus_timestamp())
            })
            .collect();

        // Assign a higher round (which may or may not have events).
        // Earlier-round events must be untouched.
        g.hg.assign_order(ordered_round + 1);

        assert_eq!(g.hg.consensus_order(ordered_round), round_a_order);
        for (hash, rr, ts) in &round_a_details {
            assert_eq!(g.hg.round_received(hash), *rr);
            assert_eq!(g.hg.consensus_timestamp(hash), *ts);
        }
    }
}
