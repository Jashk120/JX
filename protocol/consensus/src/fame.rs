//! Consensus Spec §3 / §3.1 — Virtual Voting (determining a witness's fame).
//!
//! The `decideFame(w)` election is reproduced here as an eager, incremental
//! side effect of `Hashgraph::insert`, not a background/batch pass. It runs
//! immediately after `round.rs`'s `finalize_round`, and only when the newly
//! inserted event is a witness — mirroring the `if (!isWitness) return;`
//! short-circuit of Hedera/Hiero's `ConsensusImpl`. Non-witness events never
//! touch this path at all.
//!
//! # Deliberate deviations from Hedera/Hiero's `ConsensusImpl`
//!
//! The architectural shape follows Hiero, but two implementation details are
//! intentionally different at this project's scale:
//!
//! 1. **Votes live on the voter, in a plain `HashMap<EventHash, bool>`**
//!    (see `EventRecord::votes`), keyed by candidate witness hash. Hiero
//!    packs votes into a dense `election_index -> bool[]` array per voter to
//!    avoid allocating a hash map per (round, candidate) — a JVM
//!    object-reuse micro-optimization that costs real complexity here for no
//!    measurable benefit. A plain map is clearer and plenty fast.
//!
//! 2. **Vote computation is memoized and on-demand, not write-once.**
//!    `Hashgraph::insert` only guarantees an event's *own parents* are
//!    present; it does **not** guarantee witnesses arrive in round order. A
//!    straggling round-`r` witness can show up after other members have
//!    already raced ahead to round `r+3`. A voter's vote on a candidate is a
//!    pure function of the voter's own (immutable) ancestry, so votes that
//!    "should" exist are still real even when the candidate arrived late —
//!    they must not be silently dropped.
//!
//!    Two complementary triggers fill every such gap:
//!    - *Eager*: on insertion of a witness `y`, compute `y`'s votes on every
//!      candidate in the undecided working set with a round below `y`'s.
//!    - *On-demand recursion*: when computing `y`'s vote on `w` in the
//!      `r' > r + 1` branch (which reads the votes of round-`(r'-1)`
//!      witnesses `y` strongly sees), a needed voter `s`'s vote is computed
//!      lazily and memoized if it isn't cached — recursing into `s`'s own
//!      prerequisites the same way. `s` is always an ancestor of `y` (guar-
//!      anteed present by `insert`'s parent-existence check), so this never
//!      reaches into unrelated history and terminates at the round-`(r+1)`
//!      can-see layer.
//!    - *Backfill*: on insertion of a candidate `w`, existing witnesses in
//!      rounds above `w`'s have their (previously impossible) votes on `w`
//!      computed too. Without this, a candidate inserted last would stay
//!      `Undecided` forever even though `decideFame` on the fully-built graph
//!      would resolve it.
//!
//!    Coin-round votes need none of this fallback: they are derived purely
//!    from the voter's own signature, so once the election reaches the coin
//!    branch the vote value is immediate regardless of insertion order.
//!
//! # One-member-one-vote, not stake
//!
//! `MembershipRegistry` carries no weights (checked: `protocol/crypto/src/
//! membership.rs`), so witnesses are counted — matching `round.rs`'s
//! `strongly_seen_count * 3 > member_count() * 2` assumption — and the
//! supermajority check uses the exact same `* 3 > * 2` integer idiom to
//! avoid float rounding.
//!
//! # Forking (§3.2) — deferred, by design
//!
//! If a forking creator contributes two witnesses to the same round, both
//! can independently reach a fame decision under this logic. Deduplicating
//! to the canonical branch is **not** done here — that is the ordering
//! task's job (§4), which already owns `first_child` /
//! `creator_has_known_fork` and knows which branch is canonical. Don't "fix"
//! it here or you'll break the ordering task's assumptions.

use primitives::EventHash;

use crate::error::Result;
use crate::hashgraph::{
    FameStatus,
    Hashgraph,
};

/// Consensus Spec §3.1 — coin-round frequency `[DECISION NEEDED]`.
///
/// The original papers suggest "every 10 rounds"; this project follows
/// Hedera/Hiero's current `coinFreq` `ConfigProperty` default of **12**
/// (the requester's explicit choice). The election only terminates via the
/// supermajority path in practice; the coin round is a liveness backstop for
/// adversarial deadlocks, so the exact value is a tuning knob, not a
/// correctness requirement. Tests override it via
/// [`coin_round_frequency`].
pub const COIN_ROUND_FREQUENCY: u64 = 12;

/// Crate-internal accessor for the coin-round frequency, so a `#[cfg(test)]`
/// override can shrink the interval (e.g. to 2) and force the fallback path
/// without constructing a 12-round-deep graph. Production code always gets
/// [`COIN_ROUND_FREQUENCY`].
#[cfg(not(test))]
pub(crate) const fn coin_round_frequency() -> u64 {
    COIN_ROUND_FREQUENCY
}

/// Test-only override slot for [`coin_round_frequency`] (see the docs on
/// the `#[cfg(not(test))]` twin for why it exists). Tests that need a coin
/// round set this, run, and restore it — the whole crate's unit tests share
/// one process, so the restore is not optional.
///
/// # Concurrency
///
/// `cargo test` runs unit tests in parallel threads, and this slot is shared
/// process-wide. Every test in this module therefore takes
/// [`tests::test_serial_guard`] first, so no test can read a frequency that
/// another test is mid-way through overriding. (Constructing a 12-round-deep
/// graph to fire a real coin round at the default frequency was tried and
/// abandoned: the deterministic gossip generators in this suite top out at
/// ~round 4, far short of the needed diff of 12.)
#[cfg(test)]
pub(crate) static COIN_ROUND_FREQUENCY_OVERRIDE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(COIN_ROUND_FREQUENCY);

#[cfg(test)]
pub(crate) fn coin_round_frequency() -> u64 {
    COIN_ROUND_FREQUENCY_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed)
}

/// The deterministic pseudo-random fallback vote used on coin rounds.
///
/// The spec says "middle bit of the witness's signature" `[DECISION NEEDED]`.
/// Here the choice is spelled out as bit 0 of byte 32 of the 64-byte Ed25519
/// signature (`Signature::as_bytes()`): a whole middle *byte* was chosen over
/// a single middle *bit* so the derivation is trivial to inspect and test,
/// then bit 0 of that byte is the vote. Deterministic, unpredictable in
/// advance, and needs no extra communication — exactly the property the spec
/// requires of the fallback.
fn coin_round_vote(hashgraph: &Hashgraph, voter: &EventHash) -> bool {
    let signature = hashgraph
        .get(voter)
        .expect("voter must be present in the hashgraph")
        .event()
        .signature()
        .as_bytes();
    signature[32] & 0x01 == 0x01
}

/// Outcome of a single vote computation. `Cast` means a real vote was
/// computed (and cached); `Decided` means the candidate's fame was finalized
/// during the computation — either because the caller found a supermajority,
/// or because a prerequisite voter did, in which case no vote is recorded
/// (the election is over, so the vote would never be read).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VoteOutcome {
    Cast(bool),
    Decided(FameStatus),
}

impl Hashgraph {
    /// Consensus Spec §3.1 — the per-witness voting step. Called from
    /// `Hashgraph::insert` right after `finalize_round`, only when `y` is a
    /// witness (see the module doc).
    ///
    /// Two passes, both mediated by the memoized [`Hashgraph::vote_of`]:
    ///
    /// 1. *Eager*: `y` casts a vote on every undecided candidate in a round
    ///    below its own. This is the common in-order path.
    /// 2. *Backfill*: every existing witness in a round above `y`'s casts a
    ///    (previously impossible) vote on `y` — the out-of-order / straggler
    ///    path from the module doc. In-order insertions find this empty.
    pub(crate) fn vote_as_witness(&mut self, y: EventHash) -> Result<()> {
        let y_round = self.get(&y).expect("newly inserted witness must be present").round();

        let candidates: Vec<EventHash> = self
            .undecided_witnesses()
            .iter()
            .filter(|&(_, &round)| round < y_round)
            .map(|(&hash, _)| hash)
            .collect();
        for candidate in candidates {
            self.vote_of(&y, &candidate)?;
        }

        for round in (y_round + 1)..=self.highest_witness_round() {
            if self.fame_of(&y).is_some_and(|status| status != FameStatus::Undecided) {
                break;
            }
            let voters = self.witnesses_of_round(round).to_vec();
            for voter in voters {
                self.vote_of(&voter, &y)?;
            }
        }

        Ok(())
    }

    /// Consensus Spec §3.1 — memoized vote of witness `y` on candidate `w`.
    ///
    /// Returns `VoteOutcome::Cast(vote)` once `y`'s vote is known (recording
    /// it on `y`), or `VoteOutcome::Decided` if `w`'s fame was finalized —
    /// possibly by a prerequisite voter reached through the on-demand
    /// recursion, in which case the election ends before `y` ever votes.
    ///
    /// Majority is computed as `yes >= no`; on an exact tie this yields
    /// `true`. This mirrors Hiero's tie handling (`falseVotes <= trueVotes`
    /// resolves to a `true` majority before its coin-round check) and is the
    /// resolution chosen here `[DECISION NEEDED]` — with one member-one-vote
    /// counting, a tie also has no supermajority either way, so it just
    /// carries forward (or coin-votes) rather than deciding.
    fn vote_of(&mut self, y: &EventHash, w: &EventHash) -> Result<VoteOutcome> {
        let (y_round, w_round) = {
            let y_record = self.get(y).ok_or(crate::error::ConsensusError::UnknownEvent(*y))?;
            let w_record = self.get(w).ok_or(crate::error::ConsensusError::UnknownEvent(*w))?;
            (y_record.round(), w_record.round())
        };

        // Defensive: `w` is always a witness candidate here (working-set
        // members and the newly inserted witness), so `None` means the
        // election simply hasn't started/terminated — treat as undecided.
        let w_fame = self.fame_of(w).unwrap_or(FameStatus::Undecided);
        if w_fame != FameStatus::Undecided {
            return Ok(VoteOutcome::Decided(w_fame));
        }
        if let Some(vote) = self.get(y).and_then(|record| record.vote_for(w)) {
            return Ok(VoteOutcome::Cast(vote));
        }

        if y_round == w_round + 1 {
            let vote = self.see(y, w)?;
            self.record_vote(y, w, vote);
            return Ok(VoteOutcome::Cast(vote));
        }

        debug_assert!(y_round > w_round + 1, "candidates are filtered to rounds below the voter");

        // `r' > r + 1`: aggregate the round-`(r'-1)` witnesses `y` strongly
        // sees. Collected into a `Vec` first so the immutable borrow from
        // `witnesses_of_round` / `strongly_see` is released before the
        // recursive `vote_of` needs `&mut self`.
        let below = y_round - 1;
        let strongly_seen: Vec<EventHash> = self
            .witnesses_of_round(below)
            .iter()
            .filter(|s| self.strongly_see(y, s).unwrap_or(false))
            .copied()
            .collect();

        let mut yes = 0usize;
        let mut no = 0usize;
        for s in strongly_seen {
            match self.vote_of(&s, w)? {
                VoteOutcome::Decided(status) => return Ok(VoteOutcome::Decided(status)),
                VoteOutcome::Cast(vote) => {
                    if vote {
                        yes += 1;
                    } else {
                        no += 1;
                    }
                }
            }
        }

        let v = yes >= no;
        let stake = if v { yes } else { no };
        let is_coin_round = (y_round - w_round) % coin_round_frequency() == 0;
        let has_supermajority = stake * 3 > self.member_count() * 2;

        if is_coin_round && !has_supermajority {
            let vote = coin_round_vote(self, y);
            self.record_vote(y, w, vote);
            return Ok(VoteOutcome::Cast(vote));
        }
        if has_supermajority {
            let status = if v { FameStatus::Famous } else { FameStatus::NotFamous };
            self.decide_fame(w, status);
            return Ok(VoteOutcome::Decided(status));
        }

        self.record_vote(y, w, v);
        Ok(VoteOutcome::Cast(v))
    }
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
        EventHash,
        NodeId,
        Timestamp,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;

    /// Serializes all tests in this module against the shared
    /// [`COIN_ROUND_FREQUENCY_OVERRIDE`] slot: `cargo test` runs them in
    /// parallel threads, and a concurrent override would silently change
    /// what the other tests' elections compute. Poisoning is recovered by
    /// design, so one panicking test can't poison the lock for the rest.
    fn test_serial_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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

    /// Declarative dynamic-graph builder, adapted from `round.rs`'s test
    /// module (same idea, same shape). Feeds `(label, author, self_parent,
    /// other_parent)` steps and inserts them in order, returning handles by
    /// label. Assertions are self-checking: `expected_fame` recomputes the
    /// spec's `decideFame` from first principles against the live graph, so
    /// tests prove the incremental machinery matches the spec rather than
    /// hardcoding outcomes.
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

        fn witnesses_of_round(&self, round: u64) -> Vec<EventHash> {
            self.hg.witnesses_of_round(round).to_vec()
        }

        fn round(&self, label: &'static str) -> u64 {
            self.hg.get(&self.events[label]).unwrap().round()
        }

        fn is_witness(&self, label: &'static str) -> bool {
            self.hg.get(&self.events[label]).unwrap().is_witness()
        }
    }

    /// Reference `decideFame(w)` — the spec algorithm evaluated sequentially
    /// and from scratch against the fully-built graph, with no knowledge of
    /// the incremental machinery under test. Uses the same coin-round
    /// frequency accessor as production (so the test-only override applies
    /// to both sides of a coin-round assertion).
    fn reference_decide_fame(hashgraph: &Hashgraph, w: &EventHash) -> FameStatus {
        let r = hashgraph.get(w).expect("candidate must exist").round();
        let highest = hashgraph.highest_witness_round();
        let mut cache: HashMap<(EventHash, EventHash), bool> = HashMap::new();

        for r_prime in (r + 1)..=highest {
            for y in hashgraph.witnesses_of_round(r_prime) {
                if let RefOutcome::Decided(status) = reference_vote(hashgraph, y, w, &mut cache) {
                    return status;
                }
            }
        }
        FameStatus::Undecided
    }

    enum RefOutcome {
        Vote(bool),
        Decided(FameStatus),
    }

    /// Reference vote of one witness on a candidate, matching the spec's
    /// three-branch structure (can-see / majority-aggregate with decision /
    /// coin round). Memoized on `(voter, candidate)` purely for speed — the
    /// result is a pure function of the immutable graph.
    fn reference_vote(
        hashgraph: &Hashgraph,
        y: &EventHash,
        w: &EventHash,
        cache: &mut HashMap<(EventHash, EventHash), bool>,
    ) -> RefOutcome {
        let r_prime = hashgraph.get(y).expect("voter must exist").round();
        let r = hashgraph.get(w).expect("candidate must exist").round();

        if r_prime == r + 1 {
            return RefOutcome::Vote(hashgraph.see(y, w).expect("known events"));
        }

        let strongly_seen: Vec<EventHash> = hashgraph
            .witnesses_of_round(r_prime - 1)
            .iter()
            .filter(|s| hashgraph.strongly_see(y, s).unwrap_or(false))
            .copied()
            .collect();

        let mut yes = 0usize;
        let mut no = 0usize;
        for s in strongly_seen {
            let vote = match cache.get(&(s, *w)) {
                Some(&vote) => vote,
                None => match reference_vote(hashgraph, &s, w, cache) {
                    RefOutcome::Decided(status) => return RefOutcome::Decided(status),
                    RefOutcome::Vote(vote) => {
                        cache.insert((s, *w), vote);
                        vote
                    }
                },
            };
            if vote {
                yes += 1;
            } else {
                no += 1;
            }
        }

        let v = yes >= no;
        let stake = if v { yes } else { no };
        // The spec's own notation is `diff % coinFreq == 0`; the modulo
        // form is kept verbatim rather than `is_multiple_of` (which needs
        // Rust 1.87+, above this crate's declared MSRV of 1.85).
        #[allow(clippy::manual_is_multiple_of)]
        let is_coin_round = (r_prime - r) % coin_round_frequency() == 0;
        let has_supermajority = stake * 3 > hashgraph.member_count() * 2;

        if is_coin_round && !has_supermajority {
            return RefOutcome::Vote(coin_round_vote(hashgraph, y));
        }
        if has_supermajority {
            return RefOutcome::Decided(if v { FameStatus::Famous } else { FameStatus::NotFamous });
        }
        RefOutcome::Vote(v)
    }

    /// The coin-round signature bit, computed the same way production does.
    fn expected_coin_round_vote(hashgraph: &Hashgraph, y: &EventHash) -> bool {
        coin_round_vote(hashgraph, y)
    }

    /// Deterministic gossip-graph generator for the differential test: walks
    /// a fixed number of rounds of ring gossip, so information spreads
    /// through independent member chains (which is what produces strong-see
    /// relations and hence real elections).
    fn generate_ring_gossip_graph(
        member_count: usize,
        rounds_of_gossip: usize,
    ) -> (Hashgraph, Vec<EventHash>) {
        let keys: Vec<SigningKey> =
            (0..member_count).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let nodes: Vec<NodeId> = (0..member_count).map(|i| NodeId::new((i + 1) as u64)).collect();
        let mut registry = MembershipRegistry::new();
        for (node, key) in nodes.iter().zip(&keys) {
            registry.register(*node, key.verifying_key());
        }

        let mut hg = Hashgraph::new(&registry);
        let mut latest: HashMap<NodeId, EventHash> = HashMap::new();
        let mut ts = 0;

        let mut all_hashes: Vec<EventHash> = Vec::new();

        for (i, node) in nodes.iter().enumerate() {
            let ve = verified_event(&registry, &keys[i], *node, None, None, ts);
            ts += 1;
            let h = hg.insert(ve).expect("genesis must insert");
            latest.insert(*node, h);
            all_hashes.push(h);
        }

        // ring gossip: each member's next event references the previous
        // member's latest event; iterate rounds so information fans out.
        for _ in 0..rounds_of_gossip {
            let mut new_latest: HashMap<NodeId, EventHash> = HashMap::new();
            for (i, node) in nodes.iter().enumerate() {
                let self_parent = latest[node];
                let peer = nodes[(i + member_count - 1) % member_count];
                let other_parent = latest[&peer];
                let ve = verified_event(
                    &registry,
                    &keys[i],
                    *node,
                    Some(self_parent),
                    Some(other_parent),
                    ts,
                );
                ts += 1;
                let h = hg.insert(ve).expect("gossip event must insert");
                new_latest.insert(*node, h);
                all_hashes.push(h);
            }
            latest = new_latest;
        }

        (hg, all_hashes)
    }

    /// Every witness's fame from the incremental machinery must match a
    /// from-scratch sequential `decideFame`.
    fn assert_incremental_matches_reference(hg: &Hashgraph, all_hashes: &[EventHash]) {
        for &h in all_hashes {
            let record = hg.get(&h).expect("event must exist");
            if !record.is_witness() {
                continue;
            }
            let expected = reference_decide_fame(hg, &h);
            let actual = hg.fame_of(&h).expect("witness must have a fame status");
            assert_eq!(
                actual,
                expected,
                "incremental fame for witness {h:?} (round {}) diverged from the reference",
                record.round()
            );
        }
    }

    /// Differential test over a spread of generated graphs — the cheap way
    /// to exercise the can-see, majority-carry-forward, coin-round and
    /// not-famous branches across many topologies. Works over small graphs
    /// only; see `generate_ring_gossip_graph`.
    #[test]
    fn incremental_fame_matches_reference_on_generated_graphs() {
        let _guard = test_serial_guard();
        for member_count in 1..=4 {
            for rounds in 1..=4 {
                for _ in 0..4 {
                    let (hg, hashes) = generate_ring_gossip_graph(member_count, rounds);
                    assert_incremental_matches_reference(&hg, &hashes);
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Targeted scenarios
    // ---------------------------------------------------------------------

    /// Spec §3.1 test 1 — the simplest possible FAMOUS case: the round-1
    /// candidate is directly seen by every round-2 witness, and the first
    /// round-3 witness to aggregate finds an immediate supermajority. Only
    /// the `can_see` and `stake * 3 > 2n` branches run — no carry-forward.
    #[test]
    fn famous_via_direct_can_see() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        // Dense gossip: a and b alternate, fanning each genesis out through
        // the ring so that by d2, c2, a5, b4 every member has rich ancestry
        // reaching all four round-1 witnesses. Those four events become the
        // round-2 witnesses; all of them can directly see a1.
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
        ]);

        let a1 = g.events["a1"];
        assert!(g.is_witness("a1"));
        for label in ["d2", "c2", "a5", "b4"] {
            assert!(g.is_witness(label), "{label} must be a round-2 witness");
            assert_eq!(g.round(label), 2);
        }

        // Every round-2 witness can directly see the candidate.
        for label in ["d2", "c2", "a5", "b4"] {
            assert!(g.hg.see(&g.events[label], &a1).unwrap(), "{label} must directly see a1");
        }

        // The round-3 witnesses (c3, d3, a6) aggregate a supermajority of
        // `true`; the reference and the incremental machinery agree.
        g.build(&[
            ("c3", "c", Some("c2"), Some("b4")),
            ("d3", "d", Some("d2"), Some("c3")),
            ("a6", "a", Some("a5"), Some("d3")),
        ]);

        assert_eq!(reference_decide_fame(&g.hg, &a1), FameStatus::Famous);
        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Famous));
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );
    }

    /// Spec §3.1 test 2 — FAMOUS only after majority carry-forward: the
    /// round-1 votes are split 2 yes / 2 no (member b never gossips a1 to
    /// the c/d side), so no round-3 witness can reach a supermajority and
    /// the majority is carried forward; a round-4 witness finally decides.
    /// Exercises the `r' > r + 1` aggregation branch (not just can-see).
    #[test]
    fn famous_after_majority_carry_forward() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        // b's own chain b2/b3 references c1 and d1 only — never a1. The
        // c/d side grows rich ancestry through b2/b3 without ever seeing
        // a1, while the a side (a2..a5) carries a1. a1's votes end up split.
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("b2", "b", Some("b1"), Some("c1")),
            ("b3", "b", Some("b2"), Some("d1")),
            ("d2", "d", Some("d1"), Some("b3")),
            ("c2", "c", Some("c1"), Some("d2")),
            ("d3", "d", Some("d2"), Some("c2")),
            ("c3", "c", Some("c2"), Some("d3")),
            ("a2", "a", Some("a1"), Some("b2")),
            ("a3", "a", Some("a2"), Some("c2")),
            ("a4", "a", Some("a3"), Some("d3")),
            ("b4", "b", Some("b3"), Some("a4")),
            ("a5", "a", Some("a4"), Some("b4")),
        ]);

        let a1 = g.events["a1"];
        assert!(g.is_witness("a1"));

        // Round-2 witnesses: two on the a side (see a1), two on the c/d
        // side (cannot see a1) — a genuine 2-2 split.
        let r2: Vec<EventHash> = g.witnesses_of_round(2);
        assert_eq!(r2.len(), 4, "need four round-2 witnesses for a split vote");
        let mut yes = Vec::new();
        let mut no = Vec::new();
        for y in &r2 {
            if g.hg.see(y, &a1).unwrap() {
                yes.push(*y);
            } else {
                no.push(*y);
            }
        }
        assert_eq!(yes.len(), 2, "two round-2 witnesses must see a1");
        assert_eq!(no.len(), 2, "two round-2 witnesses must not see a1");

        // Round-3 witnesses aggregate the split; the 2-2 split means no
        // supermajority (stake <= 2, 2*3 <= 4*2), so the majority carries.
        g.build(&[
            ("c4", "c", Some("c3"), Some("a5")),
            ("d4", "d", Some("d3"), Some("c4")),
            ("b5", "b", Some("b4"), Some("d4")),
            ("a6", "a", Some("a5"), Some("b5")),
        ]);
        for label in ["c4", "d4", "b5", "a6"] {
            assert_eq!(g.round(label), 3, "{label} should be a round-3 witness");
        }

        // Not decided yet — the split survived the carry-forward round.
        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Undecided));

        // Round-4 witnesses finally aggregate a supermajority of the carried
        // `true` votes and decide a1 FAMOUS.
        g.build(&[("c5", "c", Some("c4"), Some("a6")), ("d5", "d", Some("d4"), Some("c5"))]);

        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Famous));
        assert_eq!(reference_decide_fame(&g.hg, &a1), FameStatus::Famous);
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );
    }

    /// Spec §3.1 test 3 — the `v == false` branch: d1 is never gossiped to
    /// anyone. Every round-2 witness votes `false` (cannot see it), a
    /// round-3 witness aggregates a supermajority of `false`, and d1 is
    /// decided NOT FAMOUS.
    #[test]
    fn witness_seen_by_nobody_is_decided_not_famous() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        // a, b, c form a rich clique; d1 exists but is never referenced.
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("a2", "a", Some("a1"), Some("b1")),
            ("b2", "b", Some("b1"), Some("c1")),
            ("c2", "c", Some("c1"), Some("a2")),
            ("a3", "a", Some("a2"), Some("b2")),
            ("b3", "b", Some("b2"), Some("c2")),
            ("c3", "c", Some("c2"), Some("a3")),
            ("a4", "a", Some("a3"), Some("c3")),
            ("b4", "b", Some("b3"), Some("a4")),
            ("c4", "c", Some("c3"), Some("b4")),
            ("d2", "d", Some("d1"), None),
            // ring gossip drives the clique into rounds 2 and 3
            ("a5", "a", Some("a4"), Some("b4")),
            ("b5", "b", Some("b4"), Some("c4")),
            ("c5", "c", Some("c4"), Some("a5")),
            ("a6", "a", Some("a5"), Some("c5")),
            ("b6", "b", Some("b5"), Some("a6")),
            ("c6", "c", Some("c5"), Some("b6")),
            ("a7", "a", Some("a6"), Some("b6")),
            ("b7", "b", Some("b6"), Some("c6")),
            ("c7", "c", Some("c6"), Some("a7")),
        ]);

        let d1 = g.events["d1"];
        assert!(g.is_witness("d1"));

        // No round-2 or round-3 witness can see d1.
        for round in 2..=3 {
            for y in g.witnesses_of_round(round) {
                assert!(
                    !g.hg.see(&y, &d1).unwrap(),
                    "round-{round} witness must not see the isolated d1"
                );
            }
        }

        assert_eq!(g.hg.fame_of(&d1), Some(FameStatus::NotFamous));
        assert_eq!(reference_decide_fame(&g.hg, &d1), FameStatus::NotFamous);
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );
    }

    /// Spec §3.1 test 4 — single-member edge case (n = 1), mirroring
    /// `round.rs`'s linear-chain test. With one member every witness
    /// strongly-sees the witness below it, so the chain round-bumps and fame
    /// resolves to FAMOUS from round 3 onward — and, critically, the
    /// machinery never panics or loops.
    #[test]
    fn single_member_network_resolves_fame_without_panicking() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a"]);
        g.build(&[
            ("a1", "a", None, None),
            ("a2", "a", Some("a1"), None),
            ("a3", "a", Some("a2"), None),
            ("a4", "a", Some("a3"), None),
            ("a5", "a", Some("a4"), None),
        ]);

        let a1 = g.events["a1"];
        assert_eq!(g.round("a2"), 2, "single-member chain round-bumps (3 > 2 for n=1)");
        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Famous));
        assert_eq!(reference_decide_fame(&g.hg, &a1), FameStatus::Famous);
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );
    }

    /// Spec §3.1 test 5 — out-of-order insertion (the §3a case). Members a,
    /// c and d form a rich gossip clique that produces round-2 and round-3
    /// witnesses, and resolves a1's fame — all *before* the "slow" member
    /// b's round-1 witness b1 is ever inserted. b1 arrives last, with no
    /// descendant witness after it to trigger a re-vote, so its fame must
    /// come out exactly as `decideFame` on the fully-built graph produces
    /// (NOT FAMOUS — nobody can see it) — proving the on-demand/backfill
    /// path doesn't silently drop the votes of witnesses inserted early.
    #[test]
    fn out_of_order_candidate_arrival_matches_reference() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);

        // Build everything except b1. No event may reference b1, and no
        // event from member b may exist yet (b2 would need b1 as its
        // self-parent).
        g.build(&[
            ("a1", "a", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("a2", "a", Some("a1"), Some("d1")),
            ("c2", "c", Some("c1"), Some("a2")),
            ("d2", "d", Some("d1"), Some("c2")),
            ("a3", "a", Some("a2"), Some("c2")),
            ("c3", "c", Some("c2"), Some("d2")),
            ("d3", "d", Some("d2"), Some("a3")),
            ("a4", "a", Some("a3"), Some("d3")),
            ("c4", "c", Some("c3"), Some("a4")),
            ("d4", "d", Some("d3"), Some("c4")),
            ("a5", "a", Some("a4"), Some("c4")),
            ("c5", "c", Some("c4"), Some("d4")),
            ("d5", "d", Some("d4"), Some("a5")),
        ]);

        // Rounds 2 and 3 are already populated before b1 exists.
        assert_eq!(g.witnesses_of_round(2).len(), 3);
        assert_eq!(g.witnesses_of_round(3).len(), 1);
        let a1 = g.events["a1"];
        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Famous));

        // Now the straggler arrives, last, with no descendant after it.
        g.build(&[("b1", "b", None, None)]);

        let b1 = g.events["b1"];
        assert!(g.is_witness("b1"));

        // b1's election must resolve exactly as the fully-built graph would:
        // everyone votes `false` on it, so it is NOT FAMOUS.
        assert_eq!(g.hg.fame_of(&b1), Some(FameStatus::NotFamous));
        assert_eq!(g.hg.fame_of(&b1), Some(reference_decide_fame(&g.hg, &b1)));

        // Pre-existing decisions are untouched by the late arrival.
        assert_eq!(g.hg.fame_of(&a1), Some(FameStatus::Famous));
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );
    }

    /// Spec §3.1 test 6 — forced coin round. `COIN_ROUND_FREQUENCY` is
    /// overridden to 2 (documented in [`coin_round_frequency`]) so a diff of
    /// 2 is a coin round. The split graph gives a1 split round-2 votes, so
    /// round-3 witnesses aggregating them find no supermajority — their
    /// votes must come from the signature-byte fallback, not the majority.
    #[test]
    fn coin_round_uses_signature_fallback_not_majority() {
        let _guard = test_serial_guard();
        let previous = COIN_ROUND_FREQUENCY_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
        COIN_ROUND_FREQUENCY_OVERRIDE.store(2, std::sync::atomic::Ordering::Relaxed);

        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("b2", "b", Some("b1"), Some("c1")),
            ("b3", "b", Some("b2"), Some("d1")),
            ("d2", "d", Some("d1"), Some("b3")),
            ("c2", "c", Some("c1"), Some("d2")),
            ("d3", "d", Some("d2"), Some("c2")),
            ("c3", "c", Some("c2"), Some("d3")),
            ("a2", "a", Some("a1"), Some("b2")),
            ("a3", "a", Some("a2"), Some("c2")),
            ("a4", "a", Some("a3"), Some("d3")),
            ("b4", "b", Some("b3"), Some("a4")),
            ("a5", "a", Some("a4"), Some("b4")),
            ("c4", "c", Some("c3"), Some("a5")),
            ("d4", "d", Some("d3"), Some("c4")),
            ("b5", "b", Some("b4"), Some("d4")),
            ("a6", "a", Some("a5"), Some("b5")),
        ]);

        let a1 = g.events["a1"];
        // Sanity: the split is real — round-2 votes on a1 are 2-2.
        let mut yes = Vec::new();
        let mut no = Vec::new();
        for y in g.witnesses_of_round(2) {
            if g.hg.see(&y, &a1).unwrap() {
                yes.push(y);
            } else {
                no.push(y);
            }
        }
        assert_eq!(yes.len(), 2);
        assert_eq!(no.len(), 2);

        // Reference and incremental must agree (both use the overridden
        // frequency, so both reach the coin-round fallback identically).
        assert_incremental_matches_reference(
            &g.hg,
            &g.events.values().copied().collect::<Vec<_>>(),
        );

        // Round-3 witnesses vote on a1 at diff == 2 (a coin round) with a
        // split strongly-seen set — no supermajority — so their recorded
        // votes must be the signature-bit fallback, not the majority.
        let a1_votes: Vec<(EventHash, bool)> = g
            .witnesses_of_round(3)
            .iter()
            .filter_map(|y| g.hg.get(y).and_then(|r| r.vote_for(&a1).map(|v| (*y, v))))
            .collect();
        assert_eq!(a1_votes.len(), 4, "all four round-3 witnesses vote on a1");
        for (y, vote) in a1_votes {
            assert_eq!(
                vote,
                expected_coin_round_vote(&g.hg, &y),
                "round-3 witness {y:?} must use the signature fallback on a coin round"
            );
        }

        COIN_ROUND_FREQUENCY_OVERRIDE.store(previous, std::sync::atomic::Ordering::Relaxed);
    }

    /// Every witness in the graph must eventually have its fame recorded as
    /// something queryable (no panics / no dropped elections) for a
    /// reasonably deep graph.
    #[test]
    fn all_witnesses_are_queryable_in_a_deep_graph() {
        let _guard = test_serial_guard();
        let (hg, hashes) = generate_ring_gossip_graph(4, 6);
        let all_hashes: HashSet<EventHash> = hashes.into_iter().collect();
        for &h in &all_hashes {
            if hg.get(&h).unwrap().is_witness() {
                assert!(hg.fame_of(&h).is_some(), "every witness must have a fame status");
            }
        }
    }

    /// Unit check of the coin-round fallback bit derivation: bit 0 of byte 32
    /// of the 64-byte signature.
    #[test]
    fn coin_round_vote_bit_is_signature_middle_byte_bit_zero() {
        let _guard = test_serial_guard();
        let key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_of(&[(node, &key)]);
        let mut hg = Hashgraph::new(&registry);

        let event = verified_event(&registry, &key, node, None, None, 100);
        let hash = hg.insert(event).unwrap();
        let signature = hg.get(&hash).unwrap().event().signature().as_bytes();

        assert_eq!(coin_round_vote(&hg, &hash), signature[32] & 0x01 == 0x01);
    }

    /// The fame of a decided witness is immutable: re-running the machinery
    /// (via fresh insertions of later witnesses) never flips it.
    #[test]
    fn decided_fame_is_immutable() {
        let _guard = test_serial_guard();
        let mut g = DynamicGraph::new(&["a", "b", "c", "d"]);
        g.build(&[
            ("a1", "a", None, None),
            ("b1", "b", None, None),
            ("c1", "c", None, None),
            ("d1", "d", None, None),
            ("a2", "a", Some("a1"), Some("b1")),
            ("b2", "b", Some("b1"), Some("a2")),
            ("c2", "c", Some("c1"), Some("b2")),
            ("d2", "d", Some("d1"), Some("c2")),
        ]);

        let a1 = g.events["a1"];
        let before = g.hg.fame_of(&a1).expect("a1 is a witness");

        // A later round of gossip arrives; fame must not flip.
        g.build(&[
            ("a3", "a", Some("a2"), Some("d2")),
            ("b3", "b", Some("b2"), Some("a3")),
            ("c3", "c", Some("c2"), Some("b3")),
            ("d3", "d", Some("d2"), Some("c3")),
        ]);

        assert_eq!(g.hg.fame_of(&a1), Some(before));
    }
}
