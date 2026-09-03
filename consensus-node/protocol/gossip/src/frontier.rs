use std::collections::{
    HashMap,
    VecDeque,
};
use std::time::{
    Duration,
    Instant,
};

use crypto::{
    Hashable,
    MembershipRegistry,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
};

use crate::error::{
    GossipError,
    Result,
};

#[derive(Clone, Debug)]
pub struct SyncConfig {
    pub filter_likely_duplicates: bool,
    pub non_ancestor_threshold: Duration,
    pub ancestor_threshold: Duration,
    pub self_threshold: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            filter_likely_duplicates: true,
            non_ancestor_threshold: Duration::from_millis(3000),
            ancestor_threshold: Duration::from_millis(250),
            self_threshold: Duration::from_millis(1000),
        }
    }
}

#[derive(Default)]
pub struct DedupState {
    sent: std::collections::HashMap<
        (primitives::EventHash, primitives::NodeId),
        (Instant, bool, bool),
    >,
}

impl DedupState {
    pub fn should_filter(
        &mut self,
        hash: &primitives::EventHash,
        target_peer: primitives::NodeId,
        is_self: bool,
        is_ancestor: bool,
        config: &SyncConfig,
    ) -> bool {
        if !config.filter_likely_duplicates {
            return false;
        }
        let now = Instant::now();
        let key = (*hash, target_peer);
        if let Some((sent_at, prev_self, prev_ancestor)) = self.sent.get(&key) {
            let elapsed = now.duration_since(*sent_at);
            let threshold = if is_self || *prev_self {
                config.self_threshold
            } else if is_ancestor || *prev_ancestor {
                config.ancestor_threshold
            } else {
                config.non_ancestor_threshold
            };
            if elapsed < threshold {
                return true;
            }
        }
        self.sent.insert(key, (now, is_self, is_ancestor));
        false
    }

    pub fn prune_expired(&mut self, config: &SyncConfig) {
        let now = Instant::now();
        let max =
            config.non_ancestor_threshold.max(config.ancestor_threshold).max(config.self_threshold);
        // Prune at max_threshold + slack (1000ms) — 4000ms with defaults.
        let prune_after = max + Duration::from_millis(1000);
        self.sent.retain(|_, (t, _, _)| now.duration_since(*t) < prune_after);
    }
}

/// Builds the per-creator "highest seq I hold" summary that a sync request
/// carries (Consensus Spec §5). Uses `Hashgraph::latest_event_by`, so it is
/// O(members) with no graph scan.
pub fn known_summary(
    hashgraph: &consensus::Hashgraph,
    registry: &MembershipRegistry,
) -> Vec<(NodeId, u64)> {
    registry
        .member_ids()
        .into_iter()
        .map(|node| {
            let seq = hashgraph
                .latest_event_by(&node)
                .and_then(|h| hashgraph.get(h))
                .map_or(0, |record| record.seq());
            (node, seq)
        })
        .collect()
}

/// Computes the events the requester (whose summary is `known`) lacks: for
/// each creator, every event above the creator's known seq, collected by
/// walking the creator's `self_parent` chain from its latest event back
/// down to the known frontier. The union is then topologically sorted
/// (Kahn's algorithm, edges from both parents) so a receiver inserting in
/// order never hits `MissingParent`.
pub fn delta_events(
    hashgraph: &consensus::Hashgraph,
    known: &[(NodeId, u64)],
    registry: &MembershipRegistry,
) -> Result<Vec<Event>> {
    let known_seq: HashMap<NodeId, u64> = known.iter().copied().collect();
    let mut creators: std::collections::HashSet<NodeId> =
        registry.member_ids().into_iter().collect();
    for k in known_seq.keys() {
        creators.insert(*k);
    }

    let mut collected: HashMap<EventHash, Event> = HashMap::new();
    for creator in creators {
        let frontier = known_seq.get(&creator).copied().unwrap_or(0);
        let mut cursor = hashgraph.latest_event_by(&creator).copied();
        while let Some(hash) = cursor {
            let record = hashgraph.get(&hash).ok_or_else(|| {
                GossipError::Sync(format!("latest event {hash:?} missing from graph"))
            })?;
            if record.seq() <= frontier {
                break;
            }
            collected.insert(hash, record.event().clone());
            cursor = record.event().self_parent().copied();
        }
    }

    topo_sort(&collected)
}

pub fn delta_events_filtered(
    hashgraph: &consensus::Hashgraph,
    known: &[(NodeId, u64)],
    registry: &MembershipRegistry,
    self_id: NodeId,
    target_peer: NodeId,
    dedup: &mut DedupState,
    config: &SyncConfig,
) -> Result<Vec<Event>> {
    let events = delta_events(hashgraph, known, registry)?;
    if !config.filter_likely_duplicates {
        return Ok(events);
    }
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        let is_self = *event.creator() == self_id;
        let hash = event.hash().expect("hash bounded");
        let is_ancestor = if is_self {
            false
        } else {
            hashgraph
                .latest_event_by(&self_id)
                .and_then(|latest| hashgraph.is_ancestor(&hash, latest).ok())
                .unwrap_or(false)
        };
        if !dedup.should_filter(&hash, target_peer, is_self, is_ancestor, config) {
            out.push(event);
        }
    }
    dedup.prune_expired(config);
    Ok(out)
}

/// Kahn's algorithm over the collected delta. Dependency edges are an
/// event's parents, but only when those parents are also part of the delta
/// — a parent outside the delta is already known to the receiver.
fn topo_sort(events: &HashMap<EventHash, Event>) -> Result<Vec<Event>> {
    let mut indegree: HashMap<EventHash, usize> = HashMap::with_capacity(events.len());
    let mut children: HashMap<EventHash, Vec<EventHash>> = HashMap::with_capacity(events.len());

    for hash in events.keys() {
        indegree.entry(*hash).or_insert(0);
        children.entry(*hash).or_default();
    }
    for event in events.values() {
        let hash = event.hash().expect("hash bounded");
        for parent in [event.self_parent(), event.other_parent()].into_iter().flatten() {
            if events.contains_key(parent) {
                children.entry(*parent).or_default().push(hash);
                *indegree.entry(hash).or_default() += 1;
            }
        }
    }

    let mut queue: VecDeque<EventHash> =
        indegree.iter().filter(|(_, degree)| **degree == 0).map(|(&hash, _)| hash).collect();

    let mut ordered = Vec::with_capacity(events.len());
    while let Some(hash) = queue.pop_front() {
        ordered.push(hash);
        for &child in &children[&hash] {
            let degree = indegree.get_mut(&child).expect("child is in the delta");
            *degree -= 1;
            if *degree == 0 {
                queue.push_back(child);
            }
        }
    }

    if ordered.len() != events.len() {
        return Err(GossipError::Sync(format!(
            "delta contains a cycle or dangling parent ({}/{} emitted)",
            ordered.len(),
            events.len()
        )));
    }

    Ok(ordered.into_iter().map(|hash| events[&hash].clone()).collect())
}

#[cfg(test)]
mod tests {
    use crypto::{
        Signable,
        Verifiable,
    };
    use ed25519_dalek::SigningKey;
    use primitives::{
        Timestamp,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;

    /// A minimal test harness: three creators gossip into a shared registry
    /// and hashgraph so we can build real deltas without networking.
    struct Harness {
        hashgraph: consensus::Hashgraph,
        registry: MembershipRegistry,
        keys: HashMap<NodeId, SigningKey>,
    }

    impl Harness {
        fn new(ids: &[u64]) -> Self {
            let mut registry = MembershipRegistry::new();
            let keys: HashMap<NodeId, SigningKey> = ids
                .iter()
                .map(|&id| {
                    let key = SigningKey::generate(&mut OsRng);
                    registry.register(
                        NodeId::new(id),
                        key.verifying_key(),
                        crypto::BlsIdentity::from_ikm(&[id as u8; 32])
                            .expect("bls")
                            .public
                            .to_bytes(),
                    );
                    (NodeId::new(id), key)
                })
                .collect();
            let hashgraph = consensus::Hashgraph::new(&registry);
            Self { hashgraph, registry, keys }
        }

        /// Creates and inserts an event with the given parents for `creator`,
        /// signing with the harness's key for that creator.
        fn make_event(
            &mut self,
            creator: u64,
            self_parent: Option<EventHash>,
            other_parent: Option<EventHash>,
        ) -> EventHash {
            let key = self.keys[&NodeId::new(creator)].clone();
            let unsigned = UnsignedEvent::new(
                NodeId::new(creator),
                self_parent,
                other_parent,
                Timestamp::new(1),
                Vec::new(),
            );
            let event = unsigned.sign(&key).expect("sign bounded");
            let verified = event.verify(&self.registry).expect("signs correctly");
            self.hashgraph.insert(verified).expect("inserts")
        }
    }

    fn key_for(harness: &Harness, creator: u64) -> ed25519_dalek::SigningKey {
        harness.keys[&NodeId::new(creator)].clone()
    }

    #[test]
    fn known_summary_reports_latest_seq_per_creator() {
        let mut h = Harness::new(&[1, 2]);
        let g1 = h.make_event(1, None, None);
        h.make_event(1, Some(g1), None);
        h.make_event(2, None, None);

        let summary = known_summary(&h.hashgraph, &h.registry);
        assert_eq!(summary, vec![(NodeId::new(1), 2), (NodeId::new(2), 1)]);
    }

    #[test]
    fn delta_empty_when_peer_knows_everything() {
        let mut h = Harness::new(&[1, 2]);
        let g1 = h.make_event(1, None, None);
        h.make_event(2, None, Some(g1));

        let summary = known_summary(&h.hashgraph, &h.registry);
        let delta = delta_events(&h.hashgraph, &summary, &h.registry).expect("no delta");
        assert!(delta.is_empty());
    }

    #[test]
    fn delta_returns_only_events_above_frontier() {
        let mut h = Harness::new(&[1, 2]);
        let g1 = h.make_event(1, None, None);
        let g2 = h.make_event(1, Some(g1), None);
        let g3 = h.make_event(1, Some(g2), None);

        let known = vec![(NodeId::new(1), 1u64), (NodeId::new(2), 0u64)];
        let delta = delta_events(&h.hashgraph, &known, &h.registry).expect("delta computes");
        let hashes: Vec<_> = delta.iter().map(|e| e.hash().expect("hash bounded")).collect();
        assert_eq!(hashes, vec![g2, g3]);
    }

    #[test]
    fn delta_is_parents_first_across_creators() {
        // A's latest event is the other_parent of B's latest event, so B's
        // event must not appear before A's in the delta.
        let mut h = Harness::new(&[1, 2]);
        let a1 = h.make_event(1, None, None);
        let a2 = h.make_event(1, Some(a1), None);
        let b1 = h.make_event(2, None, Some(a2));

        let known = vec![(NodeId::new(1), 0u64), (NodeId::new(2), 0u64)];
        let delta = delta_events(&h.hashgraph, &known, &h.registry).expect("delta computes");
        let hashes: Vec<_> = delta.iter().map(|e| e.hash().expect("hash bounded")).collect();

        let pos_a1 = hashes.iter().position(|&h| h == a1).unwrap();
        let pos_a2 = hashes.iter().position(|&h| h == a2).unwrap();
        let pos_b1 = hashes.iter().position(|&h| h == b1).unwrap();
        assert!(pos_a1 < pos_a2, "self_parent chain ordered");
        assert!(pos_a2 < pos_b1, "other_parent precedes its child");
    }

    #[test]
    fn delta_events_inserts_cleanly_in_order() {
        let mut h = Harness::new(&[1, 2]);
        let a1 = h.make_event(1, None, None);
        let a2 = h.make_event(1, Some(a1), None);
        h.make_event(2, None, Some(a2));

        let known = vec![(NodeId::new(1), 0u64), (NodeId::new(2), 0u64)];
        let delta = delta_events(&h.hashgraph, &known, &h.registry).expect("delta computes");

        // Insert the delta into a fresh hashgraph; every insert must succeed
        // (parents present) because the delta is topologically ordered.
        let mut fresh = consensus::Hashgraph::new(&h.registry);
        for event in &delta {
            let verified = event.clone().verify(&h.registry).expect("valid signature");
            fresh.insert(verified).expect("parents-first insert");
        }
    }

    #[test]
    fn signature_round_trip_uses_creator_key() {
        let h = Harness::new(&[1]);
        let key = key_for(&h, 1);
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), Vec::new())
            .sign(&key)
            .expect("sign bounded");
        let expected_hash = event.hash().expect("hash bounded");
        assert_eq!(
            event.verify(&h.registry).map(|v| v.event().hash().expect("hash bounded")),
            Ok(expected_hash)
        );
    }

    #[test]
    fn delta_includes_unknown_creator_from_responder_union() {
        let mut h = Harness::new(&[1, 2, 3]);
        let a1 = h.make_event(1, None, None);
        let b1 = h.make_event(2, None, Some(a1));
        let c1 = h.make_event(3, None, Some(b1));
        let c2 = h.make_event(3, Some(c1), Some(a1));
        let known = vec![(NodeId::new(1), 1u64), (NodeId::new(2), 1u64)];
        let delta = delta_events(&h.hashgraph, &known, &h.registry).expect("delta computes");
        let hashes: Vec<_> = delta.iter().map(|e| e.hash().expect("hash bounded")).collect();
        assert!(hashes.contains(&c1), "union must include unknown creator 3 events");
        assert!(
            hashes.contains(&c2),
            "union must include all events above frontier for unknown creator"
        );
    }

    #[test]
    fn delta_union_still_empty_when_all_known() {
        let mut h = Harness::new(&[1, 2]);
        let a1 = h.make_event(1, None, None);
        h.make_event(2, None, Some(a1));
        let summary = known_summary(&h.hashgraph, &h.registry);
        let delta = delta_events(&h.hashgraph, &summary, &h.registry).expect("delta");
        assert!(delta.is_empty(), "fully known should still be empty with union");
    }

    #[test]
    fn dedup_filter_disabled_never_filters() {
        let mut dedup = DedupState::default();
        let config = SyncConfig { filter_likely_duplicates: false, ..Default::default() };
        let hash = primitives::EventHash::new([1u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
        assert!(!dedup.should_filter(&hash, peer, false, true, &config));
    }

    #[test]
    fn dedup_self_threshold_filters_within_window() {
        let mut dedup = DedupState::default();
        let config = SyncConfig {
            filter_likely_duplicates: true,
            self_threshold: Duration::from_millis(50),
            ancestor_threshold: Duration::from_millis(25),
            non_ancestor_threshold: Duration::from_millis(100),
        };
        let hash = primitives::EventHash::new([2u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
        assert!(dedup.should_filter(&hash, peer, true, false, &config));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
    }

    #[test]
    fn dedup_ancestor_threshold_shorter_than_self() {
        let mut dedup = DedupState::default();
        let config = SyncConfig {
            filter_likely_duplicates: true,
            self_threshold: Duration::from_millis(100),
            ancestor_threshold: Duration::from_millis(30),
            non_ancestor_threshold: Duration::from_millis(200),
        };
        let hash = primitives::EventHash::new([3u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, false, true, &config));
        assert!(dedup.should_filter(&hash, peer, false, true, &config));
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            !dedup.should_filter(&hash, peer, false, true, &config),
            "ancestor threshold expired"
        );
    }

    #[test]
    fn dedup_non_ancestor_threshold_longest() {
        let mut dedup = DedupState::default();
        let config = SyncConfig {
            filter_likely_duplicates: true,
            self_threshold: Duration::from_millis(30),
            ancestor_threshold: Duration::from_millis(20),
            non_ancestor_threshold: Duration::from_millis(80),
        };
        let hash = primitives::EventHash::new([4u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, false, false, &config));
        assert!(dedup.should_filter(&hash, peer, false, false, &config));
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            dedup.should_filter(&hash, peer, false, false, &config),
            "non-ancestor threshold still active after 40ms"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(!dedup.should_filter(&hash, peer, false, false, &config));
    }

    #[test]
    fn dedup_prev_self_upgrades_threshold() {
        let mut dedup = DedupState::default();
        let config = SyncConfig {
            filter_likely_duplicates: true,
            self_threshold: Duration::from_millis(100),
            ancestor_threshold: Duration::from_millis(20),
            non_ancestor_threshold: Duration::from_millis(200),
        };
        let hash = primitives::EventHash::new([5u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
        assert!(
            dedup.should_filter(&hash, peer, false, false, &config),
            "prev_self flag must keep self_threshold"
        );
        assert!(
            dedup.should_filter(&hash, peer, false, true, &config),
            "prev_self flag dominates ancestor flag too"
        );
    }

    #[test]
    fn dedup_prev_ancestor_upgrades_threshold() {
        let mut dedup = DedupState::default();
        let config = SyncConfig {
            filter_likely_duplicates: true,
            self_threshold: Duration::from_millis(100),
            ancestor_threshold: Duration::from_millis(80),
            non_ancestor_threshold: Duration::from_millis(200),
        };
        let hash = primitives::EventHash::new([6u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, false, true, &config));
        assert!(
            dedup.should_filter(&hash, peer, false, false, &config),
            "prev_ancestor flag must keep ancestor_threshold"
        );
    }

    #[test]
    fn dedup_threshold_branching_self_dominates() {
        let mut dedup = DedupState::default();
        let config = SyncConfig::default();
        assert_eq!(config.self_threshold, Duration::from_millis(1000));
        assert_eq!(config.ancestor_threshold, Duration::from_millis(250));
        assert_eq!(config.non_ancestor_threshold, Duration::from_millis(3000));
        let hash = primitives::EventHash::new([7u8; 32]);
        let peer = NodeId::new(10);
        assert!(!dedup.should_filter(&hash, peer, true, false, &config));
        assert!(dedup.should_filter(&hash, peer, true, true, &config));
        assert!(dedup.should_filter(&hash, peer, false, true, &config));
    }

    #[test]
    fn delta_filtered_uses_dedup_and_prunes() {
        let mut h = Harness::new(&[1, 2]);
        let a1 = h.make_event(1, None, None);
        let a2 = h.make_event(1, Some(a1), None);
        let known = vec![(NodeId::new(1), 0u64), (NodeId::new(2), 0u64)];
        let mut dedup = DedupState::default();
        let config = SyncConfig::default();
        let peer = NodeId::new(10);
        let first = delta_events_filtered(
            &h.hashgraph,
            &known,
            &h.registry,
            NodeId::new(1),
            peer,
            &mut dedup,
            &config,
        )
        .expect("filtered delta");
        assert_eq!(first.len(), 2);
        let second = delta_events_filtered(
            &h.hashgraph,
            &known,
            &h.registry,
            NodeId::new(1),
            peer,
            &mut dedup,
            &config,
        )
        .expect("second filtered delta");
        assert!(second.is_empty(), "second call within dedup window should filter all");
        let all = delta_events(&h.hashgraph, &known, &h.registry).expect("unfiltered");
        assert!(all.iter().any(|e| e.hash().expect("hash bounded") == a2));
    }

    #[test]
    fn dedup_per_peer_isolation() {
        let mut dedup = DedupState::default();
        let config = SyncConfig::default();
        let hash = primitives::EventHash::new([8u8; 32]);
        let peer_a = NodeId::new(10);
        let peer_b = NodeId::new(11);
        assert!(!dedup.should_filter(&hash, peer_a, false, false, &config));
        assert!(dedup.should_filter(&hash, peer_a, false, false, &config));
        assert!(
            !dedup.should_filter(&hash, peer_b, false, false, &config),
            "different peer must not be filtered"
        );
        assert!(dedup.should_filter(&hash, peer_b, false, false, &config));
        assert!(dedup.should_filter(&hash, peer_a, false, false, &config));
    }

    #[test]
    fn delta_filtered_per_peer_isolation() {
        let mut h = Harness::new(&[1, 2]);
        let a1 = h.make_event(1, None, None);
        let _a2 = h.make_event(1, Some(a1), None);
        let known = vec![(NodeId::new(1), 0u64), (NodeId::new(2), 0u64)];
        let mut dedup = DedupState::default();
        let config = SyncConfig::default();
        let peer_a = NodeId::new(10);
        let peer_b = NodeId::new(11);
        let first_a = delta_events_filtered(
            &h.hashgraph,
            &known,
            &h.registry,
            NodeId::new(1),
            peer_a,
            &mut dedup,
            &config,
        )
        .expect("first peer_a");
        assert_eq!(first_a.len(), 2);
        let first_b = delta_events_filtered(
            &h.hashgraph,
            &known,
            &h.registry,
            NodeId::new(1),
            peer_b,
            &mut dedup,
            &config,
        )
        .expect("first peer_b should not be filtered");
        assert_eq!(first_b.len(), 2, "different peer must receive same delta");
        let second_a = delta_events_filtered(
            &h.hashgraph,
            &known,
            &h.registry,
            NodeId::new(1),
            peer_a,
            &mut dedup,
            &config,
        )
        .expect("second peer_a");
        assert!(second_a.is_empty(), "peer_a second call filtered");
    }
}
