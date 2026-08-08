use std::collections::{
    HashMap,
    VecDeque,
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
) -> Result<Vec<Event>> {
    let known_seq: HashMap<NodeId, u64> = known.iter().copied().collect();

    let mut collected: HashMap<EventHash, Event> = HashMap::new();
    for (&creator, &frontier) in &known_seq {
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
        let hash = event.hash();
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
                    registry.register(NodeId::new(id), key.verifying_key());
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
            let event = unsigned.sign(&key);
            let verified = event.clone().verify(&self.registry).expect("signs correctly");
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
        h.make_event(2, Some(g1), None);

        let summary = known_summary(&h.hashgraph, &h.registry);
        let delta = delta_events(&h.hashgraph, &summary).expect("no delta");
        assert!(delta.is_empty());
    }

    #[test]
    fn delta_returns_only_events_above_frontier() {
        let mut h = Harness::new(&[1, 2]);
        let g1 = h.make_event(1, None, None);
        let g2 = h.make_event(1, Some(g1), None);
        let g3 = h.make_event(1, Some(g2), None);

        let known = vec![(NodeId::new(1), 1u64), (NodeId::new(2), 0u64)];
        let delta = delta_events(&h.hashgraph, &known).expect("delta computes");
        let hashes: Vec<_> = delta.iter().map(|e| e.hash()).collect();
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
        let delta = delta_events(&h.hashgraph, &known).expect("delta computes");
        let hashes: Vec<_> = delta.iter().map(|e| e.hash()).collect();

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
        let delta = delta_events(&h.hashgraph, &known).expect("delta computes");

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
            .sign(&key);
        let expected_hash = event.hash();
        assert_eq!(event.verify(&h.registry).map(|v| v.event().hash()), Ok(expected_hash));
    }
}
