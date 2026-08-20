use std::collections::HashSet;

use consensus::Hashgraph;
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
use rand::rngs::StdRng;
use rand::{
    Rng,
    SeedableRng,
};

fn raw_ancestry(hashgraph: &Hashgraph, start: &EventHash) -> Vec<EventHash> {
    let mut visited = HashSet::new();
    let mut stack = vec![*start];

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }

        let event =
            hashgraph.get(&hash).expect("generated graph must contain every parent").event();
        stack.extend(event.self_parent().copied());
        stack.extend(event.other_parent().copied());
    }

    visited.into_iter().collect()
}

/// Deliberately naive reference implementation: walk both raw parent links
/// every time, including the event itself as its own ancestor.
fn brute_force_is_ancestor(hashgraph: &Hashgraph, x: &EventHash, y: &EventHash) -> bool {
    raw_ancestry(hashgraph, x).contains(y)
}

fn brute_force_see(hashgraph: &Hashgraph, x: &EventHash, y: &EventHash) -> bool {
    if !brute_force_is_ancestor(hashgraph, x, y) {
        return false;
    }

    let target_creator = *hashgraph.get(y).expect("generated event must exist").event().creator();
    let ancestry = raw_ancestry(hashgraph, x);
    let target_creator_events: Vec<_> = ancestry
        .iter()
        .filter_map(|hash| hashgraph.get(hash).map(|record| (*hash, record.event())))
        .filter(|(_, event)| *event.creator() == target_creator)
        .collect();

    // Two events by one creator with the same self-parent are the raw-pointer
    // representation of a fork. The observer cannot see the target through
    // an ancestry containing both branches.
    for (index, (_, event)) in target_creator_events.iter().enumerate() {
        for (_, other) in target_creator_events.iter().skip(index + 1) {
            if event.self_parent() == other.self_parent() {
                return false;
            }
        }
    }

    true
}

/// Recompute strong seeing from scratch: x must see y, and a strict
/// two-thirds of the explicitly supplied members must have an event in x's
/// raw ancestry that sees y.
fn brute_force_strongly_see(
    hashgraph: &Hashgraph,
    members: &[NodeId],
    x: &EventHash,
    y: &EventHash,
) -> bool {
    if !brute_force_see(hashgraph, x, y) {
        return false;
    }

    let ancestry = raw_ancestry(hashgraph, x);
    let seeing_members = members
        .iter()
        .filter(|member| {
            ancestry.iter().any(|candidate| {
                hashgraph.get(candidate).is_some_and(|record| record.event().creator() == *member)
                    && brute_force_see(hashgraph, candidate, y)
            })
        })
        .count();

    seeing_members * 3 > members.len() * 2
}

struct GeneratedGraph {
    hashgraph: Hashgraph,
    members: Vec<NodeId>,
    events: Vec<(EventHash, NodeId, Option<EventHash>, Option<EventHash>)>,
}

struct GraphBuilder {
    hashgraph: Hashgraph,
    registry: MembershipRegistry,
    members: Vec<NodeId>,
    keys: Vec<SigningKey>,
    latest_by_member: Vec<Option<EventHash>>,
    events: Vec<(EventHash, NodeId, Option<EventHash>, Option<EventHash>)>,
    timestamp: u64,
}

impl GraphBuilder {
    fn insert(
        &mut self,
        creator_index: usize,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
    ) {
        let creator = self.members[creator_index];
        let event = UnsignedEvent::new(
            creator,
            self_parent,
            other_parent,
            Timestamp::new(self.timestamp),
            Vec::new(),
        )
        .sign(&self.keys[creator_index]);
        let verified = event.verify(&self.registry).expect("generated event must verify");
        let hash = self.hashgraph.insert(verified).expect("generated graph must insert");
        self.events.push((hash, creator, self_parent, other_parent));
        self.latest_by_member[creator_index] = Some(hash);
        self.timestamp += 1;
    }
}

fn generate_graph(seed: u64, include_fork: bool) -> GeneratedGraph {
    let mut rng = StdRng::seed_from_u64(seed);
    let member_count = rng.gen_range(2..=4);
    let event_count = rng.gen_range(5..=8).max(member_count + usize::from(include_fork) * 2);
    let members: Vec<_> = (0..member_count).map(|id| NodeId::new(id as u64 + 1)).collect();
    let keys: Vec<_> = (0..member_count).map(|_| SigningKey::generate(&mut rng)).collect();

    let mut registry = MembershipRegistry::new();
    for (member, key) in members.iter().zip(&keys) {
        registry.register(*member, key.verifying_key());
    }
    let mut builder = GraphBuilder {
        hashgraph: Hashgraph::new(&registry),
        registry,
        members,
        keys,
        latest_by_member: vec![None; member_count],
        events: Vec::new(),
        timestamp: 0,
    };

    for creator_index in 0..member_count {
        builder.insert(creator_index, None, None);
    }

    if include_fork {
        let fork_parent = builder.latest_by_member[0];
        let other_parent = builder.events[rng.gen_range(0..builder.events.len())].0;
        builder.insert(0, fork_parent, Some(other_parent));
    }

    while builder.events.len() < event_count {
        let creator_index = rng.gen_range(0..member_count);
        let self_parent = builder.latest_by_member[creator_index];
        let other_parent =
            rng.gen_bool(0.75).then(|| builder.events[rng.gen_range(0..builder.events.len())].0);
        builder.insert(creator_index, self_parent, other_parent);
    }

    GeneratedGraph {
        hashgraph: builder.hashgraph,
        members: builder.members,
        events: builder.events,
    }
}

#[test]
fn incremental_ancestry_matches_brute_force_reference() {
    const FIRST_SEED: u64 = 0x5eed_2026;
    const GRAPH_COUNT: u64 = 32;

    for graph_index in 0..GRAPH_COUNT {
        let seed = FIRST_SEED + graph_index;
        let graph = generate_graph(seed, graph_index == 0);
        let hashes: Vec<_> = graph.events.iter().map(|(hash, ..)| *hash).collect();

        for x in &hashes {
            for y in &hashes {
                let expected_see = brute_force_see(&graph.hashgraph, x, y);
                let actual_see = graph.hashgraph.see(x, y).expect("event pair must be known");
                let expected_strong =
                    brute_force_strongly_see(&graph.hashgraph, &graph.members, x, y);
                let actual_strong =
                    graph.hashgraph.strongly_see(x, y).expect("event pair must be known");

                if actual_see != expected_see || actual_strong != expected_strong {
                    eprintln!("seed: {seed}");
                    eprintln!("graph index: {graph_index}");
                    eprintln!("events:");
                    for (hash, creator, self_parent, other_parent) in &graph.events {
                        eprintln!(
                            "  {hash:?}: creator={creator:?}, self_parent={self_parent:?}, other_parent={other_parent:?}"
                        );
                    }
                    eprintln!("pair: x={x:?}, y={y:?}");
                    eprintln!("see: expected={expected_see}, actual={actual_see}");
                    eprintln!("strongly_see: expected={expected_strong}, actual={actual_strong}");
                    panic!("ancestry implementation differs from brute-force reference");
                }
            }
        }
    }
}

#[test]
fn fork_branch_selected_from_observers_ancestry_can_strongly_see() {
    let members = vec![NodeId::new(1), NodeId::new(2)];
    let keys = vec![SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    let mut registry = MembershipRegistry::new();
    for (member, key) in members.iter().zip(&keys) {
        registry.register(*member, key.verifying_key());
    }
    let member_count = members.len();

    let mut builder = GraphBuilder {
        hashgraph: Hashgraph::new(&registry),
        registry,
        members,
        keys,
        latest_by_member: vec![None; member_count],
        events: Vec::new(),
        timestamp: 0,
    };

    builder.insert(0, None, None);
    builder.insert(1, None, None);

    let fork_parent = builder.latest_by_member[0].expect("creator 1 genesis must exist");
    let other_parent = builder.latest_by_member[1];
    builder.insert(0, Some(fork_parent), other_parent);
    builder.insert(0, Some(fork_parent), other_parent);
    let y = builder.events.last().expect("event was just inserted").0;
    let b1_parent = builder.latest_by_member[1].expect("creator 2 genesis must exist");
    builder.insert(1, Some(b1_parent), Some(y));
    let b1 = builder.events.last().expect("event was just inserted").0;
    builder.insert(1, Some(b1), Some(y));
    let x = builder.events.last().expect("event was just inserted").0;

    assert!(builder.hashgraph.strongly_see(&x, &y).expect("events must be known"));
}
