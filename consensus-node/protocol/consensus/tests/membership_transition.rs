//! Phase 2 membership transition: one long-running `Hashgraph` crosses from
//! a 3-member to a 4-member roster at an activation round, without a restart.
//!
//! The whole transition runs on a *single* `Hashgraph` instance — there is no
//! `Hashgraph::new` after `add_member` (assertion d). The four assertions:
//!
//! (a) events born before the activation round keep the n=3 quorum
//!     denominator — `member_count_at_round` returns 3 for those rounds;
//! (b) events born after the activation round use the n=4 denominator;
//! (c) inserting events from the newly joined node succeeds, and its
//!     `ancestor_seqs` slot reads `0` on pre-join events (the "no ancestor
//!     from this member" sentinel every quorum site already skips);
//! (d) no `Hashgraph::new` after `add_member`.

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
use rand::rngs::OsRng;

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

#[test]
fn single_hashgraph_crosses_membership_transition() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let key_c = SigningKey::generate(&mut OsRng);
    let node_a = NodeId::new(1);
    let node_b = NodeId::new(2);
    let node_c = NodeId::new(3);
    let initial = registry_of(&[(node_a, &key_a), (node_b, &key_b), (node_c, &key_c)]);

    // One Hashgraph for the entire test (assertion d).
    let mut hg = Hashgraph::new(&initial);

    // Round-1 witnesses plus a little gossip fan-out on the 3-member roster.
    let a1 = hg.insert(verified_event(&initial, &key_a, node_a, None, None, 100)).unwrap();
    let b1 = hg.insert(verified_event(&initial, &key_b, node_b, None, None, 101)).unwrap();
    let c1 = hg.insert(verified_event(&initial, &key_c, node_c, None, None, 102)).unwrap();
    let a2 = hg.insert(verified_event(&initial, &key_a, node_a, Some(a1), Some(b1), 103)).unwrap();
    let b2 = hg.insert(verified_event(&initial, &key_b, node_b, Some(b1), Some(c1), 104)).unwrap();
    let c2 = hg.insert(verified_event(&initial, &key_c, node_c, Some(c1), Some(a2), 105)).unwrap();

    // Pre-join events were born under the 3-member roster.
    assert_eq!(hg.member_count_at_round(1), 3, "(a) round-1 events use n=3");
    assert_eq!(hg.member_count_at_round(2), 3, "(a) rounds at or below activation use n=3");

    // Node 4 joins, activating the expanded roster at round 2.
    let key_d = SigningKey::generate(&mut OsRng);
    let node_d = NodeId::new(4);
    let mut expanded = initial.clone();
    expanded.register(node_d, key_d.verifying_key());
    hg.add_member(node_d, 2, expanded.clone());

    assert_eq!(hg.member_count(), 4);
    assert!(hg.is_member(&node_d));
    assert_eq!(hg.member_count_at_round(2), 3, "(a) activation round keeps n=3");
    assert_eq!(hg.member_count_at_round(3), 4, "(b) rounds above activation use n=4");

    // Node 4's genesis event inserts cleanly and becomes a witness; its row
    // is the backfilled 0 on every pre-join event (assertion c).
    let new_idx = hg.member_index_of(&node_d).unwrap();
    for hash in [a1, b1, c1, a2, b2, c2] {
        assert_eq!(
            hg.get(&hash).unwrap().ancestor_seq(new_idx),
            0,
            "(c) pre-join events carry the no-ancestor sentinel for node 4"
        );
    }
    let d1 = hg.insert(verified_event(&expanded, &key_d, node_d, None, Some(a2), 106)).unwrap();
    assert!(hg.get(&d1).unwrap().is_witness(), "(c) node 4's genesis is a witness");

    // Post-join events from the new member and existing members interleave
    // without panics, and every record keeps the expanded row width.
    let a3 = hg.insert(verified_event(&expanded, &key_a, node_a, Some(a2), Some(d1), 107)).unwrap();
    assert_eq!(hg.get(&a3).unwrap().ancestor_seqs_len(), 4, "(c) post-join rows are width 4");
    assert_eq!(hg.get(&d1).unwrap().ancestor_seqs_len(), 4, "(c) node 4's row is width 4");
    assert!(hg.member_count_at_round(hg.get(&a3).unwrap().round()) >= 3);
}
