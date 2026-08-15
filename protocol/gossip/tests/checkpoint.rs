//! Phase 3 integration tests over the gossip layer.
//!
//! 1. A node's checkpoint for a decided round is accepted only once the
//!    collected signatures exceed 2/3 of the roster active at that round.
//! 2. Pruning old ordered history below a confirmed checkpoint round leaves
//!    the consensus order of later rounds untouched and still admits inserts
//!    at the frontier.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use consensus::{
    CheckpointAccumulator,
    CheckpointPayload,
    encode_roster_history,
};
use crypto::{
    Hashable,
    MembershipRegistry,
    RosterHistory,
    Signable,
    Verifiable,
};
use ed25519_dalek::{
    Signer,
    SigningKey,
};
use gossip::{
    GossipNode,
    ReconnectResponse,
    SyncTiming,
    TlsIdentity,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
    Timestamp,
    UnsignedEvent,
};

fn registry_for_ids(ids: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in ids {
        registry
            .register(NodeId::new(id), SigningKey::from_bytes(&consensus_seed(id)).verifying_key());
    }
    registry
}

/// Signs the node's checkpoint signing bytes for `round` with `signer`'s key.
fn checkpoint_sig_for(
    signer: u64,
    round: u64,
    signing_bytes: &[u8; 72],
) -> consensus::CheckpointSig {
    let key = SigningKey::from_bytes(&consensus_seed(signer));
    let signature = key.sign(signing_bytes);
    consensus::CheckpointSig {
        round,
        signer: NodeId::new(signer),
        sig: primitives::Signature::new(signature.to_bytes()),
    }
}

/// The deterministic 4-member deep clique from `consensus`'s `order.rs`:
/// rounds 1-2 finalize, so a node holding it can produce checkpoints for
/// round 1.
fn build_deep_clique() -> Vec<Event> {
    let mut events = HashMap::new();
    let mut out = Vec::new();
    let mut ts = 100u64;
    let mut step = |label: &'static str,
                    author: u64,
                    self_parent: Option<&'static str>,
                    other_parent: Option<&'static str>| {
        let self_parent = self_parent.map(|label| events[label]);
        let other_parent = other_parent.map(|label| events[label]);
        let event = UnsignedEvent::new(
            NodeId::new(author),
            self_parent,
            other_parent,
            Timestamp::new(ts),
            Vec::new(),
        )
        .sign(&SigningKey::from_bytes(&consensus_seed(author)));
        ts += 1;
        events.insert(label, event.hash());
        out.push(event);
    };
    step("a1", 1, None, None);
    step("b1", 2, None, None);
    step("c1", 3, None, None);
    step("d1", 4, None, None);
    step("a2", 1, Some("a1"), Some("d1"));
    step("b2", 2, Some("b1"), Some("a2"));
    step("a3", 1, Some("a2"), Some("b2"));
    step("b3", 2, Some("b2"), Some("c1"));
    step("a4", 1, Some("a3"), Some("b3"));
    step("d2", 4, Some("d1"), Some("a4"));
    step("c2", 3, Some("c1"), Some("d2"));
    step("a5", 1, Some("a4"), Some("c2"));
    step("b4", 2, Some("b3"), Some("a5"));
    step("c3", 3, Some("c2"), Some("b4"));
    step("d3", 4, Some("d2"), Some("c3"));
    step("a6", 1, Some("a5"), Some("d3"));
    step("b5", 2, Some("b4"), Some("a6"));
    step("c4", 3, Some("c3"), Some("b5"));
    step("d4", 4, Some("d3"), Some("c4"));
    step("a7", 1, Some("a6"), Some("d4"));
    step("b6", 2, Some("b5"), Some("a7"));
    out
}

#[tokio::test]
async fn checkpoint_accepted_requires_two_thirds_weight_at_that_round() {
    // A single node holding a decided clique. Its own signature is one of the
    // four; a second and third signature are injected over the node's own
    // signing bytes (the same path inbound gossip uses).
    let registry = registry_for_ids(&[1, 2, 3, 4]);
    let identity = TlsIdentity::from_seed([0x77; 32], 1).expect("identity builds");
    let node = Arc::new(GossipNode::new(
        NodeId::new(1),
        SigningKey::from_bytes(&consensus_seed(1)),
        registry.clone(),
        identity,
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));

    for event in build_deep_clique() {
        let verified = event.clone().verify(&registry).expect("valid signature");
        let mut hg = node.hashgraph.lock().await;
        hg.insert(verified).expect("insert");
    }

    node.process_finalized_rounds().await;

    // The node produced its own checkpoint for the decided round 1.
    let signing_bytes =
        node.checkpoint_signing_bytes(1).await.expect("checkpoint produced for round 1");

    // 1 sig (the node's own) is below 2/3 of 4.
    assert!(node.signed_checkpoint_for(1).await.is_none());
    // 2 sigs total: still below 2/3.
    node.submit_checkpoint_sig(checkpoint_sig_for(2, 1, &signing_bytes)).await;
    assert!(node.signed_checkpoint_for(1).await.is_none(), "2 of 4 is below the 2/3 threshold");
    // 3 sigs total = the 2/3 + 1 boundary for a 4-member roster.
    node.submit_checkpoint_sig(checkpoint_sig_for(3, 1, &signing_bytes)).await;
    let accepted = node.signed_checkpoint_for(1).await.expect("3 of 4 reaches quorum");
    assert_eq!(accepted.payload.round, 1);
    assert_eq!(accepted.sigs.len(), 3);
}

#[tokio::test]
async fn pruning_old_events_does_not_break_ordering_after_checkpoint() {
    let nodes = spawn_cluster(&[1, 2, 3, 4]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();
    let registry = registry_for_ids(&[1, 2, 3, 4]);

    let (counts, lates) = stop_and_settle(&refs, Duration::from_secs(2)).await;
    assert_converged(&counts, &lates, "checkpoint ordering");

    let node0 = &nodes[0];
    let mut hg = node0.node.hashgraph.lock().await;

    // The cluster's own checkpoint flow (quorum acceptance -> prune) runs
    // throughout the settle window, so old ordered rounds may already be
    // gone. Record the surviving order, then prune again at the lowest
    // ordered round and verify nothing at or above it changes.
    const MAX_ROUND: u64 = 64;
    let ordered: Vec<u64> =
        (1..=MAX_ROUND).filter(|&r| !hg.consensus_order(r).is_empty()).collect();
    assert!(!ordered.is_empty(), "cluster orders at least one round: {ordered:?}");
    let before: Vec<(u64, Vec<EventHash>)> =
        ordered.iter().map(|&r| (r, hg.consensus_order(r))).collect();

    let r = ordered[0];
    hg.prune_before_round(r);

    // No surviving round's order changed.
    for (round, order) in &before {
        assert_eq!(&hg.consensus_order(*round), order, "round {round} order unchanged");
    }

    // A new event whose parents are retained rounds (rr >= R) still inserts:
    // border anchors keep every parent of a live event present. The *latest*
    // event per creator is not a safe parent choice here — one can sit below
    // R and be pruned if no descendant was gossiped before settle.
    let retained_event =
        |hg: &consensus::Hashgraph, creator: NodeId, from_round: u64| -> EventHash {
            (from_round..=MAX_ROUND)
                .flat_map(|round| hg.consensus_order(round))
                .find(|h| hg.get(h).is_some_and(|rec| *rec.event().creator() == creator))
                .expect("a retained event from the creator")
        };
    let self_parent = retained_event(&hg, NodeId::new(1), r);
    let other_parent = retained_event(&hg, NodeId::new(2), r);
    drop(hg);

    let new_event = make_event_with_payload(
        &nodes[0].key,
        1,
        Some(self_parent),
        Some(other_parent),
        Vec::new(),
    );
    let new_hash = insert_event(node0, &registry, new_event).await;
    {
        let hg = node0.node.hashgraph.lock().await;
        assert!(hg.get(&new_hash).is_some(), "new event inserts after pruning");
    }
    drop_nodes(nodes);
}

/// A learner whose secret does not match the key the checkpoint roster holds
/// for it could never produce a verifiable event — every sync round would
/// fail silently and consensus would stall (the `jkaind init --force`-without-
/// wiping-data/ footgun). `apply_checkpoint` must reject such a checkpoint
/// before any state is loaded, while a matching secret restores normally.
#[tokio::test]
async fn from_checkpoint_rejects_roster_key_mismatched_to_the_learner() {
    let roster = registry_for_ids(&[1, 4]);
    let state = state::State::new(temp_state_db().state_keyspace());
    let state_bytes = state.to_bytes();
    let state_hash = state.root();
    let payload = CheckpointPayload::new(1, state_hash, roster.clone());

    // Both members sign: the 2-node roster's quorum is all of them.
    let mut accumulator = CheckpointAccumulator::new(payload.clone());
    accumulator.add_sig(checkpoint_sig_for(1, 1, &payload.signing_bytes()), &roster);
    let accepted = accumulator
        .add_sig(checkpoint_sig_for(4, 1, &payload.signing_bytes()), &roster)
        .expect("2-node roster reaches quorum");
    let response = ReconnectResponse {
        signed_checkpoint: accepted,
        state_bytes,
        roster_history_bytes: encode_roster_history(&RosterHistory::new(roster)),
        decided_round: 1,
        retained: Vec::new(),
    };

    let node4_id = NodeId::new(4);
    let identity4 = TlsIdentity::from_seed(tls_seed(4), 4).expect("identity");

    // The matching secret restores from the checkpoint.
    let correct = GossipNode::from_checkpoint(
        node4_id,
        SigningKey::from_bytes(&consensus_seed(4)),
        identity4.clone(),
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        response.clone(),
        temp_state_db(),
    )
    .await;
    assert!(correct.is_ok(), "a matching secret restores");

    // A rotated secret is rejected up front, before any state is applied.
    let rotated = GossipNode::from_checkpoint(
        node4_id,
        SigningKey::from_bytes(&[9u8; 32]),
        identity4,
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        response,
        temp_state_db(),
    )
    .await;
    assert!(rotated.is_err(), "a rotated secret is rejected before restoring");
}
