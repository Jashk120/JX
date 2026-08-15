//! Phase 2 membership activation over the gossip layer.
//!
//! A finalized event carrying a `MembershipOp::Add` payload is decoded by
//! `GossipNode::process_finalized_rounds`, bucketed by roundReceived, and
//! activated once the activation round (`roundReceived + 1`) is fully
//! decided: the hashgraph grows, the roster schedules the new member, and the
//! peer set gains the new node. A second call over the same finalized set is
//! a no-op (the processed-round watermark prevents re-bucketing; the
//! `is_member` guard prevents re-activation).

use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use std::sync::Arc;
use std::time::Duration;

use crypto::{
    Hashable,
    MembershipOp,
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    SyncTiming,
    TlsIdentity,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use state::StateDb;

fn temp_state_db() -> Arc<StateDb> {
    let dir = tempfile::tempdir().expect("temp dir");
    Arc::new(StateDb::open(dir.path()).expect("state db opens"))
}

fn key_for(id: u64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}

fn registry_for(ids: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in ids {
        registry.register(NodeId::new(id), key_for(id).verifying_key());
    }
    registry
}

fn membership_add_tx(new_node: u64) -> Transaction {
    let op = MembershipOp::Add {
        node: NodeId::new(new_node),
        key: Box::new(key_for(new_node).verifying_key()),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000),
        reconnect_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7001)),
    };
    let mut payload = vec![0x02];
    payload.extend_from_slice(&op.encode());
    Transaction::from_bytes(payload)
}

/// The deterministic 4-member deep clique used by `consensus`'s `order.rs`
/// tests: rounds 1-4 finalize, so an op carried by a round-1 event is
/// activated once round 2 is decided.
struct CliqueBuilder {
    events: std::collections::HashMap<&'static str, EventHash>,
    ts: u64,
}

impl CliqueBuilder {
    fn step(
        &mut self,
        label: &'static str,
        author: u64,
        self_parent: Option<&'static str>,
        other_parent: Option<&'static str>,
        payload: Vec<Transaction>,
    ) -> Event {
        let self_parent = self_parent.map(|label| self.events[label]);
        let other_parent = other_parent.map(|label| self.events[label]);
        let event = UnsignedEvent::new(
            NodeId::new(author),
            self_parent,
            other_parent,
            Timestamp::new(self.ts),
            payload,
        )
        .sign(&key_for(author));
        self.ts += 1;
        self.events.insert(label, event.hash());
        event
    }
}

fn build_clique() -> (Vec<Event>, EventHash) {
    let mut builder = CliqueBuilder { events: std::collections::HashMap::new(), ts: 100 };
    let events = vec![
        builder.step("a1", 1, None, None, Vec::new()),
        builder.step("b1", 2, None, None, vec![membership_add_tx(5)]),
        builder.step("c1", 3, None, None, Vec::new()),
        builder.step("d1", 4, None, None, Vec::new()),
        builder.step("a2", 1, Some("a1"), Some("d1"), Vec::new()),
        builder.step("b2", 2, Some("b1"), Some("a2"), Vec::new()),
        builder.step("a3", 1, Some("a2"), Some("b2"), Vec::new()),
        builder.step("b3", 2, Some("b2"), Some("c1"), Vec::new()),
        builder.step("a4", 1, Some("a3"), Some("b3"), Vec::new()),
        builder.step("d2", 4, Some("d1"), Some("a4"), Vec::new()),
        builder.step("c2", 3, Some("c1"), Some("d2"), Vec::new()),
        builder.step("a5", 1, Some("a4"), Some("c2"), Vec::new()),
        builder.step("b4", 2, Some("b3"), Some("a5"), Vec::new()),
        builder.step("c3", 3, Some("c2"), Some("b4"), Vec::new()),
        builder.step("d3", 4, Some("d2"), Some("c3"), Vec::new()),
        builder.step("a6", 1, Some("a5"), Some("d3"), Vec::new()),
        builder.step("b5", 2, Some("b4"), Some("a6"), Vec::new()),
        builder.step("c4", 3, Some("c3"), Some("b5"), Vec::new()),
        builder.step("d4", 4, Some("d3"), Some("c4"), Vec::new()),
        builder.step("a7", 1, Some("a6"), Some("d4"), Vec::new()),
        builder.step("b6", 2, Some("b5"), Some("a7"), Vec::new()),
        builder.step("c5", 3, Some("c4"), Some("b6"), Vec::new()),
        builder.step("d5", 4, Some("d4"), Some("c5"), Vec::new()),
        builder.step("a8", 1, Some("a7"), Some("d5"), Vec::new()),
        builder.step("b7", 2, Some("b6"), Some("a8"), Vec::new()),
    ];
    let b1 = builder.events["b1"];
    (events, b1)
}

#[tokio::test]
async fn finalized_membership_op_activates_new_member_idempotently() {
    let registry = registry_for(&[1, 2, 3, 4]);
    let identity = TlsIdentity::from_seed([0x77; 32], 1).expect("identity builds");
    let node = Arc::new(GossipNode::new(
        NodeId::new(1),
        key_for(1),
        registry.clone(),
        identity,
        Vec::new(),
        SyncTiming::new(Duration::from_millis(25), Duration::from_millis(500)),
        temp_state_db(),
    ));

    // Insert the finalized clique directly into the node's hashgraph.
    let (events, b1) = build_clique();
    for event in &events {
        let verified = event.clone().verify(&registry).expect("valid signature");
        let mut hg = node.hashgraph.lock().await;
        hg.insert(verified).expect("insert");
    }

    // The op's event (b1) is finalized; activation fires once the round after
    // its roundReceived is fully decided.
    let b1_rr = {
        let hg = node.hashgraph.lock().await;
        hg.round_received(&b1).expect("b1 is ordered")
    };
    let activation_round = b1_rr + 1;
    assert!(!node.is_consensus_member(NodeId::new(5)).await);
    assert_eq!(node.peer_count().await, 0);

    node.process_finalized_rounds().await;

    // Activation: hashgraph grows, the roster schedules node 5 one round
    // after the activation round, and the peer set gains node 5 with its
    // reconnect port pinned.
    assert!(node.is_consensus_member(NodeId::new(5)).await);
    assert_eq!(node.peer_count().await, 1);
    {
        let hg = node.hashgraph.lock().await;
        assert_eq!(hg.member_count(), 5);
        // The activation round keeps the old roster; the round after it uses
        // the expanded one.
        assert_eq!(hg.registry_at_round(activation_round).len(), 4);
        assert_eq!(hg.registry_at_round(activation_round + 1).len(), 5);
    }
    {
        let peers = node.peers().await;
        assert_eq!(peers.len(), 1);
        let added = &peers[0];
        assert_eq!(added.node_id, NodeId::new(5));
        assert_eq!(added.reconnect_addr, Some("127.0.0.1:7001".parse().expect("valid addr")));
        // The pin must be derived from node 5's consensus key.
        let key = key_for(5).verifying_key();
        let fingerprint = {
            let hg = node.hashgraph.lock().await;
            let registry = hg.registry_at_round(activation_round + 1);
            registry.key_for(&NodeId::new(5)).expect("registered").to_owned()
        };
        assert_eq!(key, fingerprint);
    }

    // Idempotency: a second pass over the same finalized set changes nothing.
    let member_count_before = {
        let hg = node.hashgraph.lock().await;
        hg.member_count()
    };
    let peer_count_before = node.peer_count().await;
    node.process_finalized_rounds().await;
    assert_eq!(
        {
            let hg = node.hashgraph.lock().await;
            hg.member_count()
        },
        member_count_before
    );
    assert_eq!(node.peer_count().await, peer_count_before);
}
