//! End-to-end dynamic membership through the Unix control socket: a
//! `MembershipOp::Add` payload submitted to node 1's control socket propagates
//! through consensus, activates on both nodes, and the existing peers pin the
//! new member's TLS fingerprint (derived from its consensus key) together with
//! its reconnect address — the exact properties the daemon's control plane
//! depends on for a dynamically-added member.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use common::*;
use crypto::MembershipOp;
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    TlsIdentity,
};
use node::config::encode_hex;
use node::control::{
    self,
    ControlRequest,
};
use primitives::NodeId;
use tokio::net::UnixListener;
use tokio::time::{
    sleep,
    timeout,
};

async fn wait_for_member(node: &GossipNode, id: NodeId, deadline: Duration) {
    timeout(deadline, async {
        loop {
            if node.is_consensus_member(id).await {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("node becomes a consensus member");
}

#[tokio::test]
async fn add_member_via_control_socket_activates_and_pins_reconnect() {
    let (nodes, _net) = spawn_cluster(&[1, 2]).await;

    // Node 1 serves the control socket.
    let dir = tempfile::tempdir().expect("temp dir");
    let sock1 = dir.path().join("node1.sock");
    let listener1 = UnixListener::bind(&sock1).expect("bind control socket");
    let stop1 = Arc::new(AtomicBool::new(false));
    let node1 = nodes[0].node.clone();
    tokio::spawn(control::serve(listener1, node1.clone(), stop1.clone()));

    // Node 3's key material: a single seed, so its TLS identity matches the
    // fingerprint an existing node derives from its consensus key.
    let seed3 = [0x33u8; 32];
    let key3 = SigningKey::from_bytes(&seed3).verifying_key();
    let gossip3: std::net::SocketAddr = "127.0.0.1:9000".parse().expect("addr");
    let reconnect3: std::net::SocketAddr = "127.0.0.1:9001".parse().expect("addr");
    let bls_id3 = crypto::BlsIdentity::from_ikm(&seed3).expect("bls");

    let op = MembershipOp::Add {
        node: NodeId::new(3),
        key: Box::new(key3),
        bls_key: bls_id3.public.to_bytes(),
        pop: crypto::sign_pop(&bls_id3).to_bytes(),
        addr: gossip3,
        reconnect_addr: Some(reconnect3),
    };
    let payload = control::membership_op_payload(&op);
    let response =
        control::request(&sock1, &ControlRequest::SubmitTx { payload_hex: encode_hex(&payload) })
            .await
            .expect("submit request");
    assert!(response.ok, "submit accepted: {:?}", response.error);

    // The op orders through consensus and activates on both nodes.
    wait_for_member(&nodes[0].node, NodeId::new(3), DEADLINE).await;
    wait_for_member(&nodes[1].node, NodeId::new(3), DEADLINE).await;

    // Node 1's peer set now includes node 3 with the reconnect port pinned and
    // a TLS pin that matches node 3's actual certificate.
    let peers = nodes[0].node.peers().await;
    let peer3 = peers.iter().find(|peer| peer.node_id == NodeId::new(3)).expect("node 3 peer");
    assert_eq!(peer3.addr, gossip3);
    assert_eq!(peer3.reconnect_addr, Some(reconnect3), "added peer carries its reconnect port");
    let identity3 = TlsIdentity::from_seed(seed3, 3).expect("identity builds");
    assert_eq!(
        peer3.expected_spki_fingerprint,
        identity3.spki_fingerprint(),
        "TLS pin matches the added member's certificate"
    );

    stop1.store(true, std::sync::atomic::Ordering::Release);
    drop_nodes(nodes);
}

#[tokio::test]
async fn add_member_with_wrong_pop_is_not_activated() {
    let (nodes, _net) = spawn_cluster(&[1, 2]).await;

    let dir = tempfile::tempdir().expect("temp dir");
    let sock1 = dir.path().join("node1.sock");
    let listener1 = UnixListener::bind(&sock1).expect("bind control socket");
    let stop1 = Arc::new(AtomicBool::new(false));
    let node1 = nodes[0].node.clone();
    tokio::spawn(control::serve(listener1, node1.clone(), stop1.clone()));

    let seed4 = [0x44u8; 32];
    let key4 = SigningKey::from_bytes(&seed4).verifying_key();
    let gossip4: std::net::SocketAddr = "127.0.0.1:9100".parse().expect("addr");
    let bls_id4 = crypto::BlsIdentity::from_ikm(&seed4).expect("bls");
    let bls_wrong = crypto::BlsIdentity::from_ikm(&[0x99u8; 32]).expect("bls");
    let wrong_pop = crypto::sign_pop(&bls_wrong).to_bytes();

    let op = MembershipOp::Add {
        node: NodeId::new(4),
        key: Box::new(key4),
        bls_key: bls_id4.public.to_bytes(),
        pop: wrong_pop,
        addr: gossip4,
        reconnect_addr: None,
    };
    let payload = control::membership_op_payload(&op);
    let response =
        control::request(&sock1, &ControlRequest::SubmitTx { payload_hex: encode_hex(&payload) })
            .await
            .expect("submit request");
    assert!(response.ok, "submit accepted: {:?}", response.error);

    let present = timeout(Duration::from_secs(4), async {
        loop {
            if nodes[0].node.is_consensus_member(NodeId::new(4)).await
                || nodes[1].node.is_consensus_member(NodeId::new(4)).await
            {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(!present, "member with wrong PoP must NOT be activated");

    stop1.store(true, std::sync::atomic::Ordering::Release);
    drop_nodes(nodes);
}
