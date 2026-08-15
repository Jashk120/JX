//! End-to-end gossip integration tests: real TCP + TLS nodes on localhost.
//!
//! These exercise the full path — TLS handshake with SPKI pinning, sync
//! request/response framing, frontier-based delta exchange, and topological
//! insertion — and assert that independent nodes converge on identical
//! event sets, and that a node holding events a peer lacks reconciles via a
//! normal sync (partition/rejoin).

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use common::*;
use crypto::Hashable;
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    PeerInfo,
    SyncTiming,
    TlsIdentity,
};
use primitives::NodeId;

#[tokio::test]
async fn two_nodes_converge_on_identical_event_sets() {
    let nodes = spawn_cluster(&[1, 2]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();
    let (counts, lates) = stop_and_settle(&refs, Duration::from_millis(500)).await;
    assert_converged(&counts, &lates, "two nodes");
    drop_nodes(nodes);
}

#[tokio::test]
async fn four_nodes_converge_on_identical_event_sets() {
    let nodes = spawn_cluster(&[1, 2, 3, 4]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();
    let (counts, lates) = stop_and_settle(&refs, Duration::from_secs(1)).await;
    assert_converged(&counts, &lates, "four nodes");
    drop_nodes(nodes);
}

#[tokio::test]
async fn diverged_node_rejoins_and_reconciles() {
    // Nodes start with divergent local histories (each holding an event the
    // other lacks, as if partitioned), then gossip and must reconcile.
    let keys: Vec<(u64, SigningKey)> = vec![
        (1, SigningKey::from_bytes(&consensus_seed(1))),
        (2, SigningKey::from_bytes(&consensus_seed(2))),
    ];
    let registry = registry_for(&keys);

    let listener_a = bind_ephemeral().await;
    let listener_b = bind_ephemeral().await;
    let addrs = [
        listener_a.local_addr().expect("local addr"),
        listener_b.local_addr().expect("local addr"),
    ];
    let identities: Vec<TlsIdentity> = [1u64, 2]
        .iter()
        .map(|&id| TlsIdentity::from_seed(tls_seed(id), id).expect("identity"))
        .collect();

    let node_a = Arc::new(GossipNode::new(
        NodeId::new(1),
        keys[0].1.clone(),
        registry_for(&keys),
        identities[0].clone(),
        vec![PeerInfo::new(NodeId::new(2), addrs[1], identities[1].spki_fingerprint())],
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));
    let node_b = Arc::new(GossipNode::new(
        NodeId::new(2),
        keys[1].1.clone(),
        registry_for(&keys),
        identities[1].clone(),
        vec![PeerInfo::new(NodeId::new(1), addrs[0], identities[0].spki_fingerprint())],
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));

    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let a = TestNode {
        key: keys[0].1.clone(),
        node: node_a.clone(),
        stop: stop_a.clone(),
        handle: tokio::spawn(async move {
            let _ = node_a.clone().run_until_stopped(listener_a, stop_a).await;
        }),
    };
    let b = TestNode {
        key: keys[1].1.clone(),
        node: node_b.clone(),
        stop: stop_b.clone(),
        handle: tokio::spawn(async move {
            let _ = node_b.clone().run_until_stopped(listener_b, stop_b).await;
        }),
    };

    // Shared history: both nodes hold both genesis events (created once, so
    // the hashes match across nodes).
    let a1_event = make_event_with_payload(&a.key, 1, None, None, Vec::new());
    let a1 = a1_event.hash();
    insert_event(&a, &registry, a1_event.clone()).await;
    insert_event(&b, &registry, a1_event).await;
    let b1_event = make_event_with_payload(&b.key, 2, None, None, Vec::new());
    let b1 = b1_event.hash();
    insert_event(&a, &registry, b1_event.clone()).await;
    insert_event(&b, &registry, b1_event).await;

    // Divergence: each node created one event the other never saw, as if
    // partitioned. No forks — each creator keeps a clean self-parent chain.
    let a2 = insert_event(
        &a,
        &registry,
        make_event_with_payload(&a.key, 1, Some(a1), Some(b1), Vec::new()),
    )
    .await; // A2, A-only
    let b2 = insert_event(
        &b,
        &registry,
        make_event_with_payload(&b.key, 2, Some(b1), Some(a1), Vec::new()),
    )
    .await; // B2, B-only

    // Reconcile: poll until both divergent events are present on BOTH nodes.
    // Checkpoints (Phase 3) eventually prune these old-round events, so the
    // reconciliation is verified while they are still retained.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let mut reconciled = true;
            for node in [&a, &b] {
                let hashgraph = node.node.hashgraph.lock().await;
                if hashgraph.get(&a2).is_none() || hashgraph.get(&b2).is_none() {
                    reconciled = false;
                    break;
                }
            }
            if reconciled {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("divergent events reconcile on both nodes");

    // The cluster still converges to a consistent frontier afterward.
    let (counts, lates) = stop_and_settle(&[&a, &b], Duration::from_millis(300)).await;
    assert_converged(&counts, &lates, "diverged nodes");
    drop_nodes(vec![a, b]);
}
