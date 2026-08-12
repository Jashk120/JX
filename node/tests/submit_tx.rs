//! End-to-end transaction submission: a payload queued via
//! `GossipNode::submit_transaction` lands in the node's next own event,
//! propagates through gossip, and is executed by both nodes' executors.

mod common;

use common::*;
use state::Op;

#[tokio::test]
async fn submitted_transaction_executes_on_both_nodes() {
    let (nodes, _net) = spawn_cluster(&[1, 2]).await;

    let tx = Op::Put { key: b"balance".to_vec(), value: b"100".to_vec() }.encode();
    nodes[0].node.submit_transaction(tx).await;

    let value = wait_for_state(&nodes[0].node, b"balance", DEADLINE).await;
    assert_eq!(value.as_deref(), Some(&b"100"[..]), "initiator executes its own submitted tx");
    let value = wait_for_state(&nodes[1].node, b"balance", DEADLINE).await;
    assert_eq!(value.as_deref(), Some(&b"100"[..]), "peer gossips and executes the tx");

    // Both nodes must end on the identical deterministic state hash, not just
    // the same value.
    assert_eq!(
        nodes[0].node.executor_state().await,
        nodes[1].node.executor_state().await,
        "identical state across nodes"
    );

    drop_nodes(nodes);
}
