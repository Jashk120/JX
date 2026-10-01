//! Verifies the execution-path timing instrumentation populates on a live
//! cluster: once a round finalizes, `process_finalized_rounds` must record at
//! least one execution bucket and one state snapshot in `GossipMetrics`.
//!
//! This guards the observability added for the "what is slowing down" work —
//! if the execution/snapshot counters silently stop advancing, the periodic
//! metrics logs would read zero and mislead a debugging session.

mod common;

use common::*;

#[tokio::test]
async fn exec_and_snapshot_timing_counters_populate() {
    let nodes = spawn_cluster(&[1, 2, 3, 4]).await;

    tokio::time::timeout(DEADLINE, async {
        loop {
            let mut all_populated = true;
            for t in &nodes {
                let m = t.node.gossip_metrics_snapshot().await;
                if m.exec_count == 0 || m.snapshot_count == 0 {
                    all_populated = false;
                    break;
                }
            }
            if all_populated {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("every node executes at least one finalized round");

    for t in &nodes {
        let m = t.node.gossip_metrics_snapshot().await;
        assert!(m.exec_count > 0 && m.exec_ns > 0, "exec timing populated");
        assert!(m.snapshot_count > 0 && m.snapshot_ns > 0, "snapshot timing populated");
    }

    drop_nodes(nodes);
}
