//! Live-cluster profile: runs a real 4-node cluster under KV load and prints
//! the in-situ per-event costs recorded by the node instrumentation — the
//! `Hashgraph` insert timing (verify / insert / finalize / vote) and the
//! execution path (executor bucket / state snapshot).
//!
//! This is the macro counterpart to the release microbenchmarks: it shows how
//! the per-op costs land inside a running consensus node. Ignored by default;
//! run with:
//!
//! ```bash
//! cd consensus-node
//! cargo test -p gossip --release --test profile_live -- --ignored --nocapture
//! ```

mod common;

use common::*;
use state::Op;

#[tokio::test]
#[ignore = "live profile; run with --release --ignored --nocapture"]
async fn live_cluster_profile() {
    let nodes = spawn_cluster(&[1, 2, 3, 4]).await;

    let mut submitted = 0usize;
    for round in 0..40u32 {
        for (i, t) in nodes.iter().enumerate() {
            let key = format!("k-{round}-{i}").into_bytes();
            let value = format!("v-{round}-{i}").into_bytes();
            if t.node.submit_transaction(Op::Put { key, value }.encode()).await {
                submitted += 1;
            }
        }
    }

    tokio::time::timeout(DEADLINE, async {
        loop {
            let mut all_executed = true;
            for t in &nodes {
                if t.node.gossip_metrics_snapshot().await.exec_count == 0 {
                    all_executed = false;
                    break;
                }
            }
            if all_executed {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("cluster executes at least one finalized round");

    println!("\n=== live 4-node profile: {submitted} KV tx submitted ===");
    for (i, t) in nodes.iter().enumerate() {
        let m = t.node.gossip_metrics_snapshot().await;
        let it = { t.node.hashgraph.lock().await.insert_timing() };
        println!("\nnode {}:", i + 1);
        println!(
            "  verify_strict (event auth): {:>9} ns  ({} events)",
            it.verify_ns / it.verify_count.max(1),
            it.verify_count
        );
        println!(
            "  hashgraph insert:           {:>9} ns  ({} events)",
            it.insert_ns / it.insert_count.max(1),
            it.insert_count
        );
        println!(
            "    finalize_round:           {:>9} ns",
            it.finalize_round_ns / it.finalize_round_count.max(1)
        );
        println!(
            "    vote_as_witness:          {:>9} ns",
            it.vote_as_witness_ns / it.vote_as_witness_count.max(1)
        );
        println!(
            "  executor bucket (SMT):      {:>9} ns  ({} rounds)",
            m.exec_ns / m.exec_count.max(1),
            m.exec_count
        );
        println!(
            "  state snapshot (to_bytes):  {:>9} ns  ({} snapshots)",
            m.snapshot_ns / m.snapshot_count.max(1),
            m.snapshot_count
        );
    }

    drop_nodes(nodes);
}
