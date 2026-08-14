//! Phase 8 — independent restart recovery from the durable event log: a
//! stopped node rebuilds its retained graph from the local Fjall log (no
//! live peer, no `request_reconnect`) and resumes participating.
//!
//! Node 1 runs on a dedicated thread with its own single-threaded runtime —
//! a faithful stand-in for a separate process — so it can be stopped, its
//! runtime dropped (accept loops die, ports freed), and restarted on the
//! same addresses. Node 2 stays up throughout, but node 1's restart does
//! not talk to it to restore the graph.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use common::*;
use gossip::GossipNode;
use node::restart::latest_for_restart_with_log;
use node::storage::Storage;
use primitives::{
    EventHash,
    NodeId,
};
use state::{
    Op,
    State,
};
use storage::EventLog;
use tokio::net::TcpListener;
use tokio::time::{
    sleep,
    timeout,
};

/// Waits until the persisted checkpoint's snapshot includes `key`, so a
/// restart is guaranteed to resume with the submitted state already present.
async fn wait_for_persisted_state(storage: &Storage, key: &[u8], deadline: Duration) {
    timeout(deadline, async {
        loop {
            let Some(persisted) = storage.latest().expect("latest") else {
                sleep(Duration::from_millis(25)).await;
                continue;
            };
            let snapshot = State::from_bytes(&persisted.state_bytes).expect("state decodes");
            if snapshot.get(key).is_some() {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("persisted checkpoint snapshot includes the submitted key");
}

#[tokio::test]
async fn restart_replays_retained_graph_from_the_event_log_without_a_peer() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let data1 = tmp.path().join("node1");
    let mut net = net_for(&[1, 2]).await;

    // Node 1: checkpoint sink + event log sink; runs on a dedicated thread.
    let node1 = fresh_node(&net, 0);
    let storage1 = Storage::new(&data1).expect("storage opens");
    let event_log1 = Arc::new(EventLog::open(&data1).expect("event log opens"));
    node1.set_checkpoint_sink(Arc::new(storage1)).await;
    node1.set_event_sink(event_log1.clone()).await;

    let node1_stop = Arc::new(AtomicBool::new(false));
    let thread_stop = node1_stop.clone();
    let thread_node = node1.clone();
    let gossip_listener = net.gossip_listeners.remove(0);
    let reconnect_listener = net.reconnect_listeners.remove(0);
    let node1_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("node1 runtime");
        rt.block_on(async {
            let _ = thread_node
                .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, thread_stop)
                .await;
        });
        drop(rt);
    });

    // Node 2 stays in the test runtime for the whole test.
    let node2 = fresh_node(&net, 1);
    let node2_stop = Arc::new(AtomicBool::new(false));
    let spawn2 = node2.clone();
    let stop2 = node2_stop.clone();
    let gossip_listener = net.gossip_listeners.remove(0);
    let reconnect_listener = net.reconnect_listeners.remove(0);
    let _handle2 = tokio::spawn(async move {
        let _ = spawn2
            .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop2)
            .await;
    });

    // Submit a transaction and wait for it to be persisted in a checkpoint.
    let tx = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
    node1.submit_transaction(tx).await;
    wait_for_state(&node1, b"k", DEADLINE).await;
    let storage1 = Storage::new(&data1).expect("storage reopens");
    wait_for_persisted_state(&storage1, b"k", DEADLINE).await;

    // Flush any pending ordering updates into the log, then stop node 1.
    node1.process_finalized_rounds().await;
    node1_stop.store(true, Ordering::Release);
    node1_thread.join().expect("node1 thread exits");

    // Capture the now-quiescent graph as ground truth for the replay.
    let (original_hashes, original_rr): (Vec<EventHash>, HashMap<EventHash, u64>) = {
        let hg = node1.hashgraph.lock().await;
        let hashes = hg.all_event_hashes();
        let rr = hashes.iter().filter_map(|h| hg.round_received(h).map(|r| (*h, r))).collect();
        (hashes, rr)
    };
    // Release the stopped node and the test's own handle so the Fjall
    // database is fully closed and can be reopened for the replay.
    drop(node1);
    drop(event_log1);

    // Rebuild node 1 purely from disk — checkpoint + event log — with no
    // live peer and no `request_reconnect`.
    let event_log1 = Arc::new(EventLog::open(&data1).expect("event log reopens"));
    let expected_key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)).verifying_key();
    let response = latest_for_restart_with_log(&storage1, &event_log1, 1, &expected_key)
        .expect("restart data loads")
        .expect("a restart response exists");
    assert!(!response.retained.is_empty(), "the log must carry the retained window");
    assert_eq!(
        response.retained.len(),
        original_hashes.len(),
        "every live event must be replayed from the log"
    );

    let node1b = Arc::new(
        GossipNode::from_checkpoint(
            NodeId::new(1),
            ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)),
            net.identities[0].clone(),
            net.peers_for(0),
            SYNC_INTERVAL,
            SYNC_TIMEOUT,
            response,
        )
        .await
        .expect("node rebuilt from checkpoint + event log"),
    );
    node1b.set_event_sink(event_log1.clone()).await;

    // The executor state is restored exactly from the checkpoint snapshot.
    let persisted = storage1.latest().expect("latest").expect("a persisted checkpoint");
    let expected_state = State::from_bytes(&persisted.state_bytes).expect("state decodes");
    assert_eq!(node1b.executor_state().await, expected_state);
    assert_eq!(node1b.executor_state().await.get(b"k"), Some(&b"v"[..]));

    // The rebuilt graph matches the pre-restart graph exactly — same event
    // set, same ordering — without ever talking to a peer.
    let mut restored: Vec<EventHash> = node1b.hashgraph.lock().await.all_event_hashes();
    restored.sort();
    let mut original = original_hashes.clone();
    original.sort();
    assert_eq!(restored, original, "replayed graph must equal the pre-restart graph");
    for (hash, rr) in &original_rr {
        assert_eq!(
            node1b.hashgraph.lock().await.round_received(hash),
            Some(*rr),
            "replayed ordering for {hash:?}"
        );
    }

    // The restarted node resumes gossiping with the still-live peer: it must
    // create new events against it, proving the rebuilt graph is functional.
    let gossip_listener = TcpListener::bind(net.gossip_addrs[0]).await.expect("rebind gossip port");
    let reconnect_listener =
        TcpListener::bind(net.reconnect_addrs[0]).await.expect("rebind reconnect port");
    let stop1b = Arc::new(AtomicBool::new(false));
    let spawn_node = node1b.clone();
    let stop_handle = stop1b.clone();
    let handle1b = tokio::spawn(async move {
        let _ = spawn_node
            .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
            .await;
    });

    let own_seq = timeout(DEADLINE, async {
        loop {
            let latest = {
                let hg = node1b.hashgraph.lock().await;
                hg.latest_event_by(&NodeId::new(1)).and_then(|h| hg.get(h)).map(|r| r.seq())
            };
            if let Some(seq) = latest {
                return seq;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("restarted node resumes creating its own events");
    assert!(own_seq >= 1, "restarted node produced a new own event (seq {own_seq})");

    // The live peer must have received the restarted node's new events.
    timeout(DEADLINE, async {
        loop {
            let received = {
                let hg = node2.hashgraph.lock().await;
                hg.latest_event_by(&NodeId::new(1)).is_some()
            };
            if received {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("live peer receives the restarted node's events");

    stop1b.store(true, Ordering::Release);
    let _ = handle1b.await;
    node2_stop.store(true, Ordering::Release);
}
