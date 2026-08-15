//! Restart recovery from a persisted checkpoint: a stopped node restores its
//! executor state from disk (with the state-hash cross-check), rebinds its
//! original ports, reconnects to its live peer, and resumes participating.
//!
//! Node 1 runs on a dedicated thread with its own single-threaded runtime —
//! a faithful stand-in for a separate process — so it can be stopped, its
//! runtime dropped (accept loops die, ports freed), and restarted on the
//! same addresses. Node 2 stays up throughout.

mod common;

use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use common::*;
use gossip::{
    GossipNode,
    SyncTiming,
};
use node::restart::{
    latest_for_restart,
    verify_persisted,
};
use node::storage::Storage;
use primitives::NodeId;
use state::{
    Op,
    State,
    StateDb,
};
use tokio::net::TcpListener;
use tokio::time::{
    sleep,
    timeout,
};

/// Decodes the canonical `State::to_bytes()` snapshot into a `State` over a
/// fresh tempdir keyspace (kept readable by the `Arc<Keyspace>` the state
/// holds).
fn state_from_bytes(bytes: &[u8]) -> State {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = StateDb::open(dir.path()).expect("state db opens");
    State::from_bytes(db.state_keyspace(), bytes).expect("state decodes")
}

/// Waits until the persisted checkpoint's state snapshot includes `key` —
/// i.e. the stored checkpoint round ordered the transaction — so a restart is
/// guaranteed to resume with the submitted state already present. The
/// snapshot is read from the state database's `snap` keyspace (the `.snap`
/// files are gone).
async fn wait_for_persisted_state(
    storage: &Storage,
    state_db: &StateDb,
    key: &[u8],
    deadline: Duration,
) {
    timeout(deadline, async {
        loop {
            let Some(persisted) = storage.latest().expect("latest") else {
                sleep(Duration::from_millis(25)).await;
                continue;
            };
            let Some(bytes) =
                state_db.snapshot_for(persisted.checkpoint.payload.round).expect("snapshot")
            else {
                sleep(Duration::from_millis(25)).await;
                continue;
            };
            let snapshot = state_from_bytes(&bytes);
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
async fn restart_from_persisted_checkpoint_restores_state_and_resumes() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let data1 = tmp.path().join("node1");
    let mut net = net_for(&[1, 2]).await;

    // Node 1: dedicated thread + single-threaded runtime, like a process.
    let node1 = fresh_node(&net, 0);
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

    // Node 1 persists its accepted checkpoints to disk.
    let storage1 = Storage::new(&data1).expect("storage opens");
    node1.set_checkpoint_sink(Arc::new(storage1)).await;
    let storage1 = Storage::new(&data1).expect("storage reopens");

    // Submit a transaction and wait for both nodes to execute it.
    let tx = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
    node1.submit_transaction(tx).await;
    wait_for_state(&node1, b"k", DEADLINE).await;
    wait_for_state(&node2, b"k", DEADLINE).await;

    // Wait until the persisted checkpoint itself covers the transaction, so
    // the restart resumes with the submitted state already present. The state
    // snapshot lives in the node's state database `snap` keyspace.
    wait_for_persisted_state(&storage1, &net.state_dbs[0], b"k", DEADLINE).await;

    // Stop node 1 (driver exits, runtime drops, accept loops die, ports free).
    node1_stop.store(true, Ordering::Release);
    node1_thread.join().expect("node1 thread exits");

    // Load the latest persisted checkpoint now that node 1 can no longer
    // write: this is exactly what a restarting process would read.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let persisted = storage1.latest().expect("latest").expect("a persisted checkpoint");
    assert!(
        verify_persisted(&persisted, &net.state_dbs[0]),
        "persisted checkpoint passes quorum + state-hash checks"
    );
    assert_eq!(
        persisted.checkpoint.payload.round,
        storage1.latest().expect("latest").expect("still there").checkpoint.payload.round,
        "latest is stable once the node is stopped"
    );

    // Rebuild node 1 from the persisted checkpoint with its original peers.
    let expected_key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)).verifying_key();
    let response = latest_for_restart(&storage1, &net.state_dbs[0], 1, &expected_key)
        .expect("restart data loads")
        .expect("a restart response exists");
    assert_eq!(response.signed_checkpoint.payload.round, persisted.checkpoint.payload.round);
    let node1b = Arc::new(
        GossipNode::from_checkpoint(
            NodeId::new(1),
            ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)),
            net.identities[0].clone(),
            net.peers_for(0),
            SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
            response,
            net.state_dbs[0].clone(),
        )
        .await
        .expect("node rebuilt from persisted checkpoint"),
    );

    // The executor state must be restored exactly from the persisted
    // snapshot — the bytes whose Merkle root the checkpoint commits.
    let expected = state_from_bytes(
        &net.state_dbs[0]
            .snapshot_for(persisted.checkpoint.payload.round)
            .expect("snapshot")
            .expect("a snapshot for the checkpoint round"),
    );
    assert_eq!(
        node1b.executor_state().await,
        expected,
        "state restored exactly from the persisted snapshot"
    );
    assert_eq!(
        node1b.executor_state().await.get(b"k"),
        Some(b"v".to_vec()),
        "submitted key survived the restart"
    );

    // Node 1 restarts on its ORIGINAL addresses — freed by the runtime drop —
    // so node 2's peer entry still resolves.
    let gossip_listener = TcpListener::bind(net.gossip_addrs[0]).await.expect("rebind gossip port");
    let reconnect_listener =
        TcpListener::bind(net.reconnect_addrs[0]).await.expect("rebind reconnect port");
    let stop1b = Arc::new(AtomicBool::new(false));
    let spawn_node = node1b.clone();
    let stop_handle = stop1b.clone();
    node1b.request_reconnect();
    let handle1b = tokio::spawn(async move {
        let _ = spawn_node
            .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
            .await;
    });

    // The restarted node resumes gossiping: it must create new events of its
    // own against the still-live peer (sync rounds complete), regardless of
    // the 2-node post-restart fame pace.
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
