//! Restart recovery after a mid-checkpoint-write crash: the acceptance test
//! for the accept-without-durability class of bugs.
//!
//! A checkpoint file is atomically written (temp + sync + rename), so a crash
//! mid-write can only leave a *missing* or *truncated* file — never a torn
//! one.  This test simulates both failure modes and verifies that the
//! recovery path (`latest_for_restart_with_log`) either cleanly falls back
//! to a fresh start or reports a clear, non-silent error rather than
//! accepting corrupted state.
//!
//! Node 1 runs on a dedicated thread with a single-threaded runtime (a
//! faithful stand-in for a separate process) so it can be stopped and its
//! runtime dropped.  Node 2 stays up throughout.
//!
//! Scenarios tested:
//! 1. Truncated checkpoint file  →  clear error surfaced (unreadable).
//! 2. Valid checkpoint, missing state snapshot  →  verification error
//!    surfaced (no silent accept without durability).
//! 3. Valid checkpoint, state hash mismatch  →  verification error
//!    surfaced.
//! 4. Post-crash event log integrity: the event log is untouched by the
//!    checkpoint corruption and can still be read.

mod common;

use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use common::*;
use node::restart::{
    latest_for_restart_with_log,
    verify_persisted,
};
use node::storage::Storage;
use state::{
    Op,
    StateDb,
};
use storage::EventLog;
use tokio::time::{
    sleep,
    timeout,
};

fn state_from_bytes(bytes: &[u8]) -> state::State {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = StateDb::open(dir.path()).expect("state db opens");
    state::State::from_bytes(db.state_keyspace(), bytes).expect("state decodes")
}

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

/// Starts a two-node cluster, submits a transaction, waits for it to be
/// persisted, stops node 1, and returns (data_dir, net) for the caller to
/// corrupt state and test recovery.  Drops node handles and event logs before
/// returning so Fjall databases can be reopened.
async fn setup_and_stop() -> (tempfile::TempDir, ClusterNet) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let data1 = tmp.path().join("node1");
    let mut net = net_for(&[1, 2]).await;

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

    let tx = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
    node1.submit_transaction(tx).await;
    wait_for_state(&node1, b"k", DEADLINE).await;
    wait_for_state(&node2, b"k", DEADLINE).await;
    let storage1 = Storage::new(&data1).expect("storage reopens");
    wait_for_persisted_state(&storage1, &net.state_dbs[0], b"k", DEADLINE).await;

    // Stop node 1 and release all handles so Fjall databases can be reopened.
    node1_stop.store(true, Ordering::Release);
    node1_thread.join().expect("node1 thread exits");
    drop(node1);
    drop(event_log1);

    (tmp, net)
}

// ---------------------------------------------------------------------------
// Scenario 1: truncated checkpoint file → clear error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn truncated_checkpoint_surfaced_as_error() {
    let (tmp, net) = setup_and_stop().await;
    let data1 = tmp.path().join("node1");

    // Truncate the checkpoint file to simulate a write interrupted after the
    // rename but before the data was fully flushed.
    let cp_dir = data1.join("checkpoints");
    let mut cp_entries: Vec<_> = std::fs::read_dir(&cp_dir)
        .expect("checkpoint dir exists")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "cp"))
        .collect();
    assert!(!cp_entries.is_empty(), "at least one checkpoint file must exist");
    cp_entries.sort_by_key(|e| e.metadata().map(|m| m.len()).unwrap_or(0));
    let cp_file = cp_entries.first().expect("checkpoint file").path();
    std::fs::write(&cp_file, b"truncated").expect("truncate checkpoint");
    assert!(
        std::fs::metadata(&cp_file).expect("stat").len() < 100,
        "checkpoint file must be truncated"
    );

    // Reopen storage and event log after corruption.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let event_log1 = Arc::new(EventLog::open(&data1).expect("event log reopens"));

    // Storage::latest() must error on the unreadable file, not silently
    // return None (which would cause a fresh start without the operator
    // knowing the checkpoint was corrupt).
    assert!(
        storage1
            .latest()
            .expect_err("truncated checkpoint must error")
            .to_string()
            .contains("decoding checkpoint"),
        "error must mention decoding failure"
    );

    // latest_for_restart_with_log propagates the decode error as a clear
    // Err rather than accepting corrupt state or silently starting fresh.
    let expected_key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)).verifying_key();
    let err =
        latest_for_restart_with_log(&storage1, &event_log1, &net.state_dbs[0], 1, &expected_key)
            .expect_err("truncated checkpoint must propagate as error");
    assert!(
        err.to_string().contains("decoding checkpoint"),
        "error must mention decoding failure: {err}"
    );

    // The event log is independent of checkpoint corruption and must still
    // be readable.
    assert!(
        !event_log1.replay().expect("log replay succeeds").is_empty(),
        "event log must survive checkpoint truncation"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: valid checkpoint, missing state snapshot → verification error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_state_snapshot_surfaced_as_error_not_silent_accept() {
    let (tmp, net) = setup_and_stop().await;
    let data1 = tmp.path().join("node1");

    // Reopen storage to read the checkpoint round number.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let persisted = storage1.latest().expect("latest").expect("a checkpoint");
    let cp_round = persisted.checkpoint.payload.round;
    drop(storage1);

    // Remove the snapshot for this round from the snap keyspace.
    // prune_snapshots_before(round + 1) deletes all snapshots below round+1,
    // which includes our checkpoint round.
    net.state_dbs[0].prune_snapshots_before(cp_round + 1).expect("prune snapshots");

    // Reopen storage and event log after corruption.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let event_log1 = Arc::new(EventLog::open(&data1).expect("event log reopens"));

    // verify_persisted must reject: no snapshot → verification fails.
    assert!(
        !verify_persisted(&persisted, &net.state_dbs[0]),
        "verify_persisted must reject when the state snapshot is absent"
    );

    // latest_for_restart_with_log must surface the error, not return Ok(None).
    let expected_key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)).verifying_key();
    let err =
        latest_for_restart_with_log(&storage1, &event_log1, &net.state_dbs[0], 1, &expected_key)
            .expect_err("missing snapshot must error, not silently succeed");
    assert!(
        err.to_string().contains("failed verification"),
        "error message must mention verification failure: {err}"
    );

    // The event log is untouched and still readable.
    assert!(
        !event_log1.replay().expect("log replay succeeds").is_empty(),
        "event log must survive state-snapshot corruption"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: valid checkpoint, state hash mismatch → verification error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_hash_mismatch_surfaced_as_error_not_silent_accept() {
    let (tmp, net) = setup_and_stop().await;
    let data1 = tmp.path().join("node1");

    // Reopen storage to read the checkpoint round number.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let persisted = storage1.latest().expect("latest").expect("a checkpoint");
    let cp_round = persisted.checkpoint.payload.round;
    drop(storage1);

    // Overwrite the state snapshot with different bytes whose root cannot
    // match the committed state_hash.  This simulates a scenario where the
    // state database was replaced or corrupted externally.
    let wrong_bytes = b"this is not the original state snapshot";
    net.state_dbs[0].snapshot(cp_round, wrong_bytes).expect("snapshot overwrites");

    // Reopen storage and event log after corruption.
    let storage1 = Storage::new(&data1).expect("storage reopens");
    let event_log1 = Arc::new(EventLog::open(&data1).expect("event log reopens"));

    // verify_persisted must reject: root mismatch.
    assert!(
        !verify_persisted(&persisted, &net.state_dbs[0]),
        "verify_persisted must reject when the state hash doesn't match"
    );

    // latest_for_restart_with_log must surface the error.
    let expected_key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1)).verifying_key();
    let err =
        latest_for_restart_with_log(&storage1, &event_log1, &net.state_dbs[0], 1, &expected_key)
            .expect_err("state hash mismatch must error, not silently succeed");
    assert!(
        err.to_string().contains("failed verification"),
        "error message must mention verification failure: {err}"
    );

    // The event log is still readable.
    assert!(
        !event_log1.replay().expect("log replay succeeds").is_empty(),
        "event log must survive state-hash corruption"
    );
}
