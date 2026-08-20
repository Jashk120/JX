//! Restart recovery from a persisted checkpoint.
//!
//! A restarting node does not replay history: it loads its latest accepted
//! [`SignedCheckpoint`] plus the state snapshot that hashes to its committed
//! `state_hash`, verifies both, and rebuilds a [`gossip::ReconnectResponse`]
//! that [`gossip::GossipNode::from_checkpoint`] can consume. The state
//! snapshot for the checkpoint round is served from the Fjall state
//! database's `snap` keyspace (`state::StateDb`) — the `.snap` files are gone.
//! The retained event graph is deliberately not persisted — the restarting
//! node then `request_reconnect()`s from a live peer for the event window. A
//! simultaneous full-cluster restart re-geneses above the restored state,
//! which is acceptable for the smoke-test scope of a static 2-node cluster.

use anyhow::{
    Context,
    Result,
    bail,
};
use crypto::{
    Hashable,
    RosterHistory,
    Verifiable,
};
use ed25519_dalek::VerifyingKey;
use primitives::NodeId;
use state::StateDb;

use crate::storage::PersistedCheckpoint;

/// Rebuilds the executor state from `bytes` — canonical `State::to_bytes()`
/// for the checkpoint round — into `state_db`'s live partition, resetting any
/// prior contents first. Returns `None` on truncation or storage failure.
pub fn restore_state(state_db: &StateDb, bytes: &[u8]) -> Option<state::State> {
    state_db.clear_state().ok()?;
    state::State::from_bytes(state_db.state_keyspace(), bytes)
}

/// Verifies a persisted checkpoint: the signature quorum must hold, and the
/// state snapshot persisted for the checkpoint round must rebuild to the
/// committed Merkle root.
///
/// Verification is side-effect free: the snapshot bytes are decoded over a
/// temporary `StateDb` so the live `state` partition is never cleared. The
/// previous implementation cleared the live partition via `restore_state`,
/// which mutated the shared `StateDb` used by the running executor and made
/// concurrent verification destructive.
pub fn verify_persisted(state: &PersistedCheckpoint, state_db: &StateDb) -> bool {
    if !gossip::verify_signed_checkpoint(&state.checkpoint, state.checkpoint.payload.roster_hash) {
        return false;
    }
    let Some(bytes) = state_db.snapshot_for(state.checkpoint.payload.round).ok().flatten() else {
        return false;
    };
    let Ok(dir) = tempfile::tempdir() else {
        return false;
    };
    let Ok(tmp_db) = StateDb::open(dir.path()) else {
        return false;
    };
    let Some(rebuilt) = state::State::from_bytes(tmp_db.state_keyspace(), &bytes) else {
        return false;
    };
    rebuilt.root() == state.checkpoint.payload.state_hash
}

/// The persisted roster must agree with the node's current `expected_key`:
/// restoring a checkpoint whose roster holds a different key for this node
/// would make every event it signs fail verification and silently stall
/// consensus (a classic `jkaind init --force` key-rotation footgun). The two
/// failure modes are distinguished so the operator knows whether to restore
/// the original secret or wipe `data/` and re-genesis.
fn check_own_key(
    checkpoint: &consensus::SignedCheckpoint,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<()> {
    match checkpoint.payload.roster_snapshot.key_for(&NodeId::new(node_id)) {
        Err(_) => {
            bail!(
                "node {node_id}: this node's key is not in the checkpoint roster — if you are \
                 joining as a new member, wipe data/ and use `jkaind add-member` to join from \
                 the current round instead of restoring an incompatible checkpoint"
            );
        }
        Ok(key) if key.as_bytes() != expected_key.as_bytes() => {
            bail!(
                "node {node_id}: secret key does not match this node's verifying key in the \
                 checkpoint roster — restore the original secret or wipe data/ to re-genesis"
            );
        }
        Ok(_) => {}
    }
    Ok(())
}

/// Builds the [`gossip::ReconnectResponse`] that reconstructs a node from a
/// verified persisted checkpoint. The state snapshot for the checkpoint round
/// comes from the state database's `snap` keyspace, the roster history is
/// seeded from the checkpoint's embedded roster snapshot (static cluster
/// scope), `retained` is empty (the graph is not persisted), and
/// `decided_round` is the checkpoint round — `Hashgraph::from_checkpoint`
/// already marks everything at or below it decided.
pub fn build_reconnect_response(
    state: PersistedCheckpoint,
    state_db: &StateDb,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<gossip::ReconnectResponse> {
    let checkpoint = &state.checkpoint;
    check_own_key(checkpoint, node_id, expected_key)?;
    let bytes = snapshot_for_round(state_db, checkpoint.payload.round)?;
    let roster_history = RosterHistory::new(checkpoint.payload.roster_snapshot.clone());
    let roster_history_bytes = consensus::encode_roster_history(&roster_history);
    let last_timestamp = state_db.watermark().unwrap_or(None).unwrap_or(0);
    Ok(gossip::ReconnectResponse {
        signed_checkpoint: checkpoint.clone(),
        state_bytes: bytes,
        roster_history_bytes,
        decided_round: checkpoint.payload.round,
        retained: Vec::new(),
        last_timestamp,
    })
}

/// Builds the [`gossip::ReconnectResponse`] that reconstructs a node from a
/// verified persisted checkpoint **plus the durable event log** (Phase 8).
///
/// The retained graph is replayed from the local log instead of being
/// fetched from a live peer, so a node recovers independently. Each replayed
/// record is signature-verified against the roster active at its birth round
/// (the persisted roster history, falling back to the checkpoint's single
/// snapshot when no history was ever written — e.g. a static cluster), so a
/// corrupt or tampered log is surfaced at rebuild time rather than trusted.
///
/// `decided_round` is the checkpoint round; the replayed records already
/// carry their `roundReceived` (recorded by the previous run), so ordering
/// is reproduced exactly instead of being re-derived. The state bytes for the
/// checkpoint round come from the state database's `snap` keyspace.
pub fn replay_response(
    state: PersistedCheckpoint,
    state_db: &StateDb,
    node_id: u64,
    expected_key: &VerifyingKey,
    event_log: &storage::EventLog,
) -> Result<gossip::ReconnectResponse> {
    let checkpoint = &state.checkpoint;
    check_own_key(checkpoint, node_id, expected_key)?;
    let bytes = snapshot_for_round(state_db, checkpoint.payload.round)?;
    let roster_history = match event_log.roster_history()? {
        Some(bytes) => consensus::decode_roster_history(&bytes)
            .with_context(|| "decoding persisted roster history from the event log")?,
        None => RosterHistory::new(checkpoint.payload.roster_snapshot.clone()),
    };

    let mut retained = Vec::new();
    for record in event_log.replay()? {
        let roster = roster_history.roster_for_round(record.round);
        record.event.clone().verify(roster).with_context(|| {
            format!(
                "replayed event {:?} failed verification against the roster active at its \
                     birth round",
                record.event.hash()
            )
        })?;
        retained.push(record);
    }

    let watermark = state_db.watermark().unwrap_or(None).unwrap_or(0);
    let retained_max = retained
        .iter()
        .filter(|r| r.event.creator().get() == node_id)
        .map(|r| r.event.timestamp().get())
        .max()
        .unwrap_or(0);
    let last_timestamp = watermark.max(retained_max);
    Ok(gossip::ReconnectResponse {
        signed_checkpoint: checkpoint.clone(),
        state_bytes: bytes,
        roster_history_bytes: consensus::encode_roster_history(&roster_history),
        decided_round: checkpoint.payload.round,
        retained,
        last_timestamp,
    })
}

/// The persisted state snapshot for an accepted checkpoint `round`, or an
/// error when the state database holds no snapshot for it.
fn snapshot_for_round(state_db: &StateDb, round: u64) -> Result<Vec<u8>> {
    state_db
        .snapshot_for(round)?
        .ok_or_else(|| anyhow::anyhow!("no state snapshot for checkpoint round {round}"))
}

/// Loads, verifies, and wraps the latest persisted checkpoint for
/// `node_id`. Returns `Ok(None)` when the node has nothing persisted yet
/// (fresh start). Returns `Err` when a checkpoint exists but fails
/// verification — a corrupt disk state that must be surfaced, not silently
/// regenerated over.
pub fn latest_for_restart(
    storage: &crate::storage::Storage,
    state_db: &StateDb,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<Option<gossip::ReconnectResponse>> {
    let Some(state) = storage.latest()? else {
        return Ok(None);
    };
    if !verify_persisted(&state, state_db) {
        bail!(
            "persisted checkpoint for round {} failed verification (quorum or state hash)",
            state.checkpoint.payload.round
        );
    }
    let response = build_reconnect_response(state, state_db, node_id, expected_key)?;
    Ok(Some(response))
}

/// Like [`latest_for_restart`], but rebuilds the retained graph from the
/// durable event log (Phase 8) instead of leaving it to be fetched from a
/// live peer. Returns `Ok(None)` when the node has nothing persisted yet.
pub fn latest_for_restart_with_log(
    storage: &crate::storage::Storage,
    event_log: &storage::EventLog,
    state_db: &StateDb,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<Option<gossip::ReconnectResponse>> {
    let Some(state) = storage.latest()? else {
        return Ok(None);
    };
    if !verify_persisted(&state, state_db) {
        bail!(
            "persisted checkpoint for round {} failed verification (quorum or state hash)",
            state.checkpoint.payload.round
        );
    }
    let response = replay_response(state, state_db, node_id, expected_key, event_log)?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use consensus::{
        CheckpointAccumulator,
        CheckpointPayload,
        SignedCheckpoint,
    };
    use crypto::{
        MembershipRegistry,
        Signable,
    };
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };
    use primitives::Signature;
    use state::StateDb;
    use tempfile::TempDir;

    use super::*;

    /// A `StateDb` in a tempdir plus the directory guard, so the directory
    /// outlives the database.
    struct TestDb {
        _dir: TempDir,
        db: StateDb,
    }

    impl TestDb {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let db = StateDb::open(dir.path()).expect("state db opens");
            Self { _dir: dir, db }
        }
    }

    fn cluster_of(ids: &[u64]) -> (MembershipRegistry, Vec<(u64, SigningKey)>) {
        let mut registry = MembershipRegistry::new();
        let keys: Vec<(u64, SigningKey)> = ids
            .iter()
            .map(|&id| {
                let key = SigningKey::from_bytes(&[id as u8; 32]);
                registry.register(NodeId::new(id), key.verifying_key());
                (id, key)
            })
            .collect();
        (registry, keys)
    }

    /// Produces a genuine quorum-signed checkpoint for `round`, mirroring the
    /// accumulator path the gossip layer uses. For a 2-node roster both
    /// signatures are required (2/3 of 2 = 2), so adding them tips quorum.
    fn quorum_checkpoint(round: u64, state_hash: [u8; 32], ids: &[u64]) -> SignedCheckpoint {
        let (registry, keys) = cluster_of(ids);
        let payload = CheckpointPayload::new(round, state_hash, registry);
        let mut accumulator = CheckpointAccumulator::new(payload.clone());
        let mut accepted = None;
        for (id, key) in keys {
            let sig = key.sign(&payload.signing_bytes());
            let sig = consensus::CheckpointSig {
                round,
                signer: NodeId::new(id),
                sig: Signature::new(sig.to_bytes()),
            };
            accepted = accumulator.add_sig(sig, &payload.roster_snapshot);
        }
        accepted.expect("2-node cluster reaches quorum with both sigs")
    }

    /// An empty state's serialization plus its Merkle root — the smallest
    /// valid checkpoint state commitment.
    fn empty_state_bytes_and_root() -> (Vec<u8>, [u8; 32]) {
        let db = TestDb::new();
        let state = state::State::new(db.db.state_keyspace());
        (state.to_bytes(), state.root())
    }

    #[test]
    fn verify_persisted_accepts_valid_state() {
        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(3, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(3, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };
        assert!(verify_persisted(&state, &db.db), "state bytes must rebuild to state_hash");
    }

    #[test]
    fn verify_persisted_rejects_wrong_state_bytes() {
        let (_, empty_root) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(3, empty_root, &[1, 2]);
        // A non-empty state whose root cannot equal the empty-state root.
        let db = TestDb::new();
        let mut other = state::State::new(db.db.state_keyspace());
        other.apply(&state::Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        db.db.snapshot(3, &other.to_bytes()).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };
        assert!(!verify_persisted(&state, &db.db), "mismatched state bytes must fail");
    }

    #[test]
    fn verify_persisted_missing_snapshot_fails() {
        let (_, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(3, state_hash, &[1, 2]);
        let db = TestDb::new();
        let state = PersistedCheckpoint { checkpoint };
        assert!(!verify_persisted(&state, &db.db), "no snapshot means no verification");
    }

    #[test]
    fn response_builds_with_expected_fields() {
        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(4, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint: checkpoint.clone() };
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let response = build_reconnect_response(state, &db.db, 1, &key).expect("builds");
        assert_eq!(response.signed_checkpoint, checkpoint);
        assert_eq!(response.state_bytes, state_bytes, "snapshot bytes served verbatim");
        assert_eq!(response.decided_round, 4);
        assert!(response.retained.is_empty());
        assert!(!response.roster_history_bytes.is_empty());
    }

    #[test]
    fn rejects_key_mismatch_in_persisted_roster() {
        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(4, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };
        // The checkpoint roster holds `[1u8; 32]`'s key for node 1; restoring
        // with a different secret (e.g. after `jkaind init --force`) must be
        // rejected up front instead of silently stalling consensus.
        let rotated_key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let err = build_reconnect_response(state, &db.db, 1, &rotated_key)
            .expect_err("mismatched key must fail");
        assert!(err.to_string().contains("secret key does not match"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_node_absent_from_persisted_roster() {
        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(4, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };
        let key = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let err =
            build_reconnect_response(state, &db.db, 3, &key).expect_err("absent node must fail");
        assert!(
            err.to_string().contains("key is not in the checkpoint roster"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn replay_verifies_each_event_against_the_roster_at_its_birth_round() {
        // A checkpoint committing nodes 1 and 2 at round 1, an empty roster
        // history (so replay falls back to the checkpoint snapshot), and a
        // log holding an event signed by a creator that is NOT in that
        // roster: the replay must refuse the corrupt log.
        let tmp = tempfile::tempdir().expect("temp dir");
        let event_log = storage::EventLog::open(tmp.path()).expect("event log opens");

        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(1, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(1, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };

        let bogus = primitives::UnsignedEvent::new(
            primitives::NodeId::new(9),
            None,
            None,
            primitives::Timestamp::new(1),
            Vec::new(),
        )
        .finalize(primitives::Signature::new([9; 64]));
        event_log
            .append(&consensus::RetainedEvent {
                event: bogus,
                seq: 1,
                round: 1,
                ancestor_seqs: vec![1],
                round_received: None,
            })
            .expect("append");

        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let err =
            replay_response(state, &db.db, 1, &key, &event_log).expect_err("corrupt log must fail");
        assert!(err.to_string().contains("failed verification"), "unexpected error: {err}");
    }

    #[test]
    fn replay_returns_the_logged_events_when_all_verify() {
        // Same setup, but the logged event is genuinely signed by a member
        // of the roster active at its birth round — the replay accepts it.
        let tmp = tempfile::tempdir().expect("temp dir");
        let event_log = storage::EventLog::open(tmp.path()).expect("event log opens");

        let (state_bytes, state_hash) = empty_state_bytes_and_root();
        let checkpoint = quorum_checkpoint(1, state_hash, &[1, 2]);
        let db = TestDb::new();
        db.db.snapshot(1, &state_bytes).expect("snapshot");
        let state = PersistedCheckpoint { checkpoint };

        let key1 = SigningKey::from_bytes(&[1u8; 32]);
        let valid = primitives::UnsignedEvent::new(
            primitives::NodeId::new(1),
            None,
            None,
            primitives::Timestamp::new(1),
            Vec::new(),
        )
        .sign(&key1);
        event_log
            .append(&consensus::RetainedEvent {
                event: valid,
                seq: 1,
                round: 1,
                ancestor_seqs: vec![1],
                round_received: Some(1),
            })
            .expect("append");

        let response =
            replay_response(state, &db.db, 1, &key1.verifying_key(), &event_log).expect("replays");
        assert_eq!(response.retained.len(), 1);
        assert_eq!(response.retained[0].round_received, Some(1));
    }
}
