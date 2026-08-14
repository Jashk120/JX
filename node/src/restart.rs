//! Restart recovery from a persisted checkpoint.
//!
//! A restarting node does not replay history: it loads its latest accepted
//! [`SignedCheckpoint`] plus the state snapshot that hashes to its committed
//! `state_hash`, verifies both, and rebuilds a [`gossip::ReconnectResponse`]
//! that [`gossip::GossipNode::from_checkpoint`] can consume. The retained
//! event graph is deliberately not persisted — the restarting node then
//! `request_reconnect()`s from a live peer for the event window. A
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
use sha2::{
    Digest,
    Sha256,
};

use crate::storage::PersistedCheckpoint;

/// Verifies a persisted checkpoint: the signature quorum must hold, and the
/// state bytes must hash to the committed `state_hash`.
pub fn verify_persisted(state: &PersistedCheckpoint) -> bool {
    if !gossip::verify_signed_checkpoint(&state.checkpoint) {
        return false;
    }
    let computed = Sha256::digest(&state.state_bytes);
    computed.as_slice() == state.checkpoint.payload.state_hash.as_slice()
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
/// verified persisted checkpoint. The roster history is seeded from the
/// checkpoint's embedded roster snapshot (static cluster scope), `retained`
/// is empty (the graph is not persisted), and `decided_round` is the
/// checkpoint round — `Hashgraph::from_checkpoint` already marks everything
/// at or below it decided.
pub fn build_reconnect_response(
    state: PersistedCheckpoint,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<gossip::ReconnectResponse> {
    let checkpoint = &state.checkpoint;
    check_own_key(checkpoint, node_id, expected_key)?;
    let roster_history = RosterHistory::new(checkpoint.payload.roster_snapshot.clone());
    let roster_history_bytes = consensus::encode_roster_history(&roster_history);
    Ok(gossip::ReconnectResponse {
        signed_checkpoint: checkpoint.clone(),
        state_bytes: state.state_bytes,
        roster_history_bytes,
        decided_round: checkpoint.payload.round,
        retained: Vec::new(),
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
/// is reproduced exactly instead of being re-derived.
pub fn replay_response(
    state: PersistedCheckpoint,
    node_id: u64,
    expected_key: &VerifyingKey,
    event_log: &storage::EventLog,
) -> Result<gossip::ReconnectResponse> {
    let checkpoint = &state.checkpoint;
    check_own_key(checkpoint, node_id, expected_key)?;
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

    Ok(gossip::ReconnectResponse {
        signed_checkpoint: checkpoint.clone(),
        state_bytes: state.state_bytes,
        roster_history_bytes: consensus::encode_roster_history(&roster_history),
        decided_round: checkpoint.payload.round,
        retained,
    })
}

/// Loads, verifies, and wraps the latest persisted checkpoint for
/// `node_id`. Returns `Ok(None)` when the node has nothing persisted yet
/// (fresh start). Returns `Err` when a checkpoint exists but fails
/// verification — a corrupt disk state that must be surfaced, not silently
/// regenerated over.
pub fn latest_for_restart(
    storage: &crate::storage::Storage,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<Option<gossip::ReconnectResponse>> {
    let Some(state) = storage.latest()? else {
        return Ok(None);
    };
    if !verify_persisted(&state) {
        bail!(
            "persisted checkpoint for round {} failed verification (quorum or state hash)",
            state.checkpoint.payload.round
        );
    }
    let response = build_reconnect_response(state, node_id, expected_key)?;
    Ok(Some(response))
}

/// Like [`latest_for_restart`], but rebuilds the retained graph from the
/// durable event log (Phase 8) instead of leaving it to be fetched from a
/// live peer. Returns `Ok(None)` when the node has nothing persisted yet.
pub fn latest_for_restart_with_log(
    storage: &crate::storage::Storage,
    event_log: &storage::EventLog,
    node_id: u64,
    expected_key: &VerifyingKey,
) -> Result<Option<gossip::ReconnectResponse>> {
    let Some(state) = storage.latest()? else {
        return Ok(None);
    };
    if !verify_persisted(&state) {
        bail!(
            "persisted checkpoint for round {} failed verification (quorum or state hash)",
            state.checkpoint.payload.round
        );
    }
    let response = replay_response(state, node_id, expected_key, event_log)?;
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

    use super::*;

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

    #[test]
    fn verify_persisted_accepts_valid_state() {
        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(3, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes };
        assert!(verify_persisted(&state), "state bytes must hash to state_hash");
    }

    #[test]
    fn verify_persisted_rejects_wrong_state_bytes() {
        let checkpoint = quorum_checkpoint(3, [7u8; 32], &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes: vec![9u8; 32] };
        assert!(!verify_persisted(&state), "mismatched state bytes must fail");
    }

    #[test]
    fn response_builds_with_expected_fields() {
        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint: checkpoint.clone(), state_bytes };
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let response = build_reconnect_response(state, 1, &key).expect("builds");
        assert_eq!(response.signed_checkpoint, checkpoint);
        assert_eq!(response.decided_round, 4);
        assert!(response.retained.is_empty());
        assert!(!response.roster_history_bytes.is_empty());
    }

    #[test]
    fn rejects_key_mismatch_in_persisted_roster() {
        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes };
        // The checkpoint roster holds `[1u8; 32]`'s key for node 1; restoring
        // with a different secret (e.g. after `jkaind init --force`) must be
        // rejected up front instead of silently stalling consensus.
        let rotated_key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let err =
            build_reconnect_response(state, 1, &rotated_key).expect_err("mismatched key must fail");
        assert!(err.to_string().contains("secret key does not match"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_node_absent_from_persisted_roster() {
        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(4, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes };
        let key = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let err = build_reconnect_response(state, 3, &key).expect_err("absent node must fail");
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

        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(1, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes };

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
        let err = replay_response(state, 1, &key, &event_log).expect_err("corrupt log must fail");
        assert!(err.to_string().contains("failed verification"), "unexpected error: {err}");
    }

    #[test]
    fn replay_returns_the_logged_events_when_all_verify() {
        // Same setup, but the logged event is genuinely signed by a member
        // of the roster active at its birth round — the replay accepts it.
        let tmp = tempfile::tempdir().expect("temp dir");
        let event_log = storage::EventLog::open(tmp.path()).expect("event log opens");

        let state_bytes = vec![0u8; 32];
        let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
        let checkpoint = quorum_checkpoint(1, state_hash, &[1, 2]);
        let state = PersistedCheckpoint { checkpoint, state_bytes };

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
            replay_response(state, 1, &key1.verifying_key(), &event_log).expect("replays");
        assert_eq!(response.retained.len(), 1);
        assert_eq!(response.retained[0].round_received, Some(1));
    }
}
