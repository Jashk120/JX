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
    Result,
    bail,
};
use crypto::RosterHistory;
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

/// Builds the [`gossip::ReconnectResponse`] that reconstructs a node from a
/// verified persisted checkpoint. The roster history is seeded from the
/// checkpoint's embedded roster snapshot (static cluster scope), `retained`
/// is empty (the graph is not persisted), and `decided_round` is the
/// checkpoint round — `Hashgraph::from_checkpoint` already marks everything
/// at or below it decided.
pub fn build_reconnect_response(
    state: PersistedCheckpoint,
    node_id: u64,
) -> Result<gossip::ReconnectResponse> {
    let checkpoint = &state.checkpoint;
    if checkpoint.payload.roster_snapshot.key_for(&NodeId::new(node_id)).is_err() {
        bail!("node {node_id} is not a member of the persisted checkpoint roster");
    }
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

/// Loads, verifies, and wraps the latest persisted checkpoint for
/// `node_id`. Returns `Ok(None)` when the node has nothing persisted yet
/// (fresh start). Returns `Err` when a checkpoint exists but fails
/// verification — a corrupt disk state that must be surfaced, not silently
/// regenerated over.
pub fn latest_for_restart(
    storage: &crate::storage::Storage,
    node_id: u64,
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
    let response = build_reconnect_response(state, node_id)?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use consensus::{
        CheckpointAccumulator,
        CheckpointPayload,
        SignedCheckpoint,
    };
    use crypto::MembershipRegistry;
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
        let response = build_reconnect_response(state, 1).expect("builds");
        assert_eq!(response.signed_checkpoint, checkpoint);
        assert_eq!(response.decided_round, 4);
        assert!(response.retained.is_empty());
        assert!(!response.roster_history_bytes.is_empty());
    }
}
