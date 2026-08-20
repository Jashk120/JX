//! Phase 3 — signed state checkpoints.
//!
//! A [`CheckpointPayload`] is the unsigned commitment every node makes once a
//! round is decided: the round, the Merkle root of the deterministic `State`,
//! and the SHA-256 of the canonical roster active at that round. Each node
//! signs [`CheckpointPayload::signing_bytes`] — a fixed 72 bytes — and the
//! resulting [`CheckpointSig`]s are gossiped. A [`CheckpointAccumulator`]
//! collects them per round and yields a [`SignedCheckpoint`] the first time
//! the signers exceed 2/3 of the roster active at that round. That accepted
//! form authorises pruning old history from the live `Hashgraph`.

use std::collections::HashMap;

use crypto::{
    CanonicalEncode,
    Hashable,
    MembershipRegistry,
};
use primitives::{
    NodeId,
    Signature,
};

/// Rounds of raw events to keep after a checkpoint round is confirmed, so a
/// peer that fell behind by up to this many rounds can still delta-sync
/// normally (Phase 3, retention margin). Distinct from the checkpoint
/// cadence: this is a pruning-retention buffer, not a frequency. The gossip
/// layer subtracts it from the confirmed round before calling
/// `Hashgraph::prune_before_round`.
pub const RETENTION_ROUNDS: u64 = 2;

/// The unsigned payload every node commits to for a given round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPayload {
    pub round: u64,
    /// The Merkle root of the state as it stood when the round's events were
    /// finalized.
    pub state_hash: [u8; 32],
    /// SHA-256 of the canonical roster bytes active at `round`.
    pub roster_hash: [u8; 32],
    /// The roster active at `round`, for self-description.
    pub roster_snapshot: MembershipRegistry,
}

impl CheckpointPayload {
    /// Builds the payload, deriving `roster_hash` from the canonical
    /// serialization of `roster_snapshot`.
    pub fn new(round: u64, state_hash: [u8; 32], roster_snapshot: MembershipRegistry) -> Self {
        let roster_hash = roster_snapshot.hash();
        Self { round, state_hash, roster_hash, roster_snapshot }
    }

    /// Canonical bytes signed by each node: `round (8 BE) || state_hash (32)
    /// || roster_hash (32)`. Compact and unambiguous — every node derives the
    /// identical bytes for the same decided round.
    pub fn signing_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];
        buf[..8].copy_from_slice(&self.round.to_be_bytes());
        buf[8..40].copy_from_slice(&self.state_hash);
        buf[40..72].copy_from_slice(&self.roster_hash);
        buf
    }
}

/// One node's Ed25519 signature over [`CheckpointPayload::signing_bytes`] for
/// `round`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSig {
    pub round: u64,
    pub signer: NodeId,
    pub sig: Signature,
}

impl CanonicalEncode for CheckpointSig {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.round.to_be_bytes());
        buf.extend_from_slice(&self.signer.get().to_be_bytes());
        buf.extend_from_slice(self.sig.as_bytes());
    }
}

impl CheckpointSig {
    /// The inverse of [`CanonicalEncode`]: parses the fixed 80-byte wire form
    /// `round || signer || sig`. `None` for any other length.
    pub fn decode(bytes: &[u8]) -> Option<CheckpointSig> {
        if bytes.len() != 80 {
            return None;
        }
        let round = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let signer = NodeId::new(u64::from_be_bytes(bytes[8..16].try_into().ok()?));
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes[16..80]);
        Some(CheckpointSig { round, signer, sig: Signature::new(sig_bytes) })
    }
}

/// A [`CheckpointPayload`] together with ≥ 2/3-weight signatures: the
/// "accepted" form that authorises pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub payload: CheckpointPayload,
    pub sigs: Vec<CheckpointSig>,
}

/// Accumulates partial signatures for a single round until quorum is met.
pub struct CheckpointAccumulator {
    payload: CheckpointPayload,
    sigs: HashMap<NodeId, CheckpointSig>,
}

impl CheckpointAccumulator {
    pub fn new(payload: CheckpointPayload) -> Self {
        Self { payload, sigs: HashMap::new() }
    }

    /// The payload this accumulator is collecting signatures for.
    pub fn payload(&self) -> &CheckpointPayload {
        &self.payload
    }

    /// The signing bytes every collected signature is over.
    pub fn signing_bytes(&self) -> [u8; 72] {
        self.payload.signing_bytes()
    }

    /// Adds one signature. The signer **must** be a member of `registry`;
    /// non-members are silently rejected. Returns `Some(SignedCheckpoint)`
    /// the first time the collected signers exceed 2/3 of `registry`'s
    /// members — the roster active at the checkpoint round, not the live
    /// roster — and `None` otherwise. A duplicate signer counts once.
    ///
    /// Weight model: all nodes currently have unit stake, so the threshold is
    /// `sigs.len() * 3 > total_members * 2`, matching `finalize_round`. When
    /// stake weights are added, replace with
    /// `total_weight_of_signers * 3 > total_weight * 2`.
    pub fn add_sig(
        &mut self,
        sig: CheckpointSig,
        registry: &MembershipRegistry,
    ) -> Option<SignedCheckpoint> {
        if sig.round != self.payload.round {
            return None;
        }
        if !registry.contains(&sig.signer) {
            return None;
        }
        let total = registry.len();
        if self.sigs.len() * 3 > total * 2 {
            return None; // already accepted
        }
        self.sigs.entry(sig.signer).or_insert(sig);
        if self.sigs.len() * 3 > total * 2 {
            let mut sigs: Vec<CheckpointSig> = self.sigs.values().cloned().collect();
            sigs.sort_by_key(|s| s.signer);
            Some(SignedCheckpoint { payload: self.payload.clone(), sigs })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            registry.register(NodeId::new(id), SigningKey::generate(&mut OsRng).verifying_key());
        }
        registry
    }

    fn sig(round: u64, signer: u64) -> CheckpointSig {
        CheckpointSig { round, signer: NodeId::new(signer), sig: Signature::new([1u8; 64]) }
    }

    #[test]
    fn checkpoint_payload_signing_bytes_is_deterministic() {
        let roster = registry_of(&[1, 2, 3, 4]);
        let a = CheckpointPayload::new(3, [7u8; 32], roster.clone());
        let b = CheckpointPayload::new(3, [7u8; 32], roster);
        assert_eq!(a.signing_bytes(), b.signing_bytes());
        assert_eq!(a.signing_bytes().len(), 72);
        // A different round (or state) changes the commitment.
        assert_ne!(
            a.signing_bytes(),
            CheckpointPayload::new(4, [7u8; 32], a.roster_snapshot.clone()).signing_bytes()
        );
        assert_ne!(
            a.signing_bytes(),
            CheckpointPayload::new(3, [8u8; 32], a.roster_snapshot.clone()).signing_bytes()
        );
    }

    #[test]
    fn accumulator_accepts_quorum_at_two_thirds_plus_one() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], registry.clone()));
        assert!(accumulator.add_sig(sig(1, 1), &registry).is_none());
        assert!(accumulator.add_sig(sig(1, 2), &registry).is_none());
        let accepted = accumulator.add_sig(sig(1, 3), &registry);
        assert!(accepted.is_some());
        let accepted = accepted.unwrap();
        assert_eq!(accepted.payload.round, 1);
        assert_eq!(accepted.sigs.len(), 3);
    }

    #[test]
    fn accumulator_rejects_below_quorum() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], registry.clone()));
        assert!(accumulator.add_sig(sig(1, 1), &registry).is_none());
        assert!(accumulator.add_sig(sig(1, 2), &registry).is_none());
        // 2 of 4 is not a 2/3 supermajority.
        assert!(accumulator.add_sig(sig(1, 2), &registry).is_none());
    }

    #[test]
    fn accumulator_uses_round_roster_not_stale_roster() {
        let round_roster = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], round_roster.clone()));
        // A 5th node joins after the checkpoint round: the live roster is
        // bigger, but quorum must use the 4-node roster active at round 1.
        let live_roster = {
            let mut reg = round_roster.clone();
            reg.register(NodeId::new(5), SigningKey::generate(&mut OsRng).verifying_key());
            reg
        };
        // 3-of-4 is a supermajority (9 > 8); 3-of-5 is not (9 ≤ 10).
        accumulator.add_sig(sig(1, 1), &round_roster);
        accumulator.add_sig(sig(1, 2), &round_roster);
        let accepted = accumulator.add_sig(sig(1, 3), &round_roster);
        assert!(accepted.is_some(), "quorum computed from the round roster");

        // The same three sigs against the stale 5-node live roster would not
        // reach quorum.
        let mut stale =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], live_roster.clone()));
        stale.add_sig(sig(1, 1), &live_roster);
        stale.add_sig(sig(1, 2), &live_roster);
        assert!(stale.add_sig(sig(1, 3), &live_roster).is_none());
    }

    #[test]
    fn duplicate_signer_does_not_double_count() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], registry.clone()));
        accumulator.add_sig(sig(1, 1), &registry);
        // Same signer twice: still only one.
        assert!(accumulator.add_sig(sig(1, 1), &registry).is_none());
        accumulator.add_sig(sig(1, 2), &registry);
        assert!(accumulator.add_sig(sig(1, 2), &registry).is_none());
        // Two distinct signers is below quorum for 4 members; a third tips it.
        let accepted = accumulator.add_sig(sig(1, 3), &registry);
        assert!(accepted.is_some());
        assert_eq!(accepted.unwrap().sigs.len(), 3);
        // Once accepted, later adds are no-ops (the caller drops the
        // accumulator on acceptance anyway).
        assert!(accumulator.add_sig(sig(1, 4), &registry).is_none());
    }

    #[test]
    fn checkpoint_sig_round_trips_through_canonical_bytes() {
        let original = sig(42, 7);
        let bytes = original.canonical_bytes();
        assert_eq!(bytes.len(), 80);
        assert_eq!(CheckpointSig::decode(&bytes), Some(original));

        let mut bad = bytes[..79].to_vec();
        assert_eq!(CheckpointSig::decode(&bad), None);
        bad.push(0);
        bad.push(0);
        assert_eq!(CheckpointSig::decode(&bad), None);
    }

    #[test]
    fn wrong_round_sig_is_ignored() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], registry.clone()));
        assert!(accumulator.add_sig(sig(2, 1), &registry).is_none());
    }

    #[test]
    fn non_member_sig_is_ignored() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let mut accumulator =
            CheckpointAccumulator::new(CheckpointPayload::new(1, [0u8; 32], registry.clone()));
        // Node 5 is not in the registry.
        assert!(accumulator.add_sig(sig(1, 5), &registry).is_none());
        assert!(accumulator.sigs.is_empty());
    }
}
