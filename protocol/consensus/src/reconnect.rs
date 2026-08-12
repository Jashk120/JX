//! Phase 4 — wire codecs for the reconnect protocol.
//!
//! Serialization helpers for [`SignedCheckpoint`] and [`RosterHistory`], the
//! two consensus-owned types a `ReconnectResponse` carries. They live in
//! `consensus` — where both types are defined — so the gossip `proto` layer
//! stays free of consensus internals beyond the public types it already uses.
//!
//! The `SignedCheckpoint` encoding is self-describing: the roster snapshot
//! active at the checkpoint round is embedded, so a learner can verify the
//! signature quorum against the payload alone (no external roster lookup).

use crypto::{
    Hashable,
    MembershipRegistry,
    RosterHistory,
};
use primitives::{
    Event,
    NodeId,
    Signature,
};

use crate::checkpoint::{
    CheckpointPayload,
    CheckpointSig,
    SignedCheckpoint,
};

/// One event of a retained graph transferred by a reconnect checkpoint,
/// together with the exact record metadata a learner needs to reconstruct
/// the teacher's graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedEvent {
    pub event: Event,
    /// The creator's sequence number for this event.
    pub seq: u64,
    /// The event's birth round.
    pub round: u64,
    /// The teacher's stored `ancestor_seqs` row for the event.
    pub ancestor_seqs: Vec<u64>,
    /// The teacher's ordering for the event, if it was already ordered.
    pub round_received: Option<u64>,
}

/// Encodes `sc` as:
/// ```text
/// [round: u64 BE]
/// [state_hash: 32 bytes]
/// [roster_hash: 32 bytes]
/// [roster_snapshot_len: u32 BE][roster_snapshot bytes]
/// [sig_count: u32 BE]
///   per sig: [round: u64 BE][signer_id: u64 BE][sig: 64 bytes]
/// ```
pub fn encode_signed_checkpoint(sc: &SignedCheckpoint) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&sc.payload.round.to_be_bytes());
    buf.extend_from_slice(&sc.payload.state_hash);
    buf.extend_from_slice(&sc.payload.roster_hash);
    let roster_bytes = sc.payload.roster_snapshot.to_bytes();
    buf.extend_from_slice(&(roster_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&roster_bytes);
    buf.extend_from_slice(&(sc.sigs.len() as u32).to_be_bytes());
    for sig in &sc.sigs {
        buf.extend_from_slice(&sig.round.to_be_bytes());
        buf.extend_from_slice(&sig.signer.get().to_be_bytes());
        buf.extend_from_slice(sig.sig.as_bytes());
    }
    buf
}

/// The inverse of [`encode_signed_checkpoint`]. Rebuilds the
/// [`CheckpointPayload`] (reconstructing `roster_snapshot` from the embedded
/// registry bytes) and the `Vec<CheckpointSig>`. Returns `None` on any parse
/// failure, truncation, trailing bytes, or a roster snapshot that does not
/// hash to the committed `roster_hash`.
pub fn decode_signed_checkpoint(bytes: &[u8]) -> Option<SignedCheckpoint> {
    let mut cursor = bytes;
    let round = take_u64(&mut cursor)?;
    let state_hash = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let roster_hash = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let roster_len = take_u32(&mut cursor)? as usize;
    let roster_bytes = take_exact(&mut cursor, roster_len)?;
    let roster_snapshot = MembershipRegistry::from_bytes(roster_bytes)?;
    if roster_snapshot.hash() != roster_hash {
        return None;
    }
    let payload = CheckpointPayload { round, state_hash, roster_hash, roster_snapshot };

    let sig_count = take_u32(&mut cursor)? as usize;
    let mut sigs = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let sig_round = take_u64(&mut cursor)?;
        let signer = NodeId::new(take_u64(&mut cursor)?);
        let sig_bytes = take_exact(&mut cursor, 64)?;
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(sig_bytes);
        sigs.push(CheckpointSig { round: sig_round, signer, sig: Signature::new(sig_array) });
    }
    if !cursor.is_empty() {
        return None;
    }
    Some(SignedCheckpoint { payload, sigs })
}

/// Encodes `rh` as:
/// ```text
/// [entry_count: u32 BE]
///   per entry: [round: u64 BE][registry_len: u32 BE][registry bytes]
/// ```
/// where the registry bytes are [`MembershipRegistry::to_bytes`] — the same
/// canonical form `roster_hash` is computed over.
pub fn encode_roster_history(rh: &RosterHistory) -> Vec<u8> {
    let entries: Vec<(&u64, &MembershipRegistry)> = rh.snapshots().collect();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (round, registry) in entries {
        buf.extend_from_slice(&round.to_be_bytes());
        let registry_bytes = registry.to_bytes();
        buf.extend_from_slice(&(registry_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&registry_bytes);
    }
    buf
}

/// The inverse of [`encode_roster_history`]. Returns `None` on truncation or
/// an empty history.
pub fn decode_roster_history(bytes: &[u8]) -> Option<RosterHistory> {
    let mut cursor = bytes;
    let entry_count = take_u32(&mut cursor)? as usize;
    let mut snapshots = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let round = take_u64(&mut cursor)?;
        let registry_len = take_u32(&mut cursor)? as usize;
        let registry_bytes = take_exact(&mut cursor, registry_len)?;
        let registry = MembershipRegistry::from_bytes(registry_bytes)?;
        snapshots.push((round, registry));
    }
    if !cursor.is_empty() {
        return None;
    }
    RosterHistory::from_snapshots(snapshots)
}

fn take_exact<'a>(cursor: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let head = cursor.get(..len)?;
    *cursor = &cursor[len..];
    Some(head)
}

fn take_u32(cursor: &mut &[u8]) -> Option<u32> {
    let bytes = take_exact(cursor, 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn take_u64(cursor: &mut &[u8]) -> Option<u64> {
    let bytes = take_exact(cursor, 8)?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use crypto::RosterHistory;
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

    fn dummy_sig(round: u64, signer: u64) -> CheckpointSig {
        CheckpointSig { round, signer: NodeId::new(signer), sig: Signature::new([1u8; 64]) }
    }

    fn signed_checkpoint(round: u64, signers: &[u64]) -> SignedCheckpoint {
        let roster_snapshot = registry_of(signers);
        let payload = CheckpointPayload::new(round, [7u8; 32], roster_snapshot);
        let sigs = signers.iter().map(|&signer| dummy_sig(round, signer)).collect();
        SignedCheckpoint { payload, sigs }
    }

    #[test]
    fn signed_checkpoint_round_trips_one_signer() {
        let sc = signed_checkpoint(3, &[1]);
        let decoded = decode_signed_checkpoint(&encode_signed_checkpoint(&sc)).expect("decodes");
        assert_eq!(decoded.payload.round, sc.payload.round);
        assert_eq!(decoded.payload.state_hash, sc.payload.state_hash);
        assert_eq!(decoded.payload.roster_hash, sc.payload.roster_hash);
        assert_eq!(decoded.payload.roster_snapshot, sc.payload.roster_snapshot);
        assert_eq!(decoded.sigs, sc.sigs);
    }

    #[test]
    fn signed_checkpoint_round_trips_three_and_four_signers() {
        for signers in [&[1, 2, 3][..], &[1, 2, 3, 4][..]] {
            let sc = signed_checkpoint(9, signers);
            let decoded =
                decode_signed_checkpoint(&encode_signed_checkpoint(&sc)).expect("decodes");
            assert_eq!(decoded.payload.roster_snapshot, sc.payload.roster_snapshot);
            assert_eq!(decoded.sigs.len(), signers.len());
            assert_eq!(decoded.sigs, sc.sigs);
        }
    }

    #[test]
    fn signed_checkpoint_decode_rejects_truncation() {
        let sc = signed_checkpoint(3, &[1, 2, 3]);
        let bytes = encode_signed_checkpoint(&sc);
        for cut in [1, 40, 79, bytes.len() - 1] {
            assert_eq!(decode_signed_checkpoint(&bytes[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn signed_checkpoint_decode_rejects_trailing_bytes() {
        let sc = signed_checkpoint(3, &[1]);
        let mut bytes = encode_signed_checkpoint(&sc);
        bytes.push(0);
        assert_eq!(decode_signed_checkpoint(&bytes), None);
    }

    #[test]
    fn signed_checkpoint_decode_rejects_roster_hash_mismatch() {
        let mut sc = signed_checkpoint(3, &[1, 2]);
        sc.payload.roster_hash = [0xAA; 32];
        let mut bytes = encode_signed_checkpoint(&sc);
        // The payload's roster_hash was overwritten after encoding, so the
        // bytes now carry a snapshot whose hash disagrees with the header.
        let end = 8 + 32;
        bytes[end..end + 32].copy_from_slice(&[0xAA; 32]);
        assert_eq!(decode_signed_checkpoint(&bytes), None);
    }

    #[test]
    fn roster_history_round_trips_single_snapshot() {
        let history = RosterHistory::new(registry_of(&[1, 2]));
        let decoded = decode_roster_history(&encode_roster_history(&history)).expect("decodes");
        assert_eq!(decoded.roster_for_round(1), history.roster_for_round(1));
        assert_eq!(decoded.roster_for_round(50), history.roster_for_round(50));
    }

    #[test]
    fn roster_history_round_trips_multi_snapshot() {
        let mut history = RosterHistory::new(registry_of(&[1, 2]));
        history.schedule(5, registry_of(&[1, 2, 3]));
        history.schedule(9, registry_of(&[1, 2, 3, 4]));
        let decoded = decode_roster_history(&encode_roster_history(&history)).expect("decodes");
        assert_eq!(decoded.roster_for_round(4), history.roster_for_round(4));
        assert_eq!(decoded.roster_for_round(5), history.roster_for_round(5));
        assert_eq!(decoded.roster_for_round(9), history.roster_for_round(9));
    }

    #[test]
    fn roster_history_decode_rejects_truncation_and_empty() {
        let history = RosterHistory::new(registry_of(&[1]));
        let bytes = encode_roster_history(&history);
        assert_eq!(decode_roster_history(&bytes[..bytes.len() - 1]), None);
        // Empty history (no entries) is rejected.
        assert!(decode_roster_history(&[]).is_none());
    }
}
