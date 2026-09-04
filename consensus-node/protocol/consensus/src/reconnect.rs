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
    CanonicalEncode,
    Hashable,
    MembershipRegistry,
    RosterHistory,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};

use crate::checkpoint::{
    CheckpointPayload,
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
    /// The teacher's consensus timestamp for the event, if it was already
    /// ordered. `None` for unordered events or legacy records that predate
    /// the field (decoded as `None` for backward compatibility).
    pub consensus_timestamp: Option<Timestamp>,
}

/// Encodes a retained event to its canonical on-log/on-wire form:
///
/// ```text
/// [seq: u64 BE]
/// [round: u64 BE]
/// [round_received tag: u8]  — 0x00 (none) | 0x01 + [round_received: u64 BE]
/// [ancestor_seqs_len: u32 BE]
///   per seq: [u64 BE]
/// [event_len: u32 BE][event canonical bytes]
/// [consensus_timestamp tag: u8] — 0x00 (none) | 0x01 + [timestamp: u64 BE]
///   (trailing optional for backward compatibility; old records lack this)
/// ```
///
/// This is the record format of the durable event log (Phase 8): the full
/// record metadata a replay needs to rebuild the graph, plus the event
/// itself. It deliberately shares `RetainedEvent` with the reconnect
/// protocol so one type describes both the on-wire retained graph and the
/// on-log event set.
pub fn encode_retained_event(record: &RetainedEvent) -> Result<Vec<u8>, primitives::Error> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.seq.to_be_bytes());
    buf.extend_from_slice(&record.round.to_be_bytes());
    match record.round_received {
        Some(rr) => {
            buf.push(0x01);
            buf.extend_from_slice(&rr.to_be_bytes());
        }
        None => buf.push(0x00),
    }
    let ancestor_len =
        u32::try_from(record.ancestor_seqs.len()).map_err(|_| primitives::Error::OutOfRange {
            field: "RetainedEvent ancestor_seqs length",
            got: record.ancestor_seqs.len().to_string(),
        })?;
    buf.extend_from_slice(&ancestor_len.to_be_bytes());
    for seq in &record.ancestor_seqs {
        buf.extend_from_slice(&seq.to_be_bytes());
    }
    let event_bytes = record.event.canonical_bytes()?;
    let event_len =
        u32::try_from(event_bytes.len()).map_err(|_| primitives::Error::OutOfRange {
            field: "RetainedEvent event length",
            got: event_bytes.len().to_string(),
        })?;
    buf.extend_from_slice(&event_len.to_be_bytes());
    buf.extend_from_slice(&event_bytes);
    match record.consensus_timestamp {
        Some(ts) => {
            buf.push(0x01);
            buf.extend_from_slice(&ts.get().to_be_bytes());
        }
        None => buf.push(0x00),
    }
    Ok(buf)
}

/// The inverse of [`encode_retained_event`]. Returns `None` on truncation, a
/// bad optional tag, trailing bytes, or an event whose canonical bytes do not
/// decode. Backward compatible: old records lacking the trailing
/// `consensus_timestamp` field decode with `consensus_timestamp: None`.
pub fn decode_retained_event(bytes: &[u8]) -> Option<RetainedEvent> {
    let mut cursor = bytes;
    let seq = take_u64(&mut cursor)?;
    let round = take_u64(&mut cursor)?;
    let round_received = match take_exact(&mut cursor, 1)?[0] {
        0x00 => None,
        0x01 => Some(take_u64(&mut cursor)?),
        _ => return None,
    };
    let ancestor_count = take_u32(&mut cursor)? as usize;
    let ancestor_seqs: Vec<u64> =
        (0..ancestor_count).map(|_| take_u64(&mut cursor)).collect::<Option<_>>()?;
    let event_len = take_u32(&mut cursor)? as usize;
    let event_bytes = take_exact(&mut cursor, event_len)?;
    let event = decode_event_bytes(event_bytes)?;
    let consensus_timestamp = if cursor.is_empty() {
        None
    } else {
        let tag = take_exact(&mut cursor, 1)?[0];
        let ts = match tag {
            0x00 => None,
            0x01 => Some(Timestamp::new(take_u64(&mut cursor)?)),
            _ => return None,
        };
        if !cursor.is_empty() {
            return None;
        }
        ts
    };
    Some(RetainedEvent { event, seq, round, ancestor_seqs, round_received, consensus_timestamp })
}

/// Decodes a [`Event`] from its canonical byte form (the inverse of
/// `CanonicalEncode for Event`): creator, self_parent, other_parent,
/// timestamp, payload, signature — in exactly the field order the
/// canonical encoder writes.
fn decode_event_bytes(bytes: &[u8]) -> Option<Event> {
    let mut cursor = bytes;
    let creator = NodeId::new(take_u64(&mut cursor)?);
    let self_parent = take_optional_hash(&mut cursor)?;
    let other_parent = take_optional_hash(&mut cursor)?;
    let timestamp = Timestamp::new(take_u64(&mut cursor)?);
    let payload_count = take_u32(&mut cursor)? as usize;
    let payload = (0..payload_count)
        .map(|_| {
            let tx_len = take_u32(&mut cursor)? as usize;
            let tx_bytes = take_exact(&mut cursor, tx_len)?;
            Some(Transaction::from_bytes(tx_bytes.to_vec()))
        })
        .collect::<Option<Vec<_>>>()?;
    let signature_bytes = take_exact(&mut cursor, 64)?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    if !cursor.is_empty() {
        return None;
    }
    let unsigned = UnsignedEvent::new(creator, self_parent, other_parent, timestamp, payload);
    Some(unsigned.finalize(Signature::new(signature)))
}

fn take_optional_hash(cursor: &mut &[u8]) -> Option<Option<EventHash>> {
    match take_exact(cursor, 1)?[0] {
        0x00 => Some(None),
        0x01 => {
            let bytes = take_exact(cursor, 32)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            Some(Some(EventHash::new(hash)))
        }
        _ => None,
    }
}

/// Encodes `sc` as:
/// ```text
/// [round: u64 BE]
/// [records_root: 32 bytes]
/// [state_hash: 32 bytes]
/// [roster_hash: 32 bytes]
/// [prev_checkpoint_hash: 32 bytes]
/// [roster_snapshot_len: u32 BE][roster_snapshot bytes]
/// [signer_count: u32 BE]
///   per signer: [signer_id: u64 BE]
/// [aggregate_sig: 96 bytes]
/// ```
pub fn encode_signed_checkpoint(sc: &SignedCheckpoint) -> Result<Vec<u8>, primitives::Error> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&sc.payload.round.to_be_bytes());
    buf.extend_from_slice(&sc.payload.records_root);
    buf.extend_from_slice(&sc.payload.state_hash);
    buf.extend_from_slice(&sc.payload.roster_hash);
    buf.extend_from_slice(&sc.payload.prev_checkpoint_hash);
    let roster_bytes = sc.payload.roster_snapshot.to_bytes();
    let roster_len =
        u32::try_from(roster_bytes.len()).map_err(|_| primitives::Error::OutOfRange {
            field: "SignedCheckpoint roster_snapshot length",
            got: roster_bytes.len().to_string(),
        })?;
    buf.extend_from_slice(&roster_len.to_be_bytes());
    buf.extend_from_slice(&roster_bytes);
    let signer_count =
        u32::try_from(sc.signers.len()).map_err(|_| primitives::Error::OutOfRange {
            field: "SignedCheckpoint signers length",
            got: sc.signers.len().to_string(),
        })?;
    buf.extend_from_slice(&signer_count.to_be_bytes());
    for signer in &sc.signers {
        buf.extend_from_slice(&signer.get().to_be_bytes());
    }
    buf.extend_from_slice(&sc.aggregate_sig.to_bytes());
    Ok(buf)
}

/// The inverse of [`encode_signed_checkpoint`]. Rebuilds the
/// [`CheckpointPayload`] (reconstructing `roster_snapshot` from the embedded
/// registry bytes) and the aggregate signature. Returns `None` on any parse
/// failure, truncation, trailing bytes, or a roster snapshot that does not
/// hash to the committed `roster_hash`.
pub fn decode_signed_checkpoint(bytes: &[u8]) -> Option<SignedCheckpoint> {
    let mut cursor = bytes;
    let round = take_u64(&mut cursor)?;
    let records_root = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let state_hash = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let roster_hash = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let prev_checkpoint_hash = take_exact(&mut cursor, 32)?.try_into().ok()?;
    let roster_len = take_u32(&mut cursor)? as usize;
    let roster_bytes = take_exact(&mut cursor, roster_len)?;
    let roster_snapshot = MembershipRegistry::from_bytes(roster_bytes)?;
    let computed_hash = roster_snapshot.hash().ok()?;
    if computed_hash != roster_hash {
        return None;
    }
    let payload = CheckpointPayload {
        round,
        records_root,
        state_hash,
        roster_hash,
        prev_checkpoint_hash,
        roster_snapshot,
    };

    let signer_count = take_u32(&mut cursor)? as usize;
    const MIN_SIGNER: usize = 8;
    if signer_count > cursor.len().saturating_sub(96) / MIN_SIGNER {
        return None;
    }
    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let signer = NodeId::new(take_u64(&mut cursor)?);
        signers.push(signer);
    }
    let sig_bytes = take_exact(&mut cursor, 96)?;
    let mut sig_array = [0u8; 96];
    sig_array.copy_from_slice(sig_bytes);
    let aggregate_sig = blst::min_pk::Signature::from_bytes(&sig_array).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    Some(SignedCheckpoint { payload, aggregate_sig, signers })
}

/// Encodes `rh` as:
/// ```text
/// [entry_count: u32 BE]
///   per entry: [round: u64 BE][registry_len: u32 BE][registry bytes]
/// ```
/// where the registry bytes are [`MembershipRegistry::to_bytes`] — the same
/// canonical form `roster_hash` is computed over.
pub fn encode_roster_history(rh: &RosterHistory) -> Result<Vec<u8>, primitives::Error> {
    let entries: Vec<(&u64, &MembershipRegistry)> = rh.snapshots().collect();
    let mut buf = Vec::new();
    let entry_count = u32::try_from(entries.len()).map_err(|_| primitives::Error::OutOfRange {
        field: "RosterHistory entry count",
        got: entries.len().to_string(),
    })?;
    buf.extend_from_slice(&entry_count.to_be_bytes());
    for (round, registry) in entries {
        buf.extend_from_slice(&round.to_be_bytes());
        let registry_bytes = registry.to_bytes();
        let registry_len =
            u32::try_from(registry_bytes.len()).map_err(|_| primitives::Error::OutOfRange {
                field: "RosterHistory registry length",
                got: registry_bytes.len().to_string(),
            })?;
        buf.extend_from_slice(&registry_len.to_be_bytes());
        buf.extend_from_slice(&registry_bytes);
    }
    Ok(buf)
}

/// The inverse of [`encode_roster_history`]. Returns `None` on truncation or
/// an empty history.
pub fn decode_roster_history(bytes: &[u8]) -> Option<RosterHistory> {
    let mut cursor = bytes;
    let entry_count = take_u32(&mut cursor)? as usize;
    const MIN_ENTRY: usize = 8 + 4;
    if entry_count > cursor.len() / MIN_ENTRY {
        return None;
    }
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
            let bls = crypto::bls::BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls");
            registry.register(
                NodeId::new(id),
                SigningKey::generate(&mut OsRng).verifying_key(),
                bls.public.to_bytes(),
            );
        }
        registry
    }

    fn signed_checkpoint(round: u64, signers: &[u64]) -> SignedCheckpoint {
        let roster_snapshot = registry_of(signers);
        let payload = CheckpointPayload::new(
            round,
            crate::checkpoint::compute_records_root(&[]),
            [7u8; 32],
            roster_snapshot,
        );
        let mut sigs = Vec::new();
        for &signer in signers {
            let bls = crypto::bls::BlsIdentity::from_ikm(&[signer as u8; 32]).expect("bls");
            sigs.push(bls.sign(&payload.signing_bytes()));
        }
        let _sig_refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
        let mut sorted_signers: Vec<primitives::NodeId> =
            signers.iter().map(|&id| primitives::NodeId::new(id)).collect();
        sorted_signers.sort();
        let mut pairs: Vec<(primitives::NodeId, blst::min_pk::Signature)> =
            signers.iter().zip(sigs).map(|(&id, sig)| (primitives::NodeId::new(id), sig)).collect();
        pairs.sort_by_key(|(id, _)| *id);
        let sorted_refs: Vec<&blst::min_pk::Signature> = pairs.iter().map(|(_, s)| s).collect();
        let agg = crypto::bls::aggregate(&sorted_refs).expect("aggregate");
        SignedCheckpoint { payload, aggregate_sig: agg, signers: sorted_signers }
    }

    #[test]
    fn signed_checkpoint_round_trips_one_signer() {
        let sc = signed_checkpoint(3, &[1]);
        let decoded =
            decode_signed_checkpoint(&encode_signed_checkpoint(&sc).unwrap()).expect("decodes");
        assert_eq!(decoded.payload.round, sc.payload.round);
        assert_eq!(decoded.payload.state_hash, sc.payload.state_hash);
        assert_eq!(decoded.payload.roster_hash, sc.payload.roster_hash);
        assert_eq!(decoded.payload.records_root, sc.payload.records_root);
        assert_eq!(decoded.payload.roster_snapshot, sc.payload.roster_snapshot);
        assert_eq!(decoded.aggregate_sig, sc.aggregate_sig);
        assert_eq!(decoded.signers, sc.signers);
    }

    #[test]
    fn signed_checkpoint_round_trips_three_and_four_signers() {
        for signers in [&[1, 2, 3][..], &[1, 2, 3, 4][..]] {
            let sc = signed_checkpoint(9, signers);
            let decoded =
                decode_signed_checkpoint(&encode_signed_checkpoint(&sc).unwrap()).expect("decodes");
            assert_eq!(decoded.payload.roster_snapshot, sc.payload.roster_snapshot);
            assert_eq!(decoded.signers.len(), signers.len());
            assert_eq!(decoded.aggregate_sig, sc.aggregate_sig);
            assert_eq!(decoded.signers, sc.signers);
        }
    }

    #[test]
    fn signed_checkpoint_decode_rejects_truncation() {
        let sc = signed_checkpoint(3, &[1, 2, 3]);
        let bytes = encode_signed_checkpoint(&sc).unwrap();
        for cut in [1, 40, 79, bytes.len() - 1] {
            assert_eq!(decode_signed_checkpoint(&bytes[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn signed_checkpoint_decode_rejects_trailing_bytes() {
        let sc = signed_checkpoint(3, &[1]);
        let mut bytes = encode_signed_checkpoint(&sc).unwrap();
        bytes.push(0);
        assert_eq!(decode_signed_checkpoint(&bytes), None);
    }

    #[test]
    fn signed_checkpoint_decode_rejects_roster_hash_mismatch() {
        let mut sc = signed_checkpoint(3, &[1, 2]);
        sc.payload.roster_hash = [0xAA; 32];
        let mut bytes = encode_signed_checkpoint(&sc).unwrap();
        // The payload's roster_hash was overwritten after encoding, so the
        // bytes now carry a snapshot whose hash disagrees with the header.
        let end = 8 + 32;
        bytes[end..end + 32].copy_from_slice(&[0xAA; 32]);
        assert_eq!(decode_signed_checkpoint(&bytes), None);
    }

    #[test]
    fn roster_history_round_trips_single_snapshot() {
        let history = RosterHistory::new(registry_of(&[1, 2]));
        let decoded =
            decode_roster_history(&encode_roster_history(&history).unwrap()).expect("decodes");
        assert_eq!(decoded.roster_for_round(1), history.roster_for_round(1));
        assert_eq!(decoded.roster_for_round(50), history.roster_for_round(50));
    }

    #[test]
    fn roster_history_round_trips_multi_snapshot() {
        let mut history = RosterHistory::new(registry_of(&[1, 2]));
        history.schedule(5, registry_of(&[1, 2, 3]));
        history.schedule(9, registry_of(&[1, 2, 3, 4]));
        let decoded =
            decode_roster_history(&encode_roster_history(&history).unwrap()).expect("decodes");
        assert_eq!(decoded.roster_for_round(4), history.roster_for_round(4));
        assert_eq!(decoded.roster_for_round(5), history.roster_for_round(5));
        assert_eq!(decoded.roster_for_round(9), history.roster_for_round(9));
    }

    #[test]
    fn roster_history_decode_rejects_truncation_and_empty() {
        let history = RosterHistory::new(registry_of(&[1]));
        let bytes = encode_roster_history(&history).unwrap();
        assert_eq!(decode_roster_history(&bytes[..bytes.len() - 1]), None);
        // Empty history (no entries) is rejected.
        assert!(decode_roster_history(&[]).is_none());
    }

    #[test]
    fn retained_event_round_trips_no_round_received() {
        let event = UnsignedEvent::new(
            NodeId::new(3),
            Some(EventHash::new([1; 32])),
            None,
            Timestamp::new(1234),
            vec![Transaction::from_bytes(vec![7u8; 12])],
        )
        .finalize(Signature::new([9; 64]));
        let record = RetainedEvent {
            event,
            seq: 4,
            round: 2,
            ancestor_seqs: vec![4, 0, 2],
            round_received: None,
            consensus_timestamp: None,
        };
        assert_eq!(decode_retained_event(&encode_retained_event(&record).unwrap()), Some(record));
    }

    #[test]
    fn retained_event_round_trips_with_round_received() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(5), Vec::new())
            .finalize(Signature::new([1; 64]));
        let record = RetainedEvent {
            event,
            seq: 1,
            round: 1,
            ancestor_seqs: vec![1],
            round_received: Some(3),
            consensus_timestamp: Some(Timestamp::new(999)),
        };
        assert_eq!(decode_retained_event(&encode_retained_event(&record).unwrap()), Some(record));
    }

    #[test]
    fn retained_event_decode_rejects_truncation() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(5), Vec::new())
            .finalize(Signature::new([1; 64]));
        let record = RetainedEvent {
            event,
            seq: 1,
            round: 1,
            ancestor_seqs: vec![1],
            round_received: Some(3),
            consensus_timestamp: Some(Timestamp::new(77)),
        };
        let bytes = encode_retained_event(&record).unwrap();
        for cut in [1, 9, 17, bytes.len() - 1] {
            assert_eq!(decode_retained_event(&bytes[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn retained_event_decode_rejects_trailing_bytes() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(5), Vec::new())
            .finalize(Signature::new([1; 64]));
        let record = RetainedEvent {
            event,
            seq: 1,
            round: 1,
            ancestor_seqs: vec![1],
            round_received: None,
            consensus_timestamp: None,
        };
        let mut bytes = encode_retained_event(&record).unwrap();
        bytes.push(0);
        assert_eq!(decode_retained_event(&bytes), None);
    }

    #[test]
    fn retained_event_decode_rejects_bad_round_received_tag() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(5), Vec::new())
            .finalize(Signature::new([1; 64]));
        let record = RetainedEvent {
            event,
            seq: 1,
            round: 1,
            ancestor_seqs: vec![1],
            round_received: None,
            consensus_timestamp: None,
        };
        let mut bytes = encode_retained_event(&record).unwrap();
        // Flip the round_received tag to an invalid value (0x7f).
        bytes[16] = 0x7f;
        assert_eq!(decode_retained_event(&bytes), None);
    }

    #[test]
    fn retained_event_decode_rejects_corrupt_record_bytes() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(5), Vec::new())
            .finalize(Signature::new([1; 64]));
        let record = RetainedEvent {
            event,
            seq: 1,
            round: 1,
            ancestor_seqs: vec![1],
            round_received: None,
            consensus_timestamp: None,
        };
        let mut bytes = encode_retained_event(&record).unwrap();
        // Corrupt the ancestor_seqs count (u32 BE after the round_received tag)
        // so the decoder cannot read that many rows — a structural failure.
        bytes[17..21].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_retained_event(&bytes), None);
    }

    #[test]
    fn signed_checkpoint_decode_rejects_hostile_sig_count_without_allocation() {
        let sc = signed_checkpoint(3, &[1]);
        let mut bytes = encode_signed_checkpoint(&sc).unwrap();
        // Layout: round(8) || records_root(32) || state_hash(32) ||
        // roster_hash(32) || prev_checkpoint_hash(32) || roster_len(u32)…
        let roster_len =
            u32::from_be_bytes(bytes[8 + 32 * 4..8 + 32 * 4 + 4].try_into().unwrap()) as usize;
        let sig_count_offset = 8 + 32 * 4 + 4 + roster_len;
        bytes[sig_count_offset..sig_count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_signed_checkpoint(&bytes), None);
    }

    #[test]
    fn roster_history_decode_rejects_hostile_entry_count_without_allocation() {
        let history = RosterHistory::new(registry_of(&[1]));
        let mut bytes = encode_roster_history(&history).unwrap();
        bytes[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_roster_history(&bytes), None);
    }
}
