//! Translations between the protobuf mirror types and the canonical
//! consensus/primitives forms (Phase 8, §4).
//!
//! The canonical binary encodings (`.cp` checkpoints, `encode_retained_event`,
//! gossip frames) stay the source of truth for internal use; these functions
//! build the mirror-facing protobuf views and translate back for verification.

use consensus::{
    CheckpointPayload,
    CheckpointSig,
    Hashgraph,
    RetainedEvent,
    SignedCheckpoint,
};
use crypto::{
    Hashable,
    MembershipRegistry,
};
use ed25519_dalek::VerifyingKey;
use primitives::{
    Event,
    EventHash,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};

use crate::error::{
    Result,
    StreamError,
};
use crate::pb;

/// The mirror `Event` for a freshly inserted event's record. `round_received`
/// is carried through when the record already knows it (e.g. an event a
/// reconnect teacher delivered already ordered); ordering is backfilled only
/// via the record stream, never into the event stream.
pub fn retained_event_to_proto(record: &RetainedEvent) -> pb::Event {
    pb::Event {
        creator: record.event.creator().get(),
        self_parent: record.event.self_parent().map(|hash| hash.as_bytes().to_vec()),
        other_parent: record.event.other_parent().map(|hash| hash.as_bytes().to_vec()),
        timestamp: record.event.timestamp().get(),
        transactions: record
            .event
            .payload()
            .iter()
            .map(|tx| pb::Transaction { payload: tx.payload().to_vec() })
            .collect(),
        signature: record.event.signature().as_bytes().to_vec(),
        seq: record.seq,
        birth_round: record.round,
        round_received: record.round_received,
        consensus_timestamp: None,
    }
}

/// The inverse of [`retained_event_to_proto`]: rebuilds the event from its
/// mirror form. `None` on a wrong-width hash or signature, or a malformed
/// optional field.
pub fn proto_to_event(event: &pb::Event) -> Option<Event> {
    let self_parent = proto_hash(event.self_parent.as_deref())?;
    let other_parent = proto_hash(event.other_parent.as_deref())?;
    let signature = proto_signature(event.signature.as_slice())?;
    let payload: Vec<Transaction> =
        event.transactions.iter().map(|tx| Transaction::from_bytes(tx.payload.clone())).collect();
    let unsigned = UnsignedEvent::new(
        primitives::NodeId::new(event.creator),
        self_parent,
        other_parent,
        Timestamp::new(event.timestamp),
        payload,
    );
    Some(unsigned.finalize(signature))
}

/// Reads an optional 32-byte `EventHash` from its mirror `bytes` form.
fn proto_hash(bytes: Option<&[u8]>) -> Option<Option<EventHash>> {
    match bytes {
        None => Some(None),
        Some(bytes) => {
            let hash: [u8; 32] = bytes.try_into().ok()?;
            Some(Some(EventHash::new(hash)))
        }
    }
}

/// Reads the 64-byte Ed25519 signature from its mirror form.
fn proto_signature(bytes: &[u8]) -> Option<Signature> {
    let signature: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::new(signature))
}

/// The mirror `SignedCheckpoint` for the canonical consensus form. The roster
/// snapshot is emitted as sorted `(node_id, key)` pairs, and the signatures
/// keep their canonical order.
pub fn signed_checkpoint_to_proto(checkpoint: &SignedCheckpoint) -> pb::SignedCheckpoint {
    pb::SignedCheckpoint {
        round: checkpoint.payload.round,
        state_hash: checkpoint.payload.state_hash.to_vec(),
        roster_hash: checkpoint.payload.roster_hash.to_vec(),
        roster_snapshot: checkpoint
            .payload
            .roster_snapshot
            .member_ids()
            .into_iter()
            .map(|node| {
                let key = checkpoint
                    .payload
                    .roster_snapshot
                    .key_for(&node)
                    .expect("member_ids yields registered members");
                pb::CheckpointRosterMember { node_id: node.get(), key: key.to_bytes().to_vec() }
            })
            .collect(),
        sigs: checkpoint
            .sigs
            .iter()
            .map(|sig| pb::CheckpointSig {
                round: sig.round,
                signer: sig.signer.get(),
                sig: sig.sig.as_bytes().to_vec(),
            })
            .collect(),
    }
}

/// The inverse of [`signed_checkpoint_to_proto`]: rebuilds the canonical
/// `SignedCheckpoint`, verifying that the embedded roster snapshot really
/// hashes to the committed `roster_hash` (a mirror's own quorum verification
/// then works against the payload alone). `None` on wrong-width fields or a
/// roster hash mismatch.
pub fn proto_to_signed_checkpoint(checkpoint: &pb::SignedCheckpoint) -> Option<SignedCheckpoint> {
    let state_hash: [u8; 32] = checkpoint.state_hash.clone().try_into().ok()?;
    let roster_hash: [u8; 32] = checkpoint.roster_hash.clone().try_into().ok()?;
    let roster_snapshot = roster_from_members(&checkpoint.roster_snapshot)?;
    if roster_snapshot.hash() != roster_hash {
        return None;
    }
    let payload =
        CheckpointPayload { round: checkpoint.round, state_hash, roster_hash, roster_snapshot };
    let mut sigs = Vec::with_capacity(checkpoint.sigs.len());
    for sig in &checkpoint.sigs {
        let sig_bytes: [u8; 64] = sig.sig.clone().try_into().ok()?;
        sigs.push(CheckpointSig {
            round: sig.round,
            signer: primitives::NodeId::new(sig.signer),
            sig: Signature::new(sig_bytes),
        });
    }
    Some(SignedCheckpoint { payload, sigs })
}

/// Rebuilds a `MembershipRegistry` from the mirror's sorted member list.
fn roster_from_members(members: &[pb::CheckpointRosterMember]) -> Option<MembershipRegistry> {
    let mut registry = MembershipRegistry::new();
    for member in members {
        let key_bytes: [u8; 32] = member.key.clone().try_into().ok()?;
        let key = VerifyingKey::from_bytes(&key_bytes).ok()?;
        registry.register(primitives::NodeId::new(member.node_id), key);
    }
    Some(registry)
}

/// The key `node_id`'s roster entry in a checkpoint mirror, if any. A mirror
/// verifies a node's `.rsf_sig` against the emitting node's key, which it
/// reads from the file's own embedded roster.
pub fn checkpoint_member_key(
    checkpoint: &pb::SignedCheckpoint,
    node_id: u64,
) -> Option<VerifyingKey> {
    let member = checkpoint.roster_snapshot.iter().find(|member| member.node_id == node_id)?;
    let key_bytes: [u8; 32] = member.key.clone().try_into().ok()?;
    VerifyingKey::from_bytes(&key_bytes).ok()
}

/// The record items of a decided round: every transaction of every event in
/// [`Hashgraph::consensus_order`], in that order, tagged with its source
/// event hash and payload index. Deterministic on every node by construction.
pub fn record_items_for_round(hashgraph: &Hashgraph, round: u64) -> Vec<pb::RecordItem> {
    let mut items = Vec::new();
    for hash in hashgraph.consensus_order(round) {
        let Some(record) = hashgraph.get(&hash) else { continue };
        for (index, tx) in record.event().payload().iter().enumerate() {
            items.push(pb::RecordItem {
                event_hash: hash.as_bytes().to_vec(),
                tx_index: index as u32,
                tx_payload: tx.payload().to_vec(),
            });
        }
    }
    items
}

/// Parses a `HashObject` commitment as a 32-byte digest. `None` for a wrong
/// algorithm, length, or byte count.
pub fn hash_object_digest(hash: &pb::HashObject) -> Option<[u8; 32]> {
    if hash.algorithm != crate::signature::HASH_ALGORITHM_SHA256
        || hash.length != crate::signature::HASH_LENGTH_SHA256
    {
        return None;
    }
    hash.hash.clone().try_into().ok()
}

/// The `HashObject` carrying a 32-byte digest.
pub fn digest_hash_object(digest: [u8; 32]) -> pb::HashObject {
    pb::HashObject {
        algorithm: crate::signature::HASH_ALGORITHM_SHA256,
        length: crate::signature::HASH_LENGTH_SHA256,
        hash: digest.to_vec(),
    }
}

/// Validates the embedded `round` fields of a record stream file against its
/// checkpoint anchor: both must agree.
pub fn check_round_consistency(file: &pb::RecordStreamFile) -> Result<()> {
    let Some(checkpoint) = &file.checkpoint else {
        return Err(StreamError::Malformed("record stream file has no checkpoint anchor".into()));
    };
    if file.round != checkpoint.round {
        return Err(StreamError::Malformed(format!(
            "record stream file round {} disagrees with its checkpoint round {}",
            file.round, checkpoint.round
        )));
    }
    Ok(())
}

/// Test-only helpers shared across the crate's test suites.
#[cfg(test)]
pub(crate) mod test_helpers {
    use ed25519_dalek::SigningKey;
    use primitives::NodeId;

    use super::MembershipRegistry;

    pub fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            registry
                .register(NodeId::new(id), SigningKey::from_bytes(&[id as u8; 32]).verifying_key());
        }
        registry
    }
}

#[cfg(test)]
mod tests {
    use consensus::{
        CheckpointPayload,
        CheckpointSig,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            registry.register(
                primitives::NodeId::new(id),
                SigningKey::generate(&mut OsRng).verifying_key(),
            );
        }
        registry
    }

    fn sample_record(creator: u64, seq: u64, round: u64) -> RetainedEvent {
        let event = UnsignedEvent::new(
            primitives::NodeId::new(creator),
            None,
            None,
            Timestamp::new(seq),
            vec![Transaction::from_bytes(vec![seq as u8])],
        )
        .finalize(Signature::new([seq as u8; 64]));
        RetainedEvent { event, seq, round, ancestor_seqs: vec![seq], round_received: None }
    }

    #[test]
    fn retained_event_round_trips_through_proto() {
        let record = sample_record(3, 7, 2);
        let proto = retained_event_to_proto(&record);
        assert_eq!(proto.creator, 3);
        assert_eq!(proto.seq, 7);
        assert_eq!(proto.birth_round, 2);
        assert_eq!(proto_to_event(&proto), Some(record.event));
    }

    #[test]
    fn signed_checkpoint_round_trips_through_proto() {
        let roster = registry_of(&[1, 2, 3]);
        let payload = CheckpointPayload::new(4, [7u8; 32], roster);
        let sigs = vec![CheckpointSig {
            round: 4,
            signer: primitives::NodeId::new(1),
            sig: Signature::new([9; 64]),
        }];
        let checkpoint = SignedCheckpoint { payload, sigs };
        let proto = signed_checkpoint_to_proto(&checkpoint);
        assert_eq!(proto_to_signed_checkpoint(&proto), Some(checkpoint));
    }

    #[test]
    fn proto_checkpoint_rejects_roster_hash_mismatch() {
        let roster = registry_of(&[1, 2]);
        let payload = CheckpointPayload::new(1, [0u8; 32], roster);
        let checkpoint = SignedCheckpoint { payload, sigs: Vec::new() };
        let mut proto = signed_checkpoint_to_proto(&checkpoint);
        proto.roster_hash[0] ^= 0xff;
        assert!(proto_to_signed_checkpoint(&proto).is_none());
    }
}
