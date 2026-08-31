//! The mirror-side verifier: what a mirror (e.g. the Go mirror) does with the
//! stream files (Phase 8, §3.3).
//!
//! For every file in a directory:
//!
//! 1. **Chain integrity** — the first file's `start_running_hash` is the
//!    seed; every later file's `start_running_hash` equals the previous
//!    file's `end_running_hash`; and recomputing the §5 chain over the items
//!    reproduces the file's `end_running_hash`. Truncation or reordering
//!    anywhere is rejected.
//! 2. **Signature files** — each `.esf_sig`/`.rsf_sig` Ed25519 file
//!    signature proves the emitting node's authenticity and the file's
//!    integrity (SHA-256 over the whole file); the metadata signature commits
//!    the file metadata.
//! 3. **Checkpoint quorum (record stream)** — each embedded `SignedCheckpoint`
//!    is checked against its own embedded roster: `valid * 3 > total * 2`.
//!    No single node is trusted.

use std::fs;
use std::path::Path;

use consensus::{
    RecordsRootItem,
    SignedCheckpoint,
    compute_records_root,
};
use ed25519_dalek::VerifyingKey;
use primitives::NodeId;
use prost::Message;
use sha2::{
    Digest,
    Sha256,
};

use crate::convert::{
    hash_object_digest,
    proto_to_signed_checkpoint,
};
use crate::error::{
    Result,
    StreamError,
};
use crate::event::{
    event_files_in,
    read_event_stream_file,
};
use crate::record::{
    read_record_stream_file,
    record_files_in,
};
use crate::{
    STREAM_VERSION,
    pb,
    running_hash,
    signature,
    signature_file_name,
};

/// Verifies a whole event-stream directory exactly as a mirror would: chain
/// continuity + per-file signature files, using `node_key` (the emitting
/// node's Ed25519 key) for the signatures.
pub fn verify_event_stream_dir(dir: &Path, node_key: &VerifyingKey) -> Result<()> {
    let files = event_files_in(dir)?;
    if files.is_empty() {
        return Err(StreamError::EmptyDirectory);
    }
    let mut previous_end: Option<[u8; 32]> = None;
    for (index, path) in files {
        let bytes = fs::read(&path)?;
        let file = read_event_stream_file(&bytes)?;
        let start = digest_or_err(&file, &path, true)?;
        let end = digest_or_err(&file, &path, false)?;
        check_chain_link(start, previous_end, &format!("event file {index}"))?;
        verify_item_chain(&start, &end, &file.events, |event| event.encode_to_vec())?;
        verify_signature_file_for(&path, &bytes, &start, &end, None, node_key)?;
        previous_end = Some(end);
    }
    Ok(())
}

/// Verifies a whole record-stream directory exactly as a mirror would: chain
/// continuity + BLS aggregate verification (anchored against
/// `trusted_roster_hash`) + content binding via `records_root`.
///
/// `trusted_roster_hash` anchors each checkpoint's `roster_snapshot` against
/// a roster the caller already trusts. A mismatch is rejected before
/// signature verification — a fabricated roster could make the
/// self-referential quorum trivially pass. There is no `None` path; callers
/// must supply a trusted hash and fail-closed if none is available.
///
/// Content binding: `records_root` in the checkpoint must equal
/// `compute_records_root` over the file's `RecordItem` triples. The
/// `.rsf_sig` file is not consulted — it no longer exists.
pub fn verify_record_stream_dir(
    dir: &Path,
    _node_id: NodeId,
    trusted_roster_hash: [u8; 32],
) -> Result<()> {
    let files = record_files_in(dir)?;
    if files.is_empty() {
        return Err(StreamError::EmptyDirectory);
    }
    let mut previous_end: Option<[u8; 32]> = None;
    for (round, path) in files {
        let bytes = fs::read(&path)?;
        let file = read_record_stream_file(&bytes)?;
        let start = digest_or_err(&file, &path, true)?;
        let end = digest_or_err(&file, &path, false)?;
        check_chain_link(start, previous_end, &format!("record file for round {round}"))?;
        verify_item_chain(&start, &end, &file.items, |item| item.encode_to_vec())?;
        let checkpoint = file.checkpoint.as_ref().ok_or_else(|| {
            StreamError::Malformed(format!(
                "record file for round {round} has no checkpoint anchor"
            ))
        })?;
        if !verify_checkpoint_binding(checkpoint, trusted_roster_hash, &file.items) {
            return Err(StreamError::BadQuorum);
        }
        previous_end = Some(end);
    }
    Ok(())
}

/// Enforces the chain rule: the first file starts at the seed; every later
/// file starts where the previous one ended.
fn check_chain_link(start: [u8; 32], previous_end: Option<[u8; 32]>, label: &str) -> Result<()> {
    match previous_end {
        None if start != running_hash::CHAIN_SEED => Err(StreamError::BadChainStart),
        Some(previous) if start != previous => {
            Err(StreamError::ChainDiscontinuity(label.to_string()))
        }
        _ => Ok(()),
    }
}

/// Recomputes the §5 chain over the file's items and rejects any file whose
/// embedded `end_running_hash` does not match.
fn verify_item_chain<T>(
    start: &[u8; 32],
    end: &[u8; 32],
    items: &[T],
    serialize: impl Fn(&T) -> Vec<u8>,
) -> Result<()> {
    let mut current = *start;
    for item in items {
        let bytes = serialize(item);
        current = running_hash::chain_hash(&current, &running_hash::item_hash(&bytes));
    }
    if &current != end {
        return Err(StreamError::ChainDiscontinuity(
            "end_running_hash does not match the recomputed chain".into(),
        ));
    }
    Ok(())
}

/// Reads and verifies the signature file accompanying a stream file.
fn verify_signature_file_for(
    stream_path: &Path,
    stream_bytes: &[u8],
    start: &[u8; 32],
    end: &[u8; 32],
    round: Option<u64>,
    node_key: &VerifyingKey,
) -> Result<()> {
    let stream_name = stream_path.file_name().and_then(|name| name.to_str()).unwrap_or("unknown");
    let sig_path = stream_path.with_file_name(signature_file_name(stream_name));
    let sig_bytes =
        fs::read(&sig_path).map_err(|_| StreamError::MissingSignature(stream_name.to_string()))?;
    let signature_file = signature::read_signature_file(&sig_bytes)?;
    let metadata = signature::metadata_bytes(STREAM_VERSION, start, end, round);
    let file_digest: [u8; 32] = Sha256::digest(stream_bytes).into();
    let metadata_digest: [u8; 32] = Sha256::digest(&metadata).into();
    let file_ok = signature_file
        .file_signature
        .as_ref()
        .is_some_and(|object| signature::verify_signature_object(object, &file_digest, node_key));
    let metadata_ok = signature_file.metadata_signature.as_ref().is_some_and(|object| {
        signature::verify_signature_object(object, &metadata_digest, node_key)
    });
    if !file_ok {
        return Err(StreamError::BadSignature);
    }
    if !metadata_ok {
        return Err(StreamError::BadMetadataSignature);
    }
    Ok(())
}

/// The `start_running_hash` (or `end_running_hash`) commitment of a stream
/// file as a digest, validated by the file reader.
fn digest_or_err<T>(file: &T, path: &Path, is_start: bool) -> Result<[u8; 32]>
where
    T: RunningHashCommitments,
{
    let label = path.file_name().and_then(|name| name.to_str()).unwrap_or("unknown");
    file.commitment(is_start)
        .ok_or_else(|| StreamError::Malformed(format!("{label} is missing a running hash")))
}

/// Structural access to a stream file's two running-hash commitments.
trait RunningHashCommitments {
    fn commitment(&self, is_start: bool) -> Option<[u8; 32]>;
}

impl RunningHashCommitments for pb::EventStreamFile {
    fn commitment(&self, is_start: bool) -> Option<[u8; 32]> {
        if is_start {
            self.start_running_hash.as_ref().and_then(hash_object_digest)
        } else {
            self.end_running_hash.as_ref().and_then(hash_object_digest)
        }
    }
}

impl RunningHashCommitments for pb::RecordStreamFile {
    fn commitment(&self, is_start: bool) -> Option<[u8; 32]> {
        if is_start {
            self.start_running_hash.as_ref().and_then(hash_object_digest)
        } else {
            self.end_running_hash.as_ref().and_then(hash_object_digest)
        }
    }
}

/// Verifies the ≥2/3 BLS-aggregate quorum of a checkpoint mirror, anchored
/// against `expected_roster_hash`, and its `records_root` content binding.
/// A stale, forged, or duplicate signer is rejected.
pub fn checkpoint_quorum(
    checkpoint: &pb::SignedCheckpoint,
    expected_roster_hash: [u8; 32],
) -> bool {
    let Some(checkpoint) = proto_to_signed_checkpoint(checkpoint) else { return false };
    verify_checkpoint_quorum(&checkpoint, expected_roster_hash)
}

fn verify_checkpoint_quorum(checkpoint: &SignedCheckpoint, expected_roster_hash: [u8; 32]) -> bool {
    if checkpoint.payload.roster_hash != expected_roster_hash {
        return false;
    }
    checkpoint.verify()
}

fn verify_checkpoint_binding(
    checkpoint_pb: &pb::SignedCheckpoint,
    trusted_roster_hash: [u8; 32],
    items: &[pb::RecordItem],
) -> bool {
    let Some(cp) = proto_to_signed_checkpoint(checkpoint_pb) else { return false };
    if cp.payload.roster_hash != trusted_roster_hash {
        return false;
    }
    if !cp.verify() {
        return false;
    }
    let Some(computed) = records_root_from_items(items) else { return false };
    if computed != cp.payload.records_root {
        return false;
    }
    true
}

fn records_root_from_items(items: &[pb::RecordItem]) -> Option<[u8; 32]> {
    let mut rr_items = Vec::with_capacity(items.len());
    for item in items {
        let hash: [u8; 32] = item.event_hash.clone().try_into().ok()?;
        rr_items.push(RecordsRootItem {
            event_hash: hash,
            tx_index: item.tx_index,
            tx_payload: item.tx_payload.clone(),
        });
    }
    Some(compute_records_root(&rr_items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_requires_two_thirds_plus_one() {
        let roster = crate::convert::test_helpers::registry_of(&[1, 2, 3, 4]);
        let rr = consensus::compute_records_root(&[]);
        let payload = consensus::CheckpointPayload::new(1, rr, [0u8; 32], roster);
        // Build BLS aggregate for 3 signers
        let mut sigs = Vec::new();
        for signer in [1, 2, 3] {
            let bls = crypto::BlsIdentity::from_ikm(&[signer as u8; 32]).unwrap();
            sigs.push(bls.sign(&payload.signing_bytes()));
        }
        let refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
        let agg = crypto::bls::aggregate(&refs).unwrap();
        let checkpoint = SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)],
        };
        let hash = checkpoint.payload.roster_hash;
        assert!(verify_checkpoint_quorum(&checkpoint, hash));
        let checkpoint2 = SignedCheckpoint {
            payload: checkpoint.payload.clone(),
            aggregate_sig: {
                let s1 = crypto::BlsIdentity::from_ikm(&[1u8; 32])
                    .unwrap()
                    .sign(&checkpoint.payload.signing_bytes());
                let s2 = crypto::BlsIdentity::from_ikm(&[2u8; 32])
                    .unwrap()
                    .sign(&checkpoint.payload.signing_bytes());
                crypto::bls::aggregate(&[&s1, &s2]).unwrap()
            },
            signers: vec![NodeId::new(1), NodeId::new(2)],
        };
        assert!(!verify_checkpoint_quorum(&checkpoint2, hash));
    }

    #[test]
    fn forged_signature_does_not_tip_quorum() {
        let roster = crate::convert::test_helpers::registry_of(&[1, 2, 3, 4]);
        let rr = consensus::compute_records_root(&[]);
        let payload = consensus::CheckpointPayload::new(1, rr, [0u8; 32], roster);
        let s1 = crypto::BlsIdentity::from_ikm(&[1u8; 32]).unwrap().sign(&payload.signing_bytes());
        let s2 = crypto::BlsIdentity::from_ikm(&[2u8; 32]).unwrap().sign(&payload.signing_bytes());
        let forger =
            crypto::BlsIdentity::from_ikm(&[0xEEu8; 32]).unwrap().sign(&payload.signing_bytes());
        let agg = crypto::bls::aggregate(&[&s1, &s2, &forger]).unwrap();
        let checkpoint = SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)],
        };
        assert!(!verify_checkpoint_quorum(&checkpoint, checkpoint.payload.roster_hash));
    }
}
