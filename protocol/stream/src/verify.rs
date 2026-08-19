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

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use consensus::SignedCheckpoint;
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
/// continuity + per-file signature files (against `node_id`'s key in each
/// file's embedded roster) + the embedded checkpoint quorum.
///
/// `trusted_roster_hash`, when `Some`, anchors each checkpoint's
/// `roster_snapshot` against a roster the caller already trusts. A mismatch
/// is rejected before signature verification — a fabricated roster could
/// make the self-referential quorum trivially pass. Pass `None` only when
/// no trusted roster exists; the caller must validate the roster through a
/// separate channel before trusting the restored state.
pub fn verify_record_stream_dir(
    dir: &Path,
    node_id: NodeId,
    trusted_roster_hash: Option<[u8; 32]>,
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
        if !checkpoint_quorum(checkpoint, trusted_roster_hash) {
            return Err(StreamError::BadQuorum);
        }
        let node_key = crate::convert::checkpoint_member_key(checkpoint, node_id.get())
            .ok_or_else(|| {
                StreamError::Malformed(format!(
                    "record file for round {round} embeds no key for node {}",
                    node_id.get()
                ))
            })?;
        verify_signature_file_for(&path, &bytes, &start, &end, Some(round), &node_key)?;
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

/// Verifies the ≥2/3 threshold-signed quorum of a checkpoint mirror: every
/// distinct, round-matching, roster-valid Ed25519 signature counts, and
/// `valid * 3 > total * 2` decides. A stale, forged, or duplicate signature
/// is a no-op — never a rejection.
///
/// When `expected_roster_hash` is `Some`, the checkpoint's `roster_hash`
/// is compared against it first. A mismatch means the file embeds a roster
/// the caller does not recognise — the quorum proof is rejected without
/// checking signatures. Pass `None` only when no trusted roster exists.
pub fn checkpoint_quorum(
    checkpoint: &pb::SignedCheckpoint,
    expected_roster_hash: Option<[u8; 32]>,
) -> bool {
    let Some(checkpoint) = proto_to_signed_checkpoint(checkpoint) else { return false };
    verify_checkpoint_quorum(&checkpoint, expected_roster_hash)
}

/// Quorum verification over the canonical form (same rule as
/// `gossip::verify_signed_checkpoint`, reimplemented here so a mirror —
/// which has no gossip dependency — can verify output source-agnostically).
fn verify_checkpoint_quorum(
    checkpoint: &SignedCheckpoint,
    expected_roster_hash: Option<[u8; 32]>,
) -> bool {
    if let Some(expected) = expected_roster_hash
        && checkpoint.payload.roster_hash != expected
    {
        return false;
    }
    let total = checkpoint.payload.roster_snapshot.len();
    let signing_bytes = checkpoint.payload.signing_bytes();
    let mut valid = 0usize;
    let mut seen = HashSet::new();
    for sig in &checkpoint.sigs {
        if sig.round != checkpoint.payload.round {
            continue;
        }
        if !seen.insert(sig.signer) {
            continue;
        }
        let Ok(key) = checkpoint.payload.roster_snapshot.key_for(&sig.signer) else { continue };
        let signature = ed25519_dalek::Signature::from_bytes(sig.sig.as_bytes());
        if key.verify_strict(&signing_bytes, &signature).is_ok() {
            valid += 1;
        }
    }
    valid * 3 > total * 2
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };

    use super::*;

    #[test]
    fn quorum_requires_two_thirds_plus_one() {
        let roster = crate::convert::test_helpers::registry_of(&[1, 2, 3, 4]);
        let payload = consensus::CheckpointPayload::new(1, [0u8; 32], roster);
        let signing_bytes = payload.signing_bytes();
        let mut sigs = Vec::new();
        for signer in [1, 2, 3] {
            let key = SigningKey::from_bytes(&[signer as u8; 32]);
            let signature = key.sign(&signing_bytes);
            sigs.push(consensus::CheckpointSig {
                round: 1,
                signer: NodeId::new(signer),
                sig: primitives::Signature::new(signature.to_bytes()),
            });
        }
        let checkpoint = SignedCheckpoint { payload, sigs };
        assert!(verify_checkpoint_quorum(&checkpoint, None));

        let mut below = checkpoint.clone();
        below.sigs.pop();
        assert!(!verify_checkpoint_quorum(&below, None));
    }

    #[test]
    fn forged_signature_does_not_tip_quorum() {
        let roster = crate::convert::test_helpers::registry_of(&[1, 2, 3, 4]);
        let payload = consensus::CheckpointPayload::new(1, [0u8; 32], roster);
        let signing_bytes = payload.signing_bytes();
        let sigs = [1, 2]
            .into_iter()
            .map(|signer| {
                let key = SigningKey::from_bytes(&[signer as u8; 32]);
                let signature = key.sign(&signing_bytes);
                consensus::CheckpointSig {
                    round: 1,
                    signer: NodeId::new(signer),
                    sig: primitives::Signature::new(signature.to_bytes()),
                }
            })
            .collect();
        let mut checkpoint = SignedCheckpoint { payload, sigs };
        // A forged third signature must not count toward quorum.
        checkpoint.sigs.push(consensus::CheckpointSig {
            round: 1,
            signer: NodeId::new(3),
            sig: primitives::Signature::new([0x42; 64]),
        });
        assert!(!verify_checkpoint_quorum(&checkpoint, None));
    }
}
