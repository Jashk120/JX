//! Shared helpers for the mirror stream test suites.
//!
//! The stream crate is the *consensus node's* mirror-facing writer/reader; the
//! integration tests drive it the way the daemon and a mirror do. Keys are
//! deterministic per node id (`SigningKey::from_bytes(&[id as u8; 32])`), so
//! any test can reproduce a node's verifying key for verification.

use consensus::{
    CheckpointPayload,
    RetainedEvent,
    SignedCheckpoint,
};
use crypto::MembershipRegistry;
use ed25519_dalek::SigningKey;
use primitives::{
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};

/// The consensus key for `id`, deterministic across every test.
pub fn node_key(id: u64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}

/// The roster whose member `id` is registered under [`node_key`].
pub fn registry_of(members: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in members {
        let bls = crypto::BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls");
        registry.register(NodeId::new(id), node_key(id).verifying_key(), bls.public.to_bytes());
    }
    registry
}

/// A checkpoint for `round` with real BLS signatures from `signers`.
/// `members` is the roster active at the round; the returned checkpoint is
/// quorum-valid whenever `signers` exceeds 2/3 of `members`.
pub fn signed_checkpoint(round: u64, members: &[u64], signers: &[u64]) -> SignedCheckpoint {
    let payload = CheckpointPayload::new(
        round,
        consensus::compute_records_root(&[]),
        [round as u8; 32],
        registry_of(members),
    );
    let signing_bytes = payload.signing_bytes();
    let mut sigs = Vec::new();
    for &signer in signers {
        let bls = crypto::BlsIdentity::from_ikm(&[signer as u8; 32]).expect("bls");
        sigs.push(bls.sign(&signing_bytes));
    }
    let mut pairs: Vec<(NodeId, blst::min_pk::Signature)> =
        signers.iter().zip(sigs).map(|(&id, s)| (NodeId::new(id), s)).collect();
    pairs.sort_by_key(|(id, _)| *id);
    let refs: Vec<&blst::min_pk::Signature> = pairs.iter().map(|(_, s)| s).collect();
    let agg = crypto::bls::aggregate(&refs).expect("aggregate");
    let signers_sorted: Vec<NodeId> = {
        let mut v: Vec<NodeId> = signers.iter().map(|&id| NodeId::new(id)).collect();
        v.sort();
        v
    };
    SignedCheckpoint { payload, aggregate_sig: agg, signers: signers_sorted }
}

/// A `RetainedEvent` carrying one transaction, with deterministic metadata.
pub fn sample_record(creator: u64, seq: u64, round: u64) -> RetainedEvent {
    let event = UnsignedEvent::new(
        NodeId::new(creator),
        None,
        None,
        Timestamp::new(seq),
        vec![Transaction::from_bytes(format!("payload-{seq}").into_bytes())],
    )
    .finalize(Signature::new([seq as u8; 64]));
    RetainedEvent {
        event,
        seq,
        round,
        ancestor_seqs: vec![seq],
        round_received: None,
        consensus_timestamp: None,
    }
}

/// Reads `dir`'s stream files in order and returns their bytes for a
/// byte-for-byte comparison between two independently produced streams.
#[allow(dead_code)]
pub fn read_all_files(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("stream dir")
        .filter_map(|entry| {
            let entry = entry.expect("entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None; // skip temp files
            }
            Some((name, std::fs::read(entry.path()).expect("read")))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.into_iter().map(|(_, bytes)| bytes).collect()
}
