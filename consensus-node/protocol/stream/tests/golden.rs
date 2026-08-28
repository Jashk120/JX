//! PLAN-2 Step 7 golden vectors: Rust↔Go byte-equality.
//!
//! Consumes `tests/testdata/plan2_golden.json` (shared with Go) and proves:
//! - `compute_records_root` matches expected hex for 0..5 items (incl. empty payload, padding).
//! - `CheckpointPayload::signing_bytes` 136B matches expected hex.
//! - `StateDiff` sorted LWW + tombstone protobuf encoding matches expected hex.

use std::fs;

use consensus::{
    CheckpointPayload,
    RecordsRootItem,
    compute_records_root,
};
use prost::Message;
use serde::Deserialize;
use sha2::{
    Digest,
    Sha256,
};
use stream::pb;

#[derive(Deserialize)]
struct Golden {
    records_root_vectors: Vec<RecordVector>,
    signing_bytes_vectors: Vec<SigningVector>,
    diff_encoding_vectors: Vec<DiffVector>,
}
#[derive(Deserialize)]
struct RecordVector {
    name: String,
    items: Vec<RecordItemJson>,
    expected_root_hex: String,
}
#[derive(Deserialize)]
struct RecordItemJson {
    event_hash_hex: String,
    tx_index: u32,
    tx_payload_hex: String,
}
#[derive(Deserialize)]
struct SigningVector {
    name: String,
    round: u64,
    records_root_hex: String,
    state_hash_hex: String,
    roster_hash_hex: String,
    prev_checkpoint_hash_hex: String,
    expected_signing_bytes_hex: String,
}
#[derive(Deserialize)]
struct DiffVector {
    name: String,
    diffs: Vec<DiffEntry>,
}
#[derive(Deserialize)]
struct DiffEntry {
    key_hex: String,
    value_hex: Option<String>,
    proto_hex: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
    }
    out
}
fn load_golden() -> Golden {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/plan2_golden.json");
    let data = fs::read_to_string(path).expect("read golden json");
    serde_json::from_str(&data).expect("parse golden json")
}

#[test]
fn records_root_golden_vectors_match_rust() {
    let golden = load_golden();
    assert!(
        golden.records_root_vectors.len() >= 6,
        "need at least 6 records_root vectors (0..5 incl empty payload)"
    );
    let has_three = golden.records_root_vectors.iter().any(|v| v.items.len() == 3);
    assert!(has_three, "need at least one 3-item vector to exercise padding/singleton");
    for vec in golden.records_root_vectors {
        let items: Vec<RecordsRootItem> = vec
            .items
            .iter()
            .map(|it| {
                let hash_bytes = hex_decode(&it.event_hash_hex);
                assert_eq!(hash_bytes.len(), 32, "vector {} bad hash len", vec.name);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                let payload = hex_decode(&it.tx_payload_hex);
                RecordsRootItem { event_hash: hash, tx_index: it.tx_index, tx_payload: payload }
            })
            .collect();
        let root = compute_records_root(&items);
        let expected = hex_decode(&vec.expected_root_hex);
        assert_eq!(expected.len(), 32, "vector {} bad expected len", vec.name);
        let mut exp = [0u8; 32];
        exp.copy_from_slice(&expected);
        assert_eq!(
            root,
            exp,
            "records_root mismatch for vector '{}' ({} items)",
            vec.name,
            items.len()
        );

        // Cross-check empty leaf/internal formulas for 1- and 2-item vectors sanity.
        if vec.name == "empty_0" {
            let empty: [u8; 32] = Sha256::digest([0x00u8]).into();
            assert_eq!(root, empty, "empty root must be SHA256(0x00)");
        }
    }
}

#[test]
fn signing_bytes_golden_vectors_are_136b_and_match() {
    let golden = load_golden();
    assert!(golden.signing_bytes_vectors.len() >= 5, "need at least 5 signing_bytes vectors");
    let has_genesis =
        golden.signing_bytes_vectors.iter().any(|v| v.prev_checkpoint_hash_hex == "00".repeat(32));
    assert!(has_genesis, "need at least one genesis (prev zeros) vector");
    let has_chained =
        golden.signing_bytes_vectors.iter().any(|v| v.prev_checkpoint_hash_hex != "00".repeat(32));
    assert!(has_chained, "need at least one chained non-zero prev vector");

    for vec in golden.signing_bytes_vectors {
        let rr = hex_decode(&vec.records_root_hex);
        let sh = hex_decode(&vec.state_hash_hex);
        let rh = hex_decode(&vec.roster_hash_hex);
        let prev = hex_decode(&vec.prev_checkpoint_hash_hex);
        assert_eq!(rr.len(), 32, "vector {} rr len", vec.name);
        assert_eq!(sh.len(), 32, "vector {} sh len", vec.name);
        assert_eq!(rh.len(), 32, "vector {} rh len", vec.name);
        assert_eq!(prev.len(), 32, "vector {} prev len", vec.name);
        let mut rr_a = [0u8; 32];
        let mut sh_a = [0u8; 32];
        let mut rh_a = [0u8; 32];
        let mut prev_a = [0u8; 32];
        rr_a.copy_from_slice(&rr);
        sh_a.copy_from_slice(&sh);
        rh_a.copy_from_slice(&rh);
        prev_a.copy_from_slice(&prev);

        // Build payload via roster hash directly (avoid MembershipRegistry hashing).
        // We construct a dummy registry and then override roster_hash by directly
        // using CheckpointPayload fields.
        let mut registry = crypto::MembershipRegistry::new();
        // Register a dummy member so roster_snapshot is non-empty for hash consistency,
        // but we will not use its hash; we use the fixture hashes directly via manual
        // signing bytes construction. Instead verify manual 136B construction equals
        // CheckpointPayload::signing_bytes when payload fields are set to fixture values.
        let dummy_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let dummy_bls = crypto::BlsIdentity::from_ikm(&[1u8; 32]).unwrap().public.to_bytes();
        registry.register(primitives::NodeId::new(1), dummy_key, dummy_bls);
        let mut payload = CheckpointPayload::new(vec.round, rr_a, sh_a, registry);
        // Override roster_hash to fixture value (new() derives it; we patch).
        payload.roster_hash = rh_a;
        payload.prev_checkpoint_hash = prev_a;

        let signing = payload.signing_bytes();
        assert_eq!(signing.len(), 136, "vector {} len", vec.name);
        let expected = hex_decode(&vec.expected_signing_bytes_hex);
        assert_eq!(expected.len(), 136, "vector {} expected len", vec.name);
        assert_eq!(signing.to_vec(), expected, "signing_bytes mismatch for vector '{}'", vec.name);

        // Also verify manual concatenation equals payload.signing_bytes.
        let mut manual = [0u8; 136];
        manual[..8].copy_from_slice(&vec.round.to_be_bytes());
        manual[8..40].copy_from_slice(&rr_a);
        manual[40..72].copy_from_slice(&sh_a);
        manual[72..104].copy_from_slice(&rh_a);
        manual[104..136].copy_from_slice(&prev_a);
        assert_eq!(signing, manual, "manual 136B mismatch for {}", vec.name);
    }
}

#[test]
fn diff_encoding_golden_vectors_match_rust_protobuf() {
    let golden = load_golden();
    assert!(golden.diff_encoding_vectors.len() >= 5, "need at least 5 diff vectors");
    for vec in golden.diff_encoding_vectors {
        // Sorted check: keys must be strictly increasing lexicographically.
        let mut prev: Option<Vec<u8>> = None;
        for entry in &vec.diffs {
            let key = hex_decode(&entry.key_hex);
            assert!(!key.is_empty(), "vector {} has empty key", vec.name);
            if let Some(p) = &prev {
                assert!(
                    p < &key,
                    "vector {} not sorted: prev {:x?} >= key {:x?}",
                    vec.name,
                    p,
                    key
                );
            }
            prev = Some(key.clone());
            // Proto hex round-trip via prost.
            let value = entry.value_hex.as_deref().map(hex_decode);
            let diff = stream::convert::StateDiff { key: key.clone(), value: value.clone() };
            let proto = stream::convert::state_diff_to_proto(&diff);
            let encoded = proto.encode_to_vec();
            let expected = hex_decode(&entry.proto_hex);
            assert_eq!(
                encoded, expected,
                "diff proto mismatch for vector '{}' key {:x?}",
                vec.name, key
            );
            // Decode back: None vs Some distinction preserved.
            let decoded = pb::StateDiff::decode(expected.as_slice()).expect("decode proto");
            assert_eq!(decoded.key, key, "decoded key mismatch");
            match &value {
                None => assert!(
                    decoded.value.is_none(),
                    "tombstone should decode to None for vector {}",
                    vec.name
                ),
                Some(v) => assert_eq!(
                    decoded.value.as_deref(),
                    Some(v.as_slice()),
                    "value mismatch for vector {}",
                    vec.name
                ),
            }
            // Also verify helper rejects empty key.
            if key.is_empty() {
                assert!(stream::convert::proto_to_state_diff(&proto).is_none());
            }
        }

        // Verify whole vec round-trips via state_diffs_to_proto / proto_to_state_diffs.
        let diffs: Vec<stream::convert::StateDiff> = vec
            .diffs
            .iter()
            .map(|e| stream::convert::StateDiff {
                key: hex_decode(&e.key_hex),
                value: e.value_hex.as_deref().map(hex_decode),
            })
            .collect();
        let protos = stream::convert::state_diffs_to_proto(&diffs);
        let back = stream::convert::proto_to_state_diffs(&protos).expect("back");
        assert_eq!(back, diffs, "state_diffs round-trip failed for {}", vec.name);

        // If empty, ensure proto_to_state_diffs handles it.
        if vec.name == "empty" {
            assert!(vec.diffs.is_empty());
            assert!(protos.is_empty());
        }
    }
}

#[test]
fn diff_encoding_tombstone_vs_empty_value_distinguished() {
    // Tombstone (None) must encode differently from empty value (Some([])).
    let tomb = stream::convert::StateDiff { key: b"k".to_vec(), value: None };
    let empty_val = stream::convert::StateDiff { key: b"k".to_vec(), value: Some(Vec::new()) };
    let tomb_proto = stream::convert::state_diff_to_proto(&tomb);
    let empty_proto = stream::convert::state_diff_to_proto(&empty_val);
    assert_ne!(
        tomb_proto.encode_to_vec(),
        empty_proto.encode_to_vec(),
        "tombstone vs empty value must have different protobuf bytes"
    );
    assert!(tomb_proto.value.is_none());
    assert!(empty_proto.value.is_some());
}

#[test]
fn records_root_empty_payload_and_varied_tx_index_covered() {
    // Ensure at least one vector has empty payload and varied tx_index to cover leaf edge.
    let golden = load_golden();
    let found = golden.records_root_vectors.iter().any(|v| {
        v.items.iter().any(|it| it.tx_payload_hex.is_empty())
            && v.items.iter().any(|it| it.tx_index != 0)
    });
    assert!(
        found,
        "need vector with empty payload and varied tx_index (covered by two_empty_payloads)"
    );
}
