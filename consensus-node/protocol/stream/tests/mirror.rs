//! Mirror-consumer test: decodes and verifies the stream files exactly as the
//! Go mirror would — pure protobuf (prost) reads plus the verifier, no writer
//! code — proving cross-language decodability (Phase 8, §3.3 and §7.7).
//!
//! The setup phase produces files with the consensus-node writers; the
//! verification phase deliberately uses only `stream::pb` (the generated
//! protobuf types a Go mirror's prost equivalent would use) and
//! `stream::verify`, the way the mirror consumes them: read the bytes off
//! disk, decode the protobuf message, verify the chain + signature files +
//! checkpoint quorum.

mod common;

use std::fs;
use std::sync::Arc;

use common::{
    node_key,
    registry_of,
    sample_record,
};
use crypto::Hashable;
use prost::Message;
use storage::EventSink;
use stream::record::read_record_stream_file;
use stream::{
    EventStreamWriter,
    RecordStreamWriter,
    pb,
    verify,
};

/// Sets up a full record stream (3 rounds, quorum checkpoints, real
/// signatures) plus an event stream, using the writers — the consensus-node
/// side of the contract.
async fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let record_dir = tempfile::tempdir().expect("record temp dir");
    let record_writer = RecordStreamWriter::open(
        record_dir.path(),
        node_key(1),
        Arc::new(tokio::sync::Mutex::new(consensus::Hashgraph::new(&common::registry_of(&[
            1, 2, 3, 4,
        ])))),
    )
    .expect("record writer opens");
    for round in 1..=3 {
        let items: Vec<pb::RecordItem> = (0..2)
            .map(|i| pb::RecordItem {
                event_hash: vec![round as u8; 32],
                tx_index: i as u32,
                tx_payload: format!("round-{round}-tx-{i}").into_bytes(),
            })
            .collect();
        let checkpoint =
            common::signed_checkpoint_with_items(round, &[1, 2, 3, 4], &[1, 2, 3], &items);
        record_writer.submit_items(checkpoint, items);
    }
    record_writer.barrier().await;

    let event_dir = tempfile::tempdir().expect("event temp dir");
    let event_writer =
        EventStreamWriter::open(event_dir.path(), node_key(1), 2).expect("event writer opens");
    for seq in 1..=5 {
        event_writer.append(&sample_record(1, seq, 1));
    }
    event_writer.barrier().await;

    (record_dir, event_dir)
}

/// The mirror's view of one record file: raw protobuf decode, exactly what a
/// Go mirror's generated code does. No writer types are involved.
fn mirror_read_record(path: &std::path::Path) -> pb::RecordStreamFile {
    let bytes = fs::read(path).expect("read record file");
    pb::RecordStreamFile::decode(bytes.as_slice()).expect("prost decode (Go-equivalent)")
}

/// The mirror's view of one event file.
fn mirror_read_event(path: &std::path::Path) -> pb::EventStreamFile {
    let bytes = fs::read(path).expect("read event file");
    pb::EventStreamFile::decode(bytes.as_slice()).expect("prost decode (Go-equivalent)")
}

#[tokio::test]
async fn mirror_decodes_and_verifies_record_stream() {
    let (record_dir, _) = setup().await;

    // A mirror's own reads: decode every file through the protobuf types.
    let files = stream::record::record_files_in(record_dir.path()).expect("files");
    assert_eq!(files.len(), 3);
    let mut rounds = Vec::new();
    for (round, path) in &files {
        let file = mirror_read_record(path);
        assert_eq!(file.round, *round);
        assert_eq!(file.version, stream::STREAM_VERSION);
        assert_eq!(file.items.len(), 2, "round {round} carries its finalized transactions");
        // Every item links back to its source event.
        for item in &file.items {
            assert_eq!(item.event_hash.len(), 32);
            assert_eq!(item.tx_payload, format!("round-{round}-tx-{}", item.tx_index).as_bytes());
        }
        let checkpoint = file.checkpoint.as_ref().expect("anchored checkpoint");
        assert_eq!(checkpoint.round, *round);
        assert_eq!(checkpoint.roster_snapshot.len(), 4, "embedded roster is self-describing");
        rounds.push((*round, file));
    }
    // Rounds ascending.
    assert_eq!(rounds.iter().map(|(r, _)| *r).collect::<Vec<_>>(), vec![1, 2, 3]);

    // The mirror's verification: chain + BLS aggregate + records_root binding,
    // anchored by the trusted roster hash.
    let trusted_hash = registry_of(&[1, 2, 3, 4]).hash();
    verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(1), trusted_hash)
        .expect("record stream verifies end-to-end");

    // NodeId is now ignored for record files (BLS aggregate + records_root are
    // the trust anchors); any node that trusts the roster hash sees the same
    // result.
    verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(2), trusted_hash)
        .expect("record stream verifies for any node_id when roster hash is trusted");

    // Wrong trusted hash must fail even for the correct signer set.
    let wrong_hash = registry_of(&[1, 2, 3]).hash();
    assert!(
        verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(1), wrong_hash)
            .is_err(),
        "wrong trusted roster hash must fail"
    );
}

#[tokio::test]
async fn mirror_decodes_and_verifies_event_stream() {
    let (_, event_dir) = setup().await;

    let files = stream::event::event_files_in(event_dir.path()).expect("files");
    assert_eq!(files.len(), 2);
    let mut total_events = 0;
    for (index, path) in &files {
        let file = mirror_read_event(path);
        assert_eq!(file.version, stream::STREAM_VERSION);
        for event in &file.events {
            assert_eq!(event.creator, 1);
            assert_eq!(event.seq, total_events as u64 + 1, "events stream in insertion order");
            assert_eq!(event.birth_round, 1);
            total_events += 1;
        }
        assert!(!file.events.is_empty(), "event file {index} is non-empty");
    }
    assert_eq!(total_events, 4, "5 events in windows of 2 close 2 files (the 5th stays buffered)");

    // DAG rebuild: the mirror reconstructs each event from the mirror form.
    for (_, path) in &files {
        let file = mirror_read_event(path);
        for proto in &file.events {
            let event = stream::convert::proto_to_event(proto).expect("event rebuilds");
            assert_eq!(event.creator(), &primitives::NodeId::new(1));
            assert_eq!(event.timestamp().get(), proto.timestamp);
        }
    }

    verify::verify_event_stream_dir(event_dir.path(), &node_key(1).verifying_key())
        .expect("event stream verifies end-to-end");
    assert!(
        verify::verify_event_stream_dir(event_dir.path(), &node_key(2).verifying_key()).is_err(),
        "verifying under the wrong node key must fail"
    );
}

#[tokio::test]
async fn mirror_readers_reject_corruption() {
    let (record_dir, _) = setup().await;
    let path = &stream::record::record_files_in(record_dir.path()).expect("files")[0].1;
    let bytes = fs::read(path).expect("read");
    // Truncation.
    assert!(read_record_stream_file(&bytes[..bytes.len() / 2]).is_err());
    // Trailing bytes.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(read_record_stream_file(&trailing).is_err());
    // A corrupted byte makes the whole-directory verification fail.
    let mut corrupted = bytes;
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xff;
    fs::write(path, corrupted).expect("corrupt");
    let trusted_hash = registry_of(&[1, 2, 3, 4]).hash();
    assert!(
        verify::verify_record_stream_dir(
            record_dir.path(),
            primitives::NodeId::new(1),
            trusted_hash
        )
        .is_err()
    );
}

/// A mirror service that supplies a trusted roster hash must reject a record
/// stream whose embedded checkpoints carry a forged roster — even when the
/// attacker holds a quorum in that forged roster.
///
/// Attack scenario: an attacker controls nodes 10, 11, 12 and compromises
/// node 1's signing key.  They rewrite every `.rsf` file's checkpoint to
/// embed a roster `{1, 10, 11, 12}` where 3 of 4 signatures reach quorum.
/// When verified against the forged roster's own hash the forgery passes
/// (self-trust), but with the correct `trusted_roster_hash` the mismatch is
/// caught before signatures are checked.
#[tokio::test]
async fn forged_roster_rejected_with_trusted_hash() {
    let (record_dir, _) = setup().await;

    // The correct roster hash: the real network's {1, 2, 3, 4} roster.
    let correct_roster = registry_of(&[1, 2, 3, 4]);
    let correct_roster_hash = correct_roster.hash();

    // Tamper every record file: replace its checkpoint with a forged one whose
    // records_root correctly matches the file's actual items (so the binding
    // check alone would pass). The roster forgery is what fails.
    let files = stream::record::record_files_in(record_dir.path()).expect("files");
    assert_eq!(files.len(), 3);
    for (round, path) in &files {
        let file_bytes = fs::read(path).expect("read");
        let mut file = pb::RecordStreamFile::decode(file_bytes.as_slice()).expect("decode");

        // Forged roster: attacker keys 10, 11, 12 plus the compromised node 1.
        // 3-of-4 = quorum in the attacker's own roster.
        let forged_roster = registry_of(&[1, 10, 11, 12]);
        // Recompute records_root from the file's actual items so the content
        // binding still matches; only the roster is forged.
        let rr_items: Vec<consensus::RecordsRootItem> = file
            .items
            .iter()
            .map(|it| consensus::RecordsRootItem {
                event_hash: it.event_hash.clone().try_into().expect("32"),
                tx_index: it.tx_index,
                tx_payload: it.tx_payload.clone(),
            })
            .collect();
        let records_root = consensus::compute_records_root(&rr_items);
        let forged_payload =
            consensus::CheckpointPayload::new(*round, records_root, [0xaa; 32], forged_roster);
        let signing_bytes = forged_payload.signing_bytes();
        let mut forged_s_tuples: Vec<(primitives::NodeId, blst::min_pk::Signature)> = [1, 10, 11]
            .iter()
            .map(|&signer| {
                let bls = crypto::BlsIdentity::from_ikm(&[signer as u8; 32]).expect("bls");
                (primitives::NodeId::new(signer), bls.sign(&signing_bytes))
            })
            .collect();
        forged_s_tuples.sort_by_key(|(id, _)| *id);
        let refs: Vec<&blst::min_pk::Signature> = forged_s_tuples.iter().map(|(_, s)| s).collect();
        let agg = crypto::bls::aggregate(&refs).expect("aggregate");
        let signers: Vec<primitives::NodeId> = forged_s_tuples.iter().map(|(id, _)| *id).collect();
        let forged_checkpoint =
            consensus::SignedCheckpoint { payload: forged_payload, aggregate_sig: agg, signers };

        // Swap the checkpoint inside the protobuf message; no .rsf_sig exists.
        file.checkpoint = Some(stream::convert::signed_checkpoint_to_proto(&forged_checkpoint));
        let new_file_bytes = file.encode_to_vec();
        fs::write(path, new_file_bytes).expect("write forged file");
    }

    // With the forged roster's own hash the verification passes (the
    // attacker can self-validate), but with the correct trusted hash the
    // forged roster is rejected.
    let forged_roster = registry_of(&[1, 10, 11, 12]);
    let forged_hash = forged_roster.hash();
    assert!(
        verify::verify_record_stream_dir(
            record_dir.path(),
            primitives::NodeId::new(1),
            forged_hash
        )
        .is_ok(),
        "forged roster passes when verified against its own hash (attacker self-trust)"
    );

    // With the correct trusted hash the forged roster is rejected.
    assert!(
        verify::verify_record_stream_dir(
            record_dir.path(),
            primitives::NodeId::new(1),
            correct_roster_hash,
        )
        .is_err(),
        "forged roster must fail when the caller supplies a trusted roster hash"
    );

    // Also verify that flipping a single item's payload breaks the
    // records_root binding even though the BLS aggregate and roster are valid.
    let (record_dir2, _) = setup().await;
    let files2 = stream::record::record_files_in(record_dir2.path()).expect("files");
    let target = &files2[0].1;
    let mut file =
        pb::RecordStreamFile::decode(fs::read(target).expect("read").as_slice()).expect("decode");
    assert!(!file.items.is_empty());
    file.items[0].tx_payload.push(0xff);
    let tampered_bytes = file.encode_to_vec();
    fs::write(target, tampered_bytes).expect("write tampered items");
    let trusted = registry_of(&[1, 2, 3, 4]).hash();
    assert!(
        verify::verify_record_stream_dir(record_dir2.path(), primitives::NodeId::new(1), trusted)
            .is_err(),
        "flipped item must fail via records_root binding"
    );
}

#[tokio::test]
async fn genuine_checkpoint_with_fabricated_items_fails_records_root() {
    let dir = tempfile::tempdir().expect("temp dir");
    let items = vec![pb::RecordItem {
        event_hash: vec![7u8; 32],
        tx_index: 0,
        tx_payload: b"honest".to_vec(),
    }];
    let checkpoint = common::signed_checkpoint_with_items(5, &[1, 2, 3, 4], &[1, 2, 3], &items);
    let writer = RecordStreamWriter::open(
        dir.path(),
        node_key(1),
        Arc::new(tokio::sync::Mutex::new(consensus::Hashgraph::new(&common::registry_of(&[
            1, 2, 3, 4,
        ])))),
    )
    .expect("writer");
    writer.submit_items(checkpoint, items);
    writer.barrier().await;

    // Fabricate: keep the genuine checkpoint but replace items with a different payload.
    let files = stream::record::record_files_in(dir.path()).expect("files");
    assert_eq!(files.len(), 1);
    let path = &files[0].1;
    let mut file =
        pb::RecordStreamFile::decode(fs::read(path).expect("read").as_slice()).expect("decode");
    file.items = vec![pb::RecordItem {
        event_hash: vec![7u8; 32],
        tx_index: 0,
        tx_payload: b"fabricated".to_vec(),
    }];
    // Fix the running hash chain so chain verification still passes but records_root fails.
    let start =
        stream::convert::hash_object_digest(file.start_running_hash.as_ref().expect("start"))
            .expect("start");
    let mut cur = start;
    for item in &file.items {
        let b = item.encode_to_vec();
        cur = stream::running_hash::chain_hash(&cur, &stream::running_hash::item_hash(&b));
    }
    file.end_running_hash = Some(stream::convert::digest_hash_object(cur));
    fs::write(path, file.encode_to_vec()).expect("write fabricated");
    let trusted = registry_of(&[1, 2, 3, 4]).hash();
    assert!(
        verify::verify_record_stream_dir(dir.path(), primitives::NodeId::new(1), trusted).is_err(),
        "fabricated items with genuine checkpoint must fail via records_root"
    );
}

#[tokio::test]
async fn wrong_dst_or_other_keys_aggregate_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let items: Vec<pb::RecordItem> = Vec::new();
    // Build a payload honestly, then sign it with keys 5,6,7 but claim signers 1,2,3.
    let honest_roster = common::registry_of(&[1, 2, 3, 4]);
    let rr = consensus::compute_records_root(&[]);
    let payload = consensus::CheckpointPayload::new(9, rr, [9u8; 32], honest_roster.clone());
    let signing_bytes = payload.signing_bytes();
    let rogue_sigs: Vec<blst::min_pk::Signature> = [5, 6, 7]
        .iter()
        .map(|&id| crypto::BlsIdentity::from_ikm(&[id as u8; 32]).unwrap().sign(&signing_bytes))
        .collect();
    let refs: Vec<&blst::min_pk::Signature> = rogue_sigs.iter().collect();
    let agg = crypto::bls::aggregate(&refs).expect("aggregate");
    let forged_cp = consensus::SignedCheckpoint {
        payload,
        aggregate_sig: agg,
        signers: vec![
            primitives::NodeId::new(1),
            primitives::NodeId::new(2),
            primitives::NodeId::new(3),
        ],
    };
    let writer = RecordStreamWriter::open(
        dir.path(),
        node_key(1),
        Arc::new(tokio::sync::Mutex::new(consensus::Hashgraph::new(&honest_roster))),
    )
    .expect("writer");
    writer.submit_items(forged_cp, items);
    writer.barrier().await;
    let trusted = registry_of(&[1, 2, 3, 4]).hash();
    assert!(
        verify::verify_record_stream_dir(dir.path(), primitives::NodeId::new(1), trusted).is_err(),
        "aggregate by other keys must fail"
    );

    // Wrong DST variant: sign the same payload with a different domain, then verify via the
    // checkpoint DST must fail.
    let payload2 = consensus::CheckpointPayload::new(
        10,
        consensus::compute_records_root(&[]),
        [10u8; 32],
        common::registry_of(&[1, 2, 3, 4]),
    );
    // Use blst directly with wrong DST.
    let ikm = [1u8; 32];
    let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).expect("sk");
    let wrong_sig = sk.sign(&payload2.signing_bytes(), b"WRONG-DST", &[]);
    let cp2 = consensus::SignedCheckpoint {
        payload: payload2,
        aggregate_sig: wrong_sig,
        signers: vec![
            primitives::NodeId::new(1),
            primitives::NodeId::new(2),
            primitives::NodeId::new(3),
        ],
    };
    // Need at least quorum signers, but we supply single wrong DST sig as aggregate; it will fail verify.
    let dir2 = tempfile::tempdir().expect("temp dir2");
    let writer2 = RecordStreamWriter::open(
        dir2.path(),
        node_key(1),
        Arc::new(tokio::sync::Mutex::new(consensus::Hashgraph::new(&common::registry_of(&[
            1, 2, 3, 4,
        ])))),
    )
    .expect("writer2");
    writer2.submit_items(cp2, Vec::new());
    writer2.barrier().await;
    assert!(
        verify::verify_record_stream_dir(dir2.path(), primitives::NodeId::new(1), trusted).is_err(),
        "wrong DST aggregate must fail"
    );
}

#[tokio::test]
async fn esf_tamper_still_caught_by_sig() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer = EventStreamWriter::open(dir.path(), node_key(1), 10).expect("writer");
    for seq in 1..=3 {
        writer.append(&sample_record(1, seq, 1));
    }
    writer.flush();
    writer.barrier().await;
    let files = stream::event::event_files_in(dir.path()).expect("files");
    assert_eq!(files.len(), 1);
    let path = &files[0].1;
    let mut bytes = fs::read(path).expect("read");
    // Tamper a byte inside the protobuf payload (before signature check).
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    fs::write(path, bytes).expect("tamper");
    assert!(
        verify::verify_event_stream_dir(dir.path(), &node_key(1).verifying_key()).is_err(),
        ".esf tamper must be caught by .esf_sig"
    );
}
