//! Chain integrity: file N+1's `start_running_hash` equals file N's
//! `end_running_hash`, the first file starts at the seed, and the reader
//! rejects truncation, trailing bytes, tampering, and reordering (Phase 8, §5
//! and §7.2).

mod common;

use std::fs;
use std::sync::Arc;

use common::{
    node_key,
    registry_of,
    sample_record,
    signed_checkpoint,
};
use crypto::Hashable;
use storage::EventSink;
use stream::event::{
    event_files_in,
    read_event_stream_file,
};
use stream::record::{
    read_record_stream_file,
    record_files_in,
};
use stream::{
    EventStreamWriter,
    RecordStreamWriter,
};

/// An empty hashgraph shared by the record-writer tests (the record writer
/// only reads it when assembling items, which these tests bypass).
fn empty_hashgraph() -> Arc<tokio::sync::Mutex<consensus::Hashgraph>> {
    Arc::new(tokio::sync::Mutex::new(consensus::Hashgraph::new(&common::registry_of(&[
        1, 2, 3, 4,
    ]))))
}

#[tokio::test]
async fn record_files_chain_continuously() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer =
        RecordStreamWriter::open(dir.path(), node_key(1), empty_hashgraph()).expect("opens");

    for round in 1..=3 {
        writer.submit_items(signed_checkpoint(round, &[1, 2, 3, 4], &[1, 2, 3]), Vec::new());
    }
    writer.barrier().await;

    let files = record_files_in(dir.path()).expect("files");
    assert_eq!(files.len(), 3);
    let mut previous_end: Option<[u8; 32]> = None;
    for (round, path) in files {
        let file = read_record_stream_file(&fs::read(&path).expect("read")).expect("decodes");
        let start =
            stream::convert::hash_object_digest(file.start_running_hash.as_ref().expect("start"))
                .expect("start digest");
        let end = stream::convert::hash_object_digest(file.end_running_hash.as_ref().expect("end"))
            .expect("end digest");
        match previous_end {
            None => {
                assert_eq!(start, stream::running_hash::CHAIN_SEED, "first file starts at the seed")
            }
            Some(previous) => {
                assert_eq!(start, previous, "file {round} chains from the previous file")
            }
        }
        previous_end = Some(end);
    }
}

#[tokio::test]
async fn event_files_chain_continuously() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer = EventStreamWriter::open(dir.path(), node_key(1), 2).expect("opens");
    for seq in 1..=4 {
        writer.append(&sample_record(1, seq, 1));
    }
    writer.barrier().await;

    let files = event_files_in(dir.path()).expect("files");
    assert_eq!(files.len(), 2);
    let mut previous_end: Option<[u8; 32]> = None;
    for (index, path) in files {
        let file = read_event_stream_file(&fs::read(&path).expect("read")).expect("decodes");
        let start =
            stream::convert::hash_object_digest(file.start_running_hash.as_ref().expect("start"))
                .expect("start digest");
        let end = stream::convert::hash_object_digest(file.end_running_hash.as_ref().expect("end"))
            .expect("end digest");
        match previous_end {
            None => {
                assert_eq!(start, stream::running_hash::CHAIN_SEED, "first file starts at the seed")
            }
            Some(previous) => {
                assert_eq!(start, previous, "event file {index} chains from the previous file")
            }
        }
        previous_end = Some(end);
    }
}

#[tokio::test]
async fn record_reader_rejects_truncation_and_trailing_bytes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer =
        RecordStreamWriter::open(dir.path(), node_key(1), empty_hashgraph()).expect("opens");
    writer.submit_items(signed_checkpoint(1, &[1, 2, 3, 4], &[1, 2, 3]), Vec::new());
    writer.barrier().await;

    let path = &record_files_in(dir.path()).expect("files")[0].1;
    let bytes = fs::read(path).expect("read");
    for cut in [1, bytes.len() - 1, bytes.len() / 2] {
        assert!(
            read_record_stream_file(&bytes[..cut]).is_err(),
            "truncation at {cut} must be rejected"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(read_record_stream_file(&trailing).is_err(), "trailing bytes must be rejected");
}

#[tokio::test]
async fn record_verifier_rejects_tampering_and_reordering() {
    let dir = tempfile::tempdir().expect("temp dir");
    let writer =
        RecordStreamWriter::open(dir.path(), node_key(1), empty_hashgraph()).expect("opens");
    for round in 1..=3 {
        writer.submit_items(signed_checkpoint(round, &[1, 2, 3, 4], &[1, 2, 3]), Vec::new());
    }
    writer.barrier().await;
    let trusted_hash = registry_of(&[1, 2, 3, 4]).hash();
    assert!(
        stream::verify::verify_record_stream_dir(
            dir.path(),
            primitives::NodeId::new(1),
            trusted_hash
        )
        .is_ok()
    );

    // Tamper: flip a byte in the middle of the second file.
    let second = &record_files_in(dir.path()).expect("files")[1].1;
    let mut tampered = fs::read(second).expect("read");
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xff;
    fs::write(second, tampered).expect("write");
    assert!(
        stream::verify::verify_record_stream_dir(
            dir.path(),
            primitives::NodeId::new(1),
            trusted_hash
        )
        .is_err(),
        "a tampered record file must fail verification"
    );

    // Reorder: overwrite round 3's file bytes onto round 2's name, so the
    // chain no longer links (round 2's start disagrees with round 1's end).
    let dir = tempfile::tempdir().expect("temp dir 2");
    let writer =
        RecordStreamWriter::open(dir.path(), node_key(1), empty_hashgraph()).expect("opens 2");
    for round in 1..=3 {
        writer.submit_items(signed_checkpoint(round, &[1, 2, 3, 4], &[1, 2, 3]), Vec::new());
    }
    writer.barrier().await;
    let files = record_files_in(dir.path()).expect("files");
    let round3_bytes = fs::read(&files[2].1).expect("read round 3");
    fs::write(&files[1].1, round3_bytes).expect("clobber round 2");
    assert!(
        stream::verify::verify_record_stream_dir(
            dir.path(),
            primitives::NodeId::new(1),
            trusted_hash
        )
        .is_err(),
        "a reordered stream must fail chain verification"
    );
}
