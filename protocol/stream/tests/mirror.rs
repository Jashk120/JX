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
    sample_record,
    signed_checkpoint,
};
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
        let checkpoint = signed_checkpoint(round, &[1, 2, 3, 4], &[1, 2, 3]);
        let items = (0..2)
            .map(|i| pb::RecordItem {
                event_hash: vec![round as u8; 32],
                tx_index: i as u32,
                tx_payload: format!("round-{round}-tx-{i}").into_bytes(),
            })
            .collect();
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
        assert_eq!(file.version, 1);
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

    // The mirror's verification: chain + signature files + checkpoint quorum,
    // source-agnostic (the node id is the only trusted input).
    verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(1))
        .expect("record stream verifies end-to-end");

    // A mirror that doubts the emitting node rejects the stream.
    assert!(
        verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(2)).is_err(),
        "verifying under the wrong node identity must fail"
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
        assert_eq!(file.version, 1);
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
    assert!(
        verify::verify_record_stream_dir(record_dir.path(), primitives::NodeId::new(1)).is_err()
    );
}
