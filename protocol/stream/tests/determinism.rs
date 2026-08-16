//! Determinism: two independently-constructed writers fed identical input
//! produce byte-identical streams (Phase 8, §3.2 — record files are
//! byte-identical across the cluster; event files are deterministic per node).
//!
//! Both writers and both streams are exercised: the record stream with real
//! quorum checkpoints and hand-assembled items, the event stream through the
//! `EventSink` append path with the same events.

mod common;

use std::sync::Arc;

use common::{
    node_key,
    read_all_files,
    sample_record,
    signed_checkpoint,
};
use consensus::Hashgraph;
use storage::EventSink;
use stream::pb::RecordItem;
use stream::{
    EventStreamWriter,
    RecordStreamWriter,
};
use tokio::sync::Mutex;

#[tokio::test]
async fn record_streams_are_byte_identical_across_writers() {
    let dir_a = tempfile::tempdir().expect("temp dir a");
    let dir_b = tempfile::tempdir().expect("temp dir b");
    let hashgraph: Arc<Mutex<Hashgraph>> =
        Arc::new(Mutex::new(Hashgraph::new(&common::registry_of(&[1, 2, 3, 4]))));

    let writer_a = RecordStreamWriter::open(dir_a.path(), node_key(1), hashgraph.clone())
        .expect("writer a opens");
    let writer_b =
        RecordStreamWriter::open(dir_b.path(), node_key(1), hashgraph).expect("writer b opens");

    for round in 1..=3 {
        let checkpoint = signed_checkpoint(round, &[1, 2, 3, 4], &[1, 2, 3]);
        let items: Vec<RecordItem> = (0..round)
            .map(|i| RecordItem {
                event_hash: vec![round as u8; 32],
                tx_index: i as u32,
                tx_payload: format!("tx-{round}-{i}").into_bytes(),
            })
            .collect();
        writer_a.submit_items(checkpoint.clone(), items.clone());
        writer_b.submit_items(checkpoint, items);
    }
    writer_a.barrier().await;
    writer_b.barrier().await;

    let files_a = read_all_files(dir_a.path());
    let files_b = read_all_files(dir_b.path());
    assert_eq!(files_a.len(), 6, "one `.rsf` + one `.rsf_sig` per round");
    assert_eq!(files_a, files_b, "two independent record writers must be byte-identical");
}

#[tokio::test]
async fn event_streams_are_byte_identical_across_writers() {
    let dir_a = tempfile::tempdir().expect("temp dir a");
    let dir_b = tempfile::tempdir().expect("temp dir b");

    let writer_a = EventStreamWriter::open(dir_a.path(), node_key(1), 3).expect("writer a opens");
    let writer_b = EventStreamWriter::open(dir_b.path(), node_key(1), 3).expect("writer b opens");

    for seq in 1..=7 {
        let record = sample_record(1, seq, 1);
        writer_a.append(&record);
        writer_b.append(&record);
    }
    writer_a.barrier().await;
    writer_b.barrier().await;

    let files_a = read_all_files(dir_a.path());
    let files_b = read_all_files(dir_b.path());
    assert_eq!(files_a.len(), 4, "2 `.esf` files + 2 `.esf_sig` files");
    assert_eq!(files_a, files_b, "two independent event writers must be byte-identical");
}
