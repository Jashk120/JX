//! Mirror-stream integration over the gossip layer (Phase 8): the record
//! stream is emitted on checkpoint acceptance and the event stream records
//! live gossip events, both through the real `GossipNode` wiring.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use crypto::{
    Hashable,
    Signable,
    Verifiable,
};
use ed25519_dalek::{
    Signer,
    SigningKey,
};
use gossip::{
    GossipNode,
    SyncTiming,
    TlsIdentity,
};
use primitives::{
    Event,
    NodeId,
    Timestamp,
    UnsignedEvent,
};
use storage::EventSink;
use stream::event::event_files_in;
use stream::record::record_files_in;
use stream::{
    EventStreamWriter,
    RecordStreamWriter,
    verify,
};

/// Signs the node's checkpoint signing bytes for `round` with `signer`'s key.
fn checkpoint_sig_for(
    signer: u64,
    round: u64,
    signing_bytes: &[u8; 72],
) -> consensus::CheckpointSig {
    let key = SigningKey::from_bytes(&consensus_seed(signer));
    let signature = key.sign(signing_bytes);
    consensus::CheckpointSig {
        round,
        signer: NodeId::new(signer),
        sig: primitives::Signature::new(signature.to_bytes()),
    }
}

/// The deterministic 4-member deep clique from `consensus`'s `order.rs`:
/// rounds 1-2 finalize, so a node holding it can produce and accept a
/// checkpoint for round 1.
fn build_deep_clique() -> Vec<Event> {
    let mut events = HashMap::new();
    let mut out = Vec::new();
    let mut ts = 100u64;
    let mut step = |label: &'static str,
                    author: u64,
                    self_parent: Option<&'static str>,
                    other_parent: Option<&'static str>| {
        let self_parent = self_parent.map(|label| events[label]);
        let other_parent = other_parent.map(|label| events[label]);
        let event = UnsignedEvent::new(
            NodeId::new(author),
            self_parent,
            other_parent,
            Timestamp::new(ts),
            Vec::new(),
        )
        .sign(&SigningKey::from_bytes(&consensus_seed(author)));
        ts += 1;
        events.insert(label, event.hash());
        out.push(event);
    };
    step("a1", 1, None, None);
    step("b1", 2, None, None);
    step("c1", 3, None, None);
    step("d1", 4, None, None);
    step("a2", 1, Some("a1"), Some("d1"));
    step("b2", 2, Some("b1"), Some("a2"));
    step("a3", 1, Some("a2"), Some("b2"));
    step("b3", 2, Some("b2"), Some("c1"));
    step("a4", 1, Some("a3"), Some("b3"));
    step("d2", 4, Some("d1"), Some("a4"));
    step("c2", 3, Some("c1"), Some("d2"));
    step("a5", 1, Some("a4"), Some("c2"));
    step("b4", 2, Some("b3"), Some("a5"));
    step("c3", 3, Some("c2"), Some("b4"));
    step("d3", 4, Some("d2"), Some("c3"));
    step("a6", 1, Some("a5"), Some("d3"));
    step("b5", 2, Some("b4"), Some("a6"));
    step("c4", 3, Some("c3"), Some("b5"));
    step("d4", 4, Some("d3"), Some("c4"));
    step("a7", 1, Some("a6"), Some("d4"));
    step("b6", 2, Some("b5"), Some("a7"));
    out
}

/// Accepting a checkpoint must emit the round's `.rsf` (assembled from the
/// hashgraph's consensus order) plus its `.rsf_sig`, and a mirror must be able
/// to verify the whole record stream from the files alone.
#[tokio::test]
async fn record_stream_emitted_on_checkpoint_accept() {
    let registry = registry_for_ids(&[1, 2, 3, 4]);
    let identity = TlsIdentity::from_seed([0x77; 32], 1).expect("identity builds");
    let node = Arc::new(GossipNode::new(
        NodeId::new(1),
        SigningKey::from_bytes(&consensus_seed(1)),
        registry.clone(),
        identity,
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));

    let streams_dir = tempfile::tempdir().expect("temp dir");
    let record_writer = Arc::new(
        RecordStreamWriter::open(
            streams_dir.path(),
            SigningKey::from_bytes(&consensus_seed(1)),
            node.hashgraph.clone(),
        )
        .expect("record writer opens"),
    );
    node.set_record_sink(record_writer.clone()).await;

    for event in build_deep_clique() {
        let verified = event.clone().verify(&registry).expect("valid signature");
        let mut hg = node.hashgraph.lock().await;
        hg.insert(verified).expect("insert");
    }

    node.process_finalized_rounds().await;
    let signing_bytes =
        node.checkpoint_signing_bytes(1).await.expect("checkpoint produced for round 1");

    // Reach the 2/3 quorum: the accept path fires the record sink.
    node.submit_checkpoint_sig(checkpoint_sig_for(2, 1, &signing_bytes)).await;
    node.submit_checkpoint_sig(checkpoint_sig_for(3, 1, &signing_bytes)).await;
    assert!(node.signed_checkpoint_for(1).await.is_some(), "round 1 reaches quorum");
    record_writer.barrier().await;

    let files = record_files_in(streams_dir.path()).expect("record files");
    assert_eq!(files.len(), 1, "one record file for the accepted round");
    let (round, _) = files[0];
    assert_eq!(round, 1);

    // A mirror verifies the emitted stream from the files alone.
    verify::verify_record_stream_dir(streams_dir.path(), NodeId::new(1))
        .expect("record stream verifies end-to-end");
}

/// A live cluster's inserted events flow into the `.esf` files, and a mirror
/// can verify the event stream from the files alone.
#[tokio::test]
async fn event_stream_records_live_events() {
    let nodes = spawn_cluster(&[1, 2]).await;
    let streams_dir = tempfile::tempdir().expect("temp dir");
    let event_writer = Arc::new(
        EventStreamWriter::open(streams_dir.path(), SigningKey::from_bytes(&consensus_seed(1)), 2)
            .expect("event writer opens"),
    );
    nodes[0].node.set_event_stream_sink(event_writer.clone()).await;

    // Let the cluster gossip a while; every freshly inserted verified event is
    // appended to the event stream in topological order.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !event_files_in(streams_dir.path()).expect("files").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("event files appear within the deadline");

    event_writer.flush();
    event_writer.barrier().await;

    let files = event_files_in(streams_dir.path()).expect("event files");
    assert!(!files.is_empty(), "the live cluster produced at least one event file");
    verify::verify_event_stream_dir(
        streams_dir.path(),
        &SigningKey::from_bytes(&consensus_seed(1)).verifying_key(),
    )
    .expect("event stream verifies end-to-end");

    drop_nodes(nodes);
}
