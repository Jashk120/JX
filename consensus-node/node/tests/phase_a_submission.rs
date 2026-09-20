//! Phase-A operability (PLAN-5 D-12): DID, sub-actor, and rebind payloads
//! built with the control-socket constructors submit successfully through a
//! single test node's control socket. Queued acceptance is the assertion —
//! the socket does not validate semantics.

mod common;

use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};

use common::*;
use node::config::encode_hex;
use node::control::{
    self,
    ControlRequest,
};
use tokio::net::UnixListener;
use tokio::time::timeout;

fn verifying_key(seed: u8) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key()
}

fn test_did_id() -> state::DidId {
    state::DidId::new("test".to_string(), "alice".to_string(), [1u8; 16]).expect("valid id")
}

fn test_did_op() -> state::DidOp {
    let document = state::DidDocument::new(
        verifying_key(2),
        vec![state::VerificationMethod::Signing(verifying_key(3))],
        false,
    )
    .expect("valid document");
    state::DidOp::new(test_did_id(), document, primitives::Signature::new([7u8; 64]), 0, true)
}

fn test_sub_actor_op() -> state::SubActorOp {
    let root_did = test_did_id();
    let actor_id =
        state::ActorId::Sub { root_did: root_did.clone(), tag: state::Tag::Messenger, index: 3 };
    let control = verifying_key(4);
    let operating = verifying_key(5);
    let leaf = state::subactor_leaf_hash(&actor_id, &control);
    let leaves = std::slice::from_ref(&leaf);
    state::SubActorOp::new(state::SubActorOpParams {
        root_did,
        tag: state::Tag::Messenger,
        index: 3,
        control_key: control,
        operating_key: operating,
        new_root: state::mth(leaves),
        consistency_proof: state::prove_consistency(leaves, 0).expect("bootstrap proves"),
        inclusion_proof: state::prove_inclusion(leaves, 0).expect("in range"),
        signature: primitives::Signature::new([7u8; 64]),
        signed_by: 0,
    })
}

fn test_rebind_op() -> state::RebindOp {
    state::RebindOp::new(
        state::ActorId::Sub { root_did: test_did_id(), tag: state::Tag::Messenger, index: 3 },
        verifying_key(6),
        primitives::Signature::new([7u8; 64]),
        primitives::Signature::new([8u8; 64]),
    )
}

#[tokio::test]
async fn phase_a_ops_submit_through_control_socket() {
    let (nodes, _net) = spawn_cluster(&[1]).await;

    let dir = tempfile::tempdir().expect("temp dir");
    let sock = dir.path().join("node.sock");
    let listener = UnixListener::bind(&sock).expect("bind control socket");
    let stop = Arc::new(AtomicBool::new(false));
    let node = nodes[0].node.clone();
    tokio::spawn(control::serve(listener, node.clone(), stop.clone()));

    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("did", control::did_op_payload(&test_did_op())),
        ("sub-actor", control::sub_actor_op_payload(&test_sub_actor_op())),
        ("rebind", control::rebind_op_payload(&test_rebind_op())),
    ];
    for (what, payload) in &payloads {
        let response = timeout(
            DEADLINE,
            control::request(&sock, &ControlRequest::SubmitTx { payload_hex: encode_hex(payload) }),
        )
        .await
        .expect("control socket answers in time")
        .expect("submit request");
        assert!(response.ok, "{what} payload accepted: {:?}", response.error);
    }

    stop.store(true, Ordering::Release);
    drop_nodes(nodes);
}
