//! PLAN-5 Phase A exit criteria, end to end.
//!
//! One linear scenario against a real [`Executor`] and a fresh [`StateDb`]:
//! create a DID, observe the auto-created root actor, mint two tagged
//! sub-actors with RFC-6962 membership proofs, verify a sub-actor off-chain by
//! Merkle proof, rebind one sub-actor's operating key to an externally-owned
//! keypair, and confirm the whole sequence is deterministic (a second executor
//! ends byte-identical).

use ed25519_dalek::{
    Signer,
    SigningKey,
    VerifyingKey,
};
use primitives::{
    Event,
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use state::{
    ActorId,
    DidDocument,
    DidId,
    DidOp,
    EMPTY_ROOT,
    Executor,
    Hash,
    InclusionProof,
    RebindOp,
    RootActor,
    StateDb,
    SubActor,
    SubActorOp,
    SubActorOpParams,
    Tag,
    VerificationMethod,
    actor_state_key,
    did_state_key,
    mth,
    prove_consistency,
    prove_inclusion,
    subactor_leaf_hash,
    verify_inclusion,
};
use tempfile::tempdir;

fn zero_sig() -> Signature {
    Signature::new([0u8; 64])
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn verifying_key(seed: u8) -> VerifyingKey {
    signing_key(seed).verifying_key()
}

fn root_did() -> DidId {
    DidId::new("testnet".into(), "alice".into(), [0xaa; 16]).expect("valid did")
}

fn event_with(payload: Vec<Transaction>) -> Event {
    UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), payload).finalize(zero_sig())
}

fn new_executor() -> Executor {
    let dir = tempdir().expect("temp dir");
    let db = StateDb::open(dir.path()).expect("state db opens");
    Executor::new(db.state_keyspace())
}

fn apply(executor: &mut Executor, tx: Transaction) {
    let event = event_with(vec![tx]);
    let result = executor.execute_event(&event).expect("no storage error");
    assert!(result.errors.is_empty(), "decode errors: {:?}", result.errors);
    assert!(result.op_errors.is_empty(), "semantic errors: {:?}", result.op_errors);
}

fn read_root(executor: &Executor, did: &DidId) -> RootActor {
    let bytes = executor
        .state()
        .get(&actor_state_key(&ActorId::Root(did.clone())))
        .expect("root record present");
    let mut cursor = &bytes[..];
    let root = RootActor::decode(&mut cursor).expect("root decodes");
    assert!(cursor.is_empty(), "root record has no trailing bytes");
    root
}

fn read_sub(executor: &Executor, actor_id: &ActorId) -> SubActor {
    let bytes = executor.state().get(&actor_state_key(actor_id)).expect("sub-actor record present");
    let mut cursor = &bytes[..];
    let sub = SubActor::decode(&mut cursor).expect("sub-actor decodes");
    assert!(cursor.is_empty(), "sub-actor record has no trailing bytes");
    sub
}

fn did_creation_tx(did: &DidId, signer_seed: u8, control_seed: u8) -> Transaction {
    let doc = DidDocument::new(
        verifying_key(control_seed),
        vec![VerificationMethod::Signing(verifying_key(signer_seed))],
        false,
    )
    .expect("valid document");
    let unsigned = DidOp::new(did.clone(), doc.clone(), zero_sig(), 0, true);
    let sig = signing_key(signer_seed).sign(&unsigned.signed_payload());
    let op = DidOp::new(did.clone(), doc, Signature::new(sig.to_bytes()), 0, true);
    let mut payload = vec![0x03u8];
    payload.extend_from_slice(&op.encode());
    Transaction::from_bytes(payload)
}

struct SubActorSpec {
    tag: Tag,
    index: u32,
    control_seed: u8,
    operating_seed: u8,
}

/// Builds the append of one sub-actor onto `leaves`, returning its transaction
/// plus the leaf and new root the off-chain verifier must check against.
fn sub_actor_tx(
    did: &DidId,
    spec: &SubActorSpec,
    signer_seed: u8,
    leaves: &[Hash],
) -> (Transaction, Hash, Hash, InclusionProof) {
    let actor_id = ActorId::Sub { root_did: did.clone(), tag: spec.tag, index: spec.index };
    let control_key = verifying_key(spec.control_seed);
    let operating_key = verifying_key(spec.operating_seed);
    let leaf = subactor_leaf_hash(&actor_id, &control_key);
    let mut new_leaves = leaves.to_vec();
    new_leaves.push(leaf);
    let new_root = mth(&new_leaves);
    let consistency = prove_consistency(&new_leaves, leaves.len()).expect("consistency proof");
    let inclusion = prove_inclusion(&new_leaves, leaves.len()).expect("inclusion proof");
    let params = |signature: Signature| SubActorOpParams {
        root_did: did.clone(),
        tag: spec.tag,
        index: spec.index,
        control_key,
        operating_key,
        new_root,
        consistency_proof: consistency.clone(),
        inclusion_proof: inclusion.clone(),
        signature,
        signed_by: 0,
    };
    let unsigned = SubActorOp::new(params(zero_sig()));
    let sig = signing_key(signer_seed).sign(&unsigned.signed_payload());
    let op = SubActorOp::new(params(Signature::new(sig.to_bytes())));
    let mut payload = vec![0x04u8];
    payload.extend_from_slice(&op.encode());
    (Transaction::from_bytes(payload), leaf, new_root, inclusion)
}

fn rebind_tx(
    actor_id: &ActorId,
    old_operating_key: &VerifyingKey,
    new_operating_seed: u8,
    root_control_seed: u8,
) -> Transaction {
    let new_operating_key = verifying_key(new_operating_seed);
    let unsigned = RebindOp::new(actor_id.clone(), new_operating_key, zero_sig(), zero_sig());
    let to_sign = unsigned.signed_payload(old_operating_key);
    let pop = signing_key(new_operating_seed).sign(&to_sign);
    let auth = signing_key(root_control_seed).sign(&to_sign);
    let op = RebindOp::new(
        actor_id.clone(),
        new_operating_key,
        Signature::new(pop.to_bytes()),
        Signature::new(auth.to_bytes()),
    );
    let mut payload = vec![0x05u8];
    payload.extend_from_slice(&op.encode());
    Transaction::from_bytes(payload)
}

#[test]
fn phase_a_exit_criteria_end_to_end() {
    let did = root_did();
    let specs = [
        SubActorSpec { tag: Tag::Messenger, index: 0, control_seed: 11, operating_seed: 12 },
        SubActorSpec { tag: Tag::Generic, index: 1, control_seed: 13, operating_seed: 14 },
    ];

    // The static op sequence is built once, independently of any executor, and
    // then applied to two of them.
    let create = did_creation_tx(&did, 1, 9);
    let mut leaves: Vec<Hash> = Vec::new();
    let mut sub_txs = Vec::new();
    for spec in &specs {
        let entry = sub_actor_tx(&did, spec, 1, &leaves);
        leaves.push(entry.1);
        sub_txs.push(entry);
    }
    let log_root = sub_txs.last().expect("two sub-actors").2;
    let actor0 = ActorId::Sub { root_did: did.clone(), tag: Tag::Messenger, index: 0 };
    let actor1 = ActorId::Sub { root_did: did.clone(), tag: Tag::Generic, index: 1 };
    let actor0_operating = verifying_key(12);
    let rebind = rebind_tx(&actor0, &actor0_operating, 0xEE, 9);

    // --- Executor A: apply step by step, asserting each milestone. ---
    let mut a = new_executor();
    apply(&mut a, create.clone());

    // Create a DID -> the root actor is auto-created, empty and controlled.
    assert!(a.state().contains(&did_state_key(&did)), "DID record present");
    let root = read_root(&a, &did);
    assert_eq!(root.leaf_count(), 0, "fresh root holds no sub-actors");
    assert_eq!(*root.merkle_root(), EMPTY_ROOT, "fresh root commits the empty log");
    assert_eq!(*root.control_key(), verifying_key(9), "root copies the document control key");

    // Mint two tagged sub-actors; the commitment advances one leaf at a time.
    for (index, (tx, leaf, new_root, inclusion)) in sub_txs.iter().enumerate() {
        apply(&mut a, tx.clone());
        let root = read_root(&a, &did);
        assert_eq!(root.leaf_count(), (index + 1) as u64, "leaf count advances");
        assert_eq!(*root.merkle_root(), *new_root, "root commits the new log");
        assert!(
            verify_inclusion(leaf, inclusion, root.merkle_root()),
            "off-chain membership proof verifies for sub-actor {index}"
        );
    }
    assert!(a.state().contains(&actor_state_key(&actor0)), "sub-actor 0 record present");
    assert!(a.state().contains(&actor_state_key(&actor1)), "sub-actor 1 record present");

    // Rebind sub-actor 0 to an external keypair: only the mutable record moves.
    let root_before = read_root(&a, &did);
    let sub_before = read_sub(&a, &actor0);
    apply(&mut a, rebind.clone());
    let sub_after = read_sub(&a, &actor0);
    assert_eq!(*sub_after.operating_key(), verifying_key(0xEE), "operating key rebound");
    assert_eq!(*sub_after.control_key(), *sub_before.control_key(), "control key unchanged");
    let root_after = read_root(&a, &did);
    assert_eq!(
        *root_after.merkle_root(),
        *root_before.merkle_root(),
        "rebind leaves the membership commitment"
    );
    assert_eq!(root_after.leaf_count(), root_before.leaf_count(), "rebind leaves leaf count");
    assert_eq!(*root_after.merkle_root(), log_root, "commitment is the two-leaf log root");

    // --- Executor B: the identical sequence must end byte-identical. ---
    let mut b = new_executor();
    apply(&mut b, create);
    for (tx, _, _, _) in &sub_txs {
        apply(&mut b, tx.clone());
    }
    apply(&mut b, rebind);
    assert_eq!(
        a.state().to_bytes().expect("to_bytes succeeds"),
        b.state().to_bytes().expect("to_bytes succeeds"),
        "the same op sequence yields byte-identical state"
    );
}
