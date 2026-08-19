//! The deterministic executor (Phase 8).
//!
//! Consumes events in finalized consensus order — the order
//! [`Hashgraph::consensus_order`] already produces per round — and folds each
//! transaction's payload into a [`State`] through [`Executor::execute_event`].
//! Execution itself is pure and deterministic: no wall-clock reads, no
//! randomness, no I/O, so the same finalized order and the same starting
//! state yield the same resulting state on every node.

use std::collections::BTreeMap;
use std::sync::Arc;

use consensus::Hashgraph;
use crypto::MembershipOp;
use ed25519_dalek::Verifier;
use fjall::Keyspace;
use primitives::Event;

use crate::did::DidDocument;
use crate::error::{
    DidError,
    ExecutorError,
};
use crate::op::{
    DecodedOp,
    Op,
};
use crate::state::State;

/// Applies transactions to a [`State`] in the order they are presented.
///
/// An [`Executor`] never invents an ordering: it only processes the sequence
/// it is given, so the caller (e.g. [`finalized_events`]) owns the consensus
/// ordering and this type owns the deterministic application.
#[derive(Debug)]
pub struct Executor {
    state: State,
}

/// The result of executing a single event's transactions.
pub struct ExecuteResult {
    /// Deterministic decode errors for individual payloads.
    pub errors: Vec<ExecutorError>,
    /// Membership operations collected as a side channel (never touch state).
    pub membership_ops: Vec<MembershipOp>,
    /// Semantic DID errors (bad signatures, unknown signers, etc.).
    pub did_errors: Vec<DidError>,
}

impl Executor {
    pub fn new(kv: Arc<Keyspace>) -> Self {
        Self { state: State::new(kv) }
    }

    /// Wraps an existing `State`, restoring an executor to a previously
    /// serialized checkpoint state (Phase 4 reconnect).
    pub fn from_state(state: State) -> Self {
        Self { state }
    }

    /// The state accumulated by the transactions applied so far.
    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn into_state(self) -> State {
        self.state
    }

    /// Decodes and applies every transaction in `event`, in payload order.
    ///
    /// KV operations apply to `State`. Membership operations never touch
    /// `State`: they are collected and returned as a side channel. DID
    /// operations are verified and applied to `State` via `Op::Put`; semantic
    /// errors (bad signature, unknown signer) are collected separately. On
    /// decode error the state is left unchanged for that payload — the
    /// operation is not applied — and the deterministic error is collected,
    /// without aborting the remaining transactions of the event.
    pub fn execute_event(&mut self, event: &Event) -> ExecuteResult {
        let mut errors = Vec::new();
        let mut membership_ops = Vec::new();
        let mut did_errors = Vec::new();

        for tx in event.payload() {
            match DecodedOp::decode(tx.payload()) {
                Ok(DecodedOp::Kv(op)) => self.state.apply(&op),
                Ok(DecodedOp::Membership(mem_op)) => membership_ops.push(mem_op),
                Ok(DecodedOp::Did(did_op)) => {
                    if let Err(e) = self.apply_did_op(did_op) {
                        did_errors.push(e);
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        ExecuteResult { errors, membership_ops, did_errors }
    }

    /// Buckets the membership ops of `finalized` — a slice of `(event,
    /// roundReceived)` pairs in non-decreasing `roundReceived` order — into
    /// `pending` by roundReceived, and advances `processed_through_round` to
    /// the highest round received in the batch.
    ///
    /// Callers invoke this once per finalized-event batch; the watermark makes
    /// a second call over the same batch a no-op (each event's payload is
    /// decoded exactly once), which is what keeps `process_finalized_rounds`
    /// idempotent. Decode errors are discarded: malformed payloads are a
    /// deterministic no-op for state and never produce membership ops.
    pub fn bucket_finalized(
        &mut self,
        pending: &mut BTreeMap<u64, Vec<MembershipOp>>,
        processed_through_round: &mut u64,
        finalized: &[(Event, u64)],
    ) {
        let Some(new_max) = finalized.iter().map(|(_, round)| *round).max() else {
            return;
        };
        if new_max <= *processed_through_round {
            return;
        }
        for (event, round_received) in finalized {
            if *round_received <= *processed_through_round {
                continue;
            }
            let result = self.execute_event(event);
            if !result.membership_ops.is_empty() {
                pending.entry(*round_received).or_default().extend(result.membership_ops);
            }
        }
        *processed_through_round = new_max;
    }

    /// Applies a DID operation to the state after verifying the signature.
    ///
    /// The single mandatory state lookup doubles as the create-vs-update
    /// branch:
    ///
    /// - **No prior document** (creation): the signature must verify against
    ///   `document.verification_methods[signed_by]` — the operation is
    ///   self-signed.
    /// - **Prior document found** (update / deactivation): the signature must
    ///   verify against the prior document's `verification_methods[signed_by]`.
    ///
    /// On success the document is written to state via `Op::Put`, reusing the
    /// existing KV path unchanged.
    fn apply_did_op(&mut self, did_op: crate::did::DidOp) -> Result<(), DidError> {
        use ed25519_dalek::VerifyingKey;

        let key = did_op.id().encode();
        let signed_payload = did_op.signed_payload();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(did_op.signature().as_bytes());

        match self.state.get(&key) {
            None => {
                // Creation: verify self-signed by the new document's own key.
                let idx = did_op.signed_by() as usize;
                let verifying_key: &VerifyingKey = did_op
                    .document()
                    .verification_methods()
                    .get(idx)
                    .ok_or(DidError::UnknownSigner)?;
                verifying_key
                    .verify(&signed_payload, &dalek_sig)
                    .map_err(|_| DidError::InvalidSignature)?;
            }
            Some(encoded_doc) => {
                // Update / deactivation: verify against the prior document.
                let mut cursor = &encoded_doc[..];
                let prior_doc =
                    DidDocument::decode(&mut cursor).map_err(|_| DidError::InvalidSignature)?;
                // Reject trailing bytes in the stored encoding.
                if !cursor.is_empty() {
                    return Err(DidError::InvalidSignature);
                }
                if prior_doc.deactivated() {
                    return Err(DidError::AlreadyDeactivated);
                }
                let idx = did_op.signed_by() as usize;
                let verifying_key: &VerifyingKey =
                    prior_doc.verification_methods().get(idx).ok_or(DidError::UnknownSigner)?;
                verifying_key
                    .verify(&signed_payload, &dalek_sig)
                    .map_err(|_| DidError::InvalidSignature)?;
            }
        }

        self.state.apply(&Op::Put { key: did_op.id().encode(), value: did_op.document().encode() });
        Ok(())
    }
}

/// Collects every finalized event in the hashgraph's consensus order, ready
/// to feed to [`Executor::execute_event`].
///
/// Rounds are visited in increasing order up to [`Hashgraph::max_ordered_round`],
/// and within a round the events come from [`Hashgraph::consensus_order`]
/// unchanged — that function sorts by `roundReceived`, then
/// `consensusTimestamp`, then the signature-derived tie-break. The executor
/// therefore reuses the exact ordering `order.rs` already produces instead of
/// defining its own.
///
/// The walk is bounded by the highest round that has an ordered event, not by
/// witness contiguity from round 1: a Phase 4 reconnect learner holds no
/// round-1 history (its accepted rounds were seeded from a checkpoint), so
/// `witnesses_of_round(1)` is empty for it even though later rounds have
/// ordered events. Rounds with no ordered events simply contribute nothing.
pub fn finalized_events(hashgraph: &Hashgraph) -> Vec<Event> {
    (1..=hashgraph.max_ordered_round())
        .flat_map(|round| hashgraph.consensus_order(round))
        .filter_map(|hash| hashgraph.get(&hash).map(|record| record.event().clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use crypto::MembershipOp;
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::StateDb;
    use crate::did::{
        DidDocument,
        DidId,
        DidOp,
    };
    use crate::op::Op;

    fn new_executor() -> Executor {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        Executor::new(db.state_keyspace())
    }

    fn new_state() -> State {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        State::new(db.state_keyspace())
    }

    fn event_with(payload: Vec<Transaction>) -> Event {
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), payload)
            .finalize(Signature::default())
    }

    fn membership_tx() -> Transaction {
        let op = MembershipOp::Add {
            node: NodeId::new(7),
            key: Box::new(SigningKey::from_bytes(&[1u8; 32]).verifying_key()),
            addr: "127.0.0.1:7000".parse().expect("valid addr"),
            reconnect_addr: None,
        };
        let mut payload = vec![0x02];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    #[test]
    fn execute_event_applies_all_valid_transactions() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put)]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert!(result.membership_ops.is_empty());
        assert!(result.did_errors.is_empty());
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn from_state_restores_exactly_the_given_state() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        let executor = Executor::from_state(state.clone());
        assert_eq!(executor.state(), &state);
        assert_eq!(executor.into_state(), state);
    }

    #[test]
    fn execute_event_collects_malformed_payload_errors() {
        let malformed = vec![0x7f];
        let event = event_with(vec![Transaction::from_bytes(malformed)]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert_eq!(result.errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn execute_event_skips_malformed_and_applies_the_rest() {
        let malformed = vec![0x7f];
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event =
            event_with(vec![Transaction::from_bytes(malformed), Transaction::from_bytes(put)]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert_eq!(result.errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn execute_event_separates_membership_op_into_side_channel() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put), membership_tx()]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert_eq!(result.membership_ops.len(), 1);
        assert!(result.did_errors.is_empty());
        // The membership op never touches State.
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn bucket_finalized_is_idempotent() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let finalized = vec![
            (event_with(vec![Transaction::from_bytes(put)]), 1),
            (event_with(vec![membership_tx()]), 2),
        ];

        let mut executor = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut processed_through_round = 0u64;

        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));

        // The same batch again must not re-bucket or re-apply anything.
        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
    }

    #[test]
    fn bucket_finalized_skips_rounds_below_the_watermark() {
        let finalized = vec![(event_with(vec![membership_tx()]), 3)];
        let mut executor = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut processed_through_round = 5u64;

        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert!(pending.is_empty());
        assert_eq!(processed_through_round, 5);
    }

    // --- DID tests ---

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn verifying_key(seed: u8) -> ed25519_dalek::VerifyingKey {
        signing_key(seed).verifying_key()
    }

    fn did_id(alias: &str) -> DidId {
        DidId::new("testnet".into(), alias.to_owned(), [0xaa; 16])
    }

    /// Builds a signed DID transaction with the given keys and parameters.
    ///
    /// `authorizer_seed` is the signing key index. `doc_keys` are the
    /// verification method key indices for the new document.
    fn did_tx(alias: &str, authorizer_seed: u8, doc_keys: &[u8], deactivated: bool) -> Transaction {
        let id = did_id(alias);
        let methods: Vec<_> = doc_keys.iter().map(|&s| verifying_key(s)).collect();
        let doc = DidDocument::new(methods, deactivated).expect("valid doc");
        let mut payload_to_sign = id.encode();
        payload_to_sign.extend_from_slice(&doc.encode());
        let sig = signing_key(authorizer_seed).sign(&payload_to_sign);
        let op = DidOp::new(id, doc, primitives::Signature::new(sig.to_bytes()), 0);
        let mut payload = vec![0x03];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    #[test]
    fn did_creation_self_signed_succeeds() {
        let tx = did_tx("alice", 1, &[1], false);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        let key = did_id("alice").encode();
        assert!(executor.state().contains(&key));
    }

    #[test]
    fn did_creation_rejects_bad_signature() {
        // Sign with key 2 but the document only has key 1.
        let tx = did_tx("alice", 2, &[1], false);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_creation_rejects_duplicate_identifier() {
        let tx1 = did_tx("alice", 1, &[1], false);
        let tx2 = did_tx("alice", 2, &[2], false);
        let event = event_with(vec![tx1, tx2]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        // First succeeds, second fails: prior doc exists (key 1), signed_by=0
        // points at prior doc's key 1, but signature was made with key 2.
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        // Only the first document is in state.
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_update_succeeds_with_current_verification_method() {
        // Create with key 1.
        let create = did_tx("alice", 1, &[1], false);
        // Update: rotate to key 2, signed by key 1 (current authorizer).
        let update = did_tx("alice", 1, &[2], false);
        let event = event_with(vec![create, update]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_update_rejects_signature_from_non_current_key() {
        // Create with key 1.
        let create = did_tx("alice", 1, &[1], false);
        // Update: signed by key 2 (rotated-out key can't sign).
        let update = did_tx("alice", 2, &[2], false);
        let event = event_with(vec![create, update]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        // Only the create was applied.
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_deactivation_is_tombstone_not_delete() {
        let create = did_tx("alice", 1, &[1], false);
        let deactivate = did_tx("alice", 1, &[1], true);
        let event = event_with(vec![create, deactivate]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        // Key still present in state.
        let key = did_id("alice").encode();
        assert!(executor.state().contains(&key));
        // Value decodes with deactivated: true.
        let encoded_doc = executor.state().get(&key).expect("present");
        let mut cursor = &encoded_doc[..];
        let doc = DidDocument::decode(&mut cursor).expect("decodes");
        assert!(doc.deactivated());
    }

    #[test]
    fn did_op_rejects_more_than_five_verification_methods() {
        // Build a raw DID payload with 6 verification methods, bypassing
        // DidDocument::new which would reject at construction time.
        let id = did_id("alice");
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.encode());
        // 6 keys — exceeds MAX_VERIFICATION_METHODS.
        payload.push(6);
        for i in 0..6u8 {
            payload.extend_from_slice(&verifying_key(i).to_bytes());
        }
        payload.push(0); // deactivated = false
        payload.extend_from_slice(&[0u8; 64]); // signature
        payload.push(0); // signed_by

        let mut outer = vec![0x03];
        outer.extend_from_slice(&payload);
        let event = event_with(vec![Transaction::from_bytes(outer)]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert_eq!(result.errors, vec![ExecutorError::MalformedDidOp]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_op_rejects_zero_verification_methods() {
        // Build a raw DID payload with 0 verification methods.
        let id = did_id("alice");
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.encode());
        payload.push(0); // 0 keys — empty list
        payload.push(0); // deactivated
        payload.extend_from_slice(&[0u8; 64]); // signature
        payload.push(0); // signed_by

        let mut outer = vec![0x03];
        outer.extend_from_slice(&payload);
        let event = event_with(vec![Transaction::from_bytes(outer)]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert_eq!(result.errors, vec![ExecutorError::MalformedDidOp]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_deactivation_revival_is_rejected() {
        let create = did_tx("alice", 1, &[1], false);
        let deactivate = did_tx("alice", 1, &[1], true);
        let event = event_with(vec![create, deactivate]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());

        // Attempt to revive the deactivated DID.
        let revive = did_tx("alice", 1, &[1], false);
        let event = event_with(vec![revive]);
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::AlreadyDeactivated]);
    }

    #[test]
    fn did_update_rejects_unknown_identifier() {
        // Try to update "alice" which doesn't exist — signed by key 2,
        // document has key 1, signed_by=0. No prior doc exists so this
        // is treated as a creation attempt. signed_by=0 is in range for
        // the new doc, but the signature was made with key 2 while the
        // doc's key 0 is key 1 → InvalidSignature.
        let tx = did_tx("alice", 2, &[1], false);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = executor.execute_event(&event);

        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        assert!(executor.state().is_empty());
    }
}
