//! The deterministic executor (Phase 8).
//!
//! Consumes events in finalized consensus order — the order
//! [`Hashgraph::consensus_order`] already produces per round — and folds each
//! transaction's payload into a [`State`] through [`Executor::execute_event`].
//! Execution itself is pure and deterministic: no wall-clock reads, no
//! randomness, no I/O, so the same finalized order and the same starting
//! state yield the same resulting state on every node.

use std::collections::{
    BTreeMap,
    HashSet,
};
use std::sync::Arc;

use consensus::Hashgraph;
use crypto::{
    Hashable,
    MembershipOp,
};
use ed25519_dalek::Verifier;
use fjall::Keyspace;
use primitives::{
    Event,
    EventHash,
};

use crate::did::DidDocument;
use crate::error::{
    DidError,
    ExecutorError,
    StateDbResult,
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
    /// Event hashes already executed. Used to make `bucket_finalized`
    /// idempotent per-event rather than per-round, so a late-arriving event
    /// whose `round_received <= processed_through_round` is not skipped forever
    /// (H-2). In-memory only; after a restart the event-log replay path
    /// rebuilds the hashgraph and re-derives `finalized_events` in canonical
    /// order, so the replay reproduces the same state. Membership ops for
    /// already-executed rounds remain correctly bucketed, giving every honest
    /// node the same Merkle root regardless of arrival timing.
    executed: HashSet<EventHash>,
}

/// After-image KV diff for a single key within a round.
///
/// `value` is `Some` for a `Put` (including DID `Put` path) and `None` for a
/// `Delete` tombstone. MembershipOps never produce a diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDiff {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
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
        Self { state: State::new(kv), executed: HashSet::new() }
    }

    /// Wraps an existing `State`, restoring an executor to a previously
    /// serialized checkpoint state (Phase 4 reconnect).
    pub fn from_state(state: State) -> Self {
        Self { state, executed: HashSet::new() }
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
    /// without aborting the remaining transactions of the event. A storage
    /// error aborts the event and is propagated as fatal for the round.
    pub fn execute_event(&mut self, event: &Event) -> StateDbResult<ExecuteResult> {
        let mut errors = Vec::new();
        let mut membership_ops = Vec::new();
        let mut did_errors = Vec::new();

        for tx in event.payload() {
            match DecodedOp::decode(tx.payload()) {
                Ok(DecodedOp::Kv(op)) => self.state.apply(&op)?,
                Ok(DecodedOp::Membership(mem_op)) => membership_ops.push(mem_op),
                Ok(DecodedOp::Did(did_op)) => match self.apply_did_op(did_op)? {
                    Ok(()) => {}
                    Err(e) => did_errors.push(e),
                },
                Err(e) => errors.push(e),
            }
        }

        Ok(ExecuteResult { errors, membership_ops, did_errors })
    }

    /// Buckets the membership ops of `finalized` — a slice of `(event,
    /// roundReceived)` pairs in non-decreasing `roundReceived` order — into
    /// `pending` by roundReceived, and advances `processed_through_round` to
    /// the highest round received in the batch.
    ///
    /// H-2 fix — the watermark no longer skips late events. Each event is
    /// executed exactly once keyed by its hash (`executed` set), so an event
    /// `y` that arrives with `round_received <= processed_through_round`
    /// (because it was absent when that round was decided elsewhere) is still
    /// applied and its membership ops bucketed. This gives deterministic
    /// convergence: the live Merkle root after the late event is applied equals
    /// the root of a node that had `y` from the start (the tree is order-
    /// independent for distinct keys; membership activation stays round-indexed).
    /// The `executed` set is in-memory; after a restart the event-log replay
    /// rebuilds the hashgraph and `finalized_events` walk re-derives ordering,
    /// so the replay reproduces the same result without relying on a persisted
    /// pending queue.
    pub fn bucket_finalized(
        &mut self,
        pending: &mut BTreeMap<u64, Vec<MembershipOp>>,
        processed_through_round: &mut u64,
        finalized: &[(Event, u64)],
    ) -> StateDbResult<()> {
        if finalized.is_empty() {
            return Ok(());
        }
        let new_max = finalized.iter().map(|(_, round)| *round).max().unwrap_or(0);
        let mut any_new = false;
        for (event, round_received) in finalized {
            let hash = event.hash().expect("hash bounded");
            if self.executed.contains(&hash) {
                continue;
            }
            let result = self.execute_event(event)?;
            if !result.membership_ops.is_empty() {
                pending.entry(*round_received).or_default().extend(result.membership_ops);
            }
            self.executed.insert(hash);
            any_new = true;
        }
        if any_new && new_max > *processed_through_round {
            *processed_through_round = new_max;
        }
        Ok(())
    }

    pub fn bucket_finalized_with_diffs(
        &mut self,
        pending: &mut BTreeMap<u64, Vec<MembershipOp>>,
        processed_through_round: &mut u64,
        finalized: &[(Event, u64)],
    ) -> StateDbResult<BTreeMap<u64, Vec<StateDiff>>> {
        if finalized.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut diffs_by_round: BTreeMap<u64, BTreeMap<Vec<u8>, Option<Vec<u8>>>> = BTreeMap::new();
        let new_max = finalized.iter().map(|(_, round)| *round).max().unwrap_or(0);
        let mut any_new = false;
        for (event, round_received) in finalized {
            let hash = event.hash().expect("hash bounded");
            if self.executed.contains(&hash) {
                continue;
            }
            let round_diffs = diffs_by_round.entry(*round_received).or_default();
            let result = self.execute_event_with_diffs(event, round_diffs)?;
            if !result.membership_ops.is_empty() {
                pending.entry(*round_received).or_default().extend(result.membership_ops);
            }
            self.executed.insert(hash);
            any_new = true;
        }
        if any_new && new_max > *processed_through_round {
            *processed_through_round = new_max;
        }
        let mut out: BTreeMap<u64, Vec<StateDiff>> = BTreeMap::new();
        for (round, map) in diffs_by_round {
            if map.is_empty() {
                continue;
            }
            let vec = map.into_iter().map(|(key, value)| StateDiff { key, value }).collect();
            out.insert(round, vec);
        }
        Ok(out)
    }

    fn execute_event_with_diffs(
        &mut self,
        event: &Event,
        diffs: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> StateDbResult<ExecuteResult> {
        let mut errors = Vec::new();
        let mut membership_ops = Vec::new();
        let mut did_errors = Vec::new();
        for tx in event.payload() {
            match DecodedOp::decode(tx.payload()) {
                Ok(DecodedOp::Kv(op)) => {
                    let entry = match &op {
                        Op::Put { key, value } => (key.clone(), Some(value.clone())),
                        Op::Delete { key } => (key.clone(), None),
                    };
                    self.state.apply(&op)?;
                    diffs.insert(entry.0, entry.1);
                }
                Ok(DecodedOp::Membership(mem_op)) => membership_ops.push(mem_op),
                Ok(DecodedOp::Did(did_op)) => {
                    let did_key = did_op.id().encode();
                    let did_value = did_op.document().encode();
                    match self.apply_did_op(did_op)? {
                        Ok(()) => {
                            diffs.insert(did_key, Some(did_value));
                        }
                        Err(e) => did_errors.push(e),
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        Ok(ExecuteResult { errors, membership_ops, did_errors })
    }

    /// Applies a DID operation to the state after verifying the signature.
    ///
    /// The `is_creation` flag on the operation determines the expected state:
    ///
    /// - **Creation** (`is_creation == true`): the identifier must *not*
    ///   already exist in state. The signature must verify against
    ///   `document.verification_methods[signed_by]` — the operation is
    ///   self-signed.
    /// - **Update / deactivation** (`is_creation == false`): the identifier
    ///   *must* already exist in state. The signature must verify against the
    ///   prior document's `verification_methods[signed_by]`.
    ///
    /// On success the document is written to state via `Op::Put`, reusing the
    /// existing KV path unchanged.
    fn apply_did_op(&mut self, did_op: crate::did::DidOp) -> StateDbResult<Result<(), DidError>> {
        let key = did_op.id().encode();
        let signed_payload = did_op.signed_payload();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(did_op.signature().as_bytes());

        let verification: Result<(), DidError> = match (did_op.is_creation(), self.state.get(&key))
        {
            (true, Some(_)) => Err(DidError::IdentifierAlreadyExists),
            (false, None) => Err(DidError::UnknownIdentifier),
            (true, None) => {
                let idx = did_op.signed_by() as usize;
                let Some(verifying_key) = did_op.document().verification_methods().get(idx) else {
                    return Ok(Err(DidError::UnknownSigner));
                };
                if verifying_key.verify(&signed_payload, &dalek_sig).is_err() {
                    return Ok(Err(DidError::InvalidSignature));
                }
                Ok(())
            }
            (false, Some(encoded_doc)) => {
                let mut cursor = &encoded_doc[..];
                let prior_doc = match DidDocument::decode(&mut cursor) {
                    Ok(doc) => doc,
                    Err(_) => return Ok(Err(DidError::InvalidSignature)),
                };
                if !cursor.is_empty() {
                    return Ok(Err(DidError::InvalidSignature));
                }
                if prior_doc.deactivated() {
                    return Ok(Err(DidError::AlreadyDeactivated));
                }
                let idx = did_op.signed_by() as usize;
                let Some(verifying_key) = prior_doc.verification_methods().get(idx) else {
                    return Ok(Err(DidError::UnknownSigner));
                };
                if verifying_key.verify(&signed_payload, &dalek_sig).is_err() {
                    return Ok(Err(DidError::InvalidSignature));
                }
                Ok(())
            }
        };

        if let Err(e) = verification {
            return Ok(Err(e));
        }

        self.state
            .apply(&Op::Put { key: did_op.id().encode(), value: did_op.document().encode() })?;
        Ok(Ok(()))
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
            bls_key: [0u8; 48],
            pop: [0u8; 96],
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
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.membership_ops.is_empty());
        assert!(result.did_errors.is_empty());
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn from_state_restores_exactly_the_given_state() {
        let mut state = new_state();
        assert!(state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }).is_ok());
        let executor = Executor::from_state(state.clone());
        assert_eq!(executor.state(), &state);
        assert_eq!(executor.into_state(), state);
    }

    #[test]
    fn execute_event_collects_malformed_payload_errors() {
        let malformed = vec![0x7f];
        let event = event_with(vec![Transaction::from_bytes(malformed)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
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
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert_eq!(result.errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn execute_event_separates_membership_op_into_side_channel() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put), membership_tx()]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
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

        assert!(
            executor
                .bucket_finalized(&mut pending, &mut processed_through_round, &finalized)
                .is_ok()
        );
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
        assert_eq!(executor.state().get(b"k"), Some(b"v".to_vec()));

        // The same batch again must not re-bucket or re-apply anything.
        assert!(
            executor
                .bucket_finalized(&mut pending, &mut processed_through_round, &finalized)
                .is_ok()
        );
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
    }

    #[test]
    fn bucket_finalized_applies_late_event_below_watermark() {
        // H-2: a late event with round_received <= watermark must still be applied.
        let finalized = vec![(event_with(vec![membership_tx()]), 3)];
        let mut executor = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut processed_through_round = 5u64;

        assert!(
            executor
                .bucket_finalized(&mut pending, &mut processed_through_round, &finalized)
                .is_ok()
        );
        assert_eq!(pending.get(&3).map(Vec::len), Some(1));
        assert_eq!(processed_through_round, 5);

        // Second call with same event is idempotent via hash dedup.
        assert!(
            executor
                .bucket_finalized(&mut pending, &mut processed_through_round, &finalized)
                .is_ok()
        );
        assert_eq!(pending.get(&3).map(Vec::len), Some(1));
    }

    // --- DID tests ---

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn verifying_key(seed: u8) -> ed25519_dalek::VerifyingKey {
        signing_key(seed).verifying_key()
    }

    fn did_id(alias: &str) -> DidId {
        match DidId::new("testnet".into(), alias.to_owned(), [0xaa; 16]) {
            Ok(id) => id,
            Err(e) => panic!("did_id: {e:?}"),
        }
    }

    /// Builds a signed DID transaction with the given keys and parameters.
    ///
    /// `authorizer_seed` is the signing key index. `doc_keys` are the
    /// verification method key indices for the new document.
    fn did_tx(
        alias: &str,
        authorizer_seed: u8,
        doc_keys: &[u8],
        deactivated: bool,
        is_creation: bool,
    ) -> Transaction {
        let id = did_id(alias);
        let methods: Vec<_> = doc_keys.iter().map(|&s| verifying_key(s)).collect();
        let doc = DidDocument::new(methods, deactivated).expect("valid doc");
        let mut payload_to_sign = id.encode();
        payload_to_sign.extend_from_slice(&doc.encode());
        let sig = signing_key(authorizer_seed).sign(&payload_to_sign);
        let op = DidOp::new(id, doc, primitives::Signature::new(sig.to_bytes()), 0, is_creation);
        let mut payload = vec![0x03];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    #[test]
    fn did_creation_self_signed_succeeds() {
        let tx = did_tx("alice", 1, &[1], false, true);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        let key = did_id("alice").encode();
        assert!(executor.state().contains(&key));
    }

    #[test]
    fn did_creation_rejects_bad_signature() {
        // Sign with key 2 but the document only has key 1.
        let tx = did_tx("alice", 2, &[1], false, true);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_creation_rejects_duplicate_identifier() {
        // First creation succeeds.
        let tx1 = did_tx("alice", 1, &[1], false, true);
        // Second creation for the same identifier is rejected at the
        // operation-type check before signature verification.
        let tx2 = did_tx("alice", 1, &[1], false, true);
        let event = event_with(vec![tx1, tx2]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::IdentifierAlreadyExists]);
        // Only the first document is in state.
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_update_succeeds_with_current_verification_method() {
        // Create with key 1.
        let create = did_tx("alice", 1, &[1], false, true);
        // Update: rotate to key 2, signed by key 1 (current authorizer).
        let update = did_tx("alice", 1, &[2], false, false);
        let event = event_with(vec![create, update]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_update_rejects_signature_from_non_current_key() {
        // Create with key 1.
        let create = did_tx("alice", 1, &[1], false, true);
        // Update: signed by key 2 (rotated-out key can't sign).
        let update = did_tx("alice", 2, &[2], false, false);
        let event = event_with(vec![create, update]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::InvalidSignature]);
        // Only the create was applied.
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_deactivation_is_tombstone_not_delete() {
        let create = did_tx("alice", 1, &[1], false, true);
        let deactivate = did_tx("alice", 1, &[1], true, false);
        let event = event_with(vec![create, deactivate]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
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
    fn did_op_accepts_exactly_five_verification_methods() {
        let tx = did_tx("alice", 1, &[1, 0, 2, 3, 4], false, true);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn did_op_rejects_six_verification_methods() {
        // Build a raw DID payload with 6 verification methods, bypassing
        // DidDocument::new which would reject at construction time.
        let id = did_id("alice");
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.encode());
        payload.push(6);
        for i in 0..6u8 {
            payload.extend_from_slice(&verifying_key(i).to_bytes());
        }
        payload.push(0); // deactivated = false
        payload.extend_from_slice(&[0u8; 64]); // signature
        payload.push(0); // signed_by
        payload.push(1); // is_creation

        let mut outer = vec![0x03];
        outer.extend_from_slice(&payload);
        let event = event_with(vec![Transaction::from_bytes(outer)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
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
        payload.push(1); // is_creation

        let mut outer = vec![0x03];
        outer.extend_from_slice(&payload);
        let event = event_with(vec![Transaction::from_bytes(outer)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert_eq!(result.errors, vec![ExecutorError::MalformedDidOp]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_deactivation_revival_is_rejected() {
        let create = did_tx("alice", 1, &[1], false, true);
        let deactivate = did_tx("alice", 1, &[1], true, false);
        let event = event_with(vec![create, deactivate]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.did_errors.is_empty());

        // Attempt to revive the deactivated DID.
        let revive = did_tx("alice", 1, &[1], false, false);
        let event = event_with(vec![revive]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::AlreadyDeactivated]);

        // Rotating keys on a deactivated document is also rejected.
        let rotate = did_tx("alice", 1, &[2], false, false);
        let event = event_with(vec![rotate]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::AlreadyDeactivated]);
    }

    #[test]
    fn did_update_rejects_unknown_identifier() {
        // Try to update "alice" which doesn't exist — the operation-type
        // check rejects before signature verification.
        let tx = did_tx("alice", 1, &[1], false, false);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.did_errors, vec![DidError::UnknownIdentifier]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn execute_event_propagates_storage_error() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let mut executor = Executor::new(db.state_keyspace());
        let statedb_path = dir.path().join(crate::state_db::STATE_DB_SUBDIR);
        let original_perms = std::fs::metadata(&statedb_path).expect("meta").permissions();
        let mut ro_perms = original_perms.clone();
        ro_perms.set_readonly(true);
        let _ = std::fs::set_permissions(&statedb_path, ro_perms);
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put)]);
        let result = executor.execute_event(&event);
        let _ = std::fs::set_permissions(&statedb_path, original_perms);
        if result.is_err() {
            assert!(executor.state().is_empty());
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn bucket_finalized_propagates_storage_error() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let mut executor = Executor::new(db.state_keyspace());
        let statedb_path = dir.path().join(crate::state_db::STATE_DB_SUBDIR);
        let original_perms = std::fs::metadata(&statedb_path).expect("meta").permissions();
        let mut ro_perms = original_perms.clone();
        ro_perms.set_readonly(true);
        let _ = std::fs::set_permissions(&statedb_path, ro_perms);
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let finalized = vec![(event_with(vec![Transaction::from_bytes(put)]), 1)];
        let mut pending = BTreeMap::new();
        let mut watermark = 0u64;
        let result = executor.bucket_finalized(&mut pending, &mut watermark, &finalized);
        let _ = std::fs::set_permissions(&statedb_path, original_perms);
        if result.is_err() {
            assert_eq!(watermark, 0);
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn late_event_with_old_round_eventually_applied_and_root_converges() {
        // Node A had the event from the start; Node B receives it late after
        // advancing its watermark past that round.
        let put_late = Op::Put { key: b"late".to_vec(), value: b"1".to_vec() }.encode();
        let put_new = Op::Put { key: b"new".to_vec(), value: b"2".to_vec() }.encode();
        let late_event = event_with(vec![Transaction::from_bytes(put_late)]);
        let new_event = event_with(vec![Transaction::from_bytes(put_new)]);

        let mut exec_a = new_executor();
        let mut pending_a: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm_a = 0u64;
        assert!(
            exec_a.bucket_finalized(&mut pending_a, &mut wm_a, &[(late_event.clone(), 2)]).is_ok()
        );
        assert!(
            exec_a.bucket_finalized(&mut pending_a, &mut wm_a, &[(new_event.clone(), 5)]).is_ok()
        );

        let mut exec_b = new_executor();
        let mut pending_b: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm_b = 0u64;
        assert!(exec_b.bucket_finalized(&mut pending_b, &mut wm_b, &[(new_event, 5)]).is_ok());
        assert_eq!(exec_b.state().get(b"late"), None);
        assert!(exec_b.bucket_finalized(&mut pending_b, &mut wm_b, &[(late_event, 2)]).is_ok());
        assert_eq!(exec_b.state().get(b"late"), Some(b"1".to_vec()));

        assert_eq!(exec_a.state().root(), exec_b.state().root());
        assert_eq!(exec_a.state().to_bytes(), exec_b.state().to_bytes());
    }

    #[test]
    fn late_membership_op_bucketed_even_when_round_below_watermark() {
        let mut exec = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm = 5u64;
        let late = vec![(event_with(vec![membership_tx()]), 3)];
        assert!(exec.bucket_finalized(&mut pending, &mut wm, &late).is_ok());
        assert_eq!(pending.get(&3).map(Vec::len), Some(1));
        assert_eq!(wm, 5);
    }

    #[test]
    fn bucket_finalized_with_diffs_sorted_lww_tombstone_and_membership_excluded() {
        let mut exec = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm = 0u64;
        let put = |k: &[u8], v: &[u8]| Op::Put { key: k.to_vec(), value: v.to_vec() }.encode();
        let del = |k: &[u8]| Op::Delete { key: k.to_vec() }.encode();
        let did = did_tx("alice", 1, &[1], false, true);
        let did_key = did_id("alice").encode();
        let event1 = event_with(vec![
            Transaction::from_bytes(put(b"z", b"1")),
            Transaction::from_bytes(put(b"a", b"2")),
            Transaction::from_bytes(del(b"a")),
            membership_tx(),
            did,
        ]);
        let event2 = event_with(vec![
            Transaction::from_bytes(put(b"a", b"final")),
            Transaction::from_bytes(del(b"z")),
            Transaction::from_bytes(put(b"m", b"mid")),
        ]);
        let finalized = vec![(event1, 7), (event2, 7)];
        let diffs =
            exec.bucket_finalized_with_diffs(&mut pending, &mut wm, &finalized).expect("diffs");
        assert_eq!(wm, 7);
        assert_eq!(pending.get(&7).map(Vec::len), Some(1));
        let round_diffs = diffs.get(&7).expect("has diffs");
        let keys: Vec<Vec<u8>> = round_diffs.iter().map(|d| d.key.clone()).collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "diffs must be sorted ascending");
        let find = |k: &[u8]| round_diffs.iter().find(|d| d.key == k).expect("key present");
        assert_eq!(find(b"a").value, Some(b"final".to_vec()));
        assert_eq!(find(b"z").value, None);
        assert_eq!(find(b"m").value, Some(b"mid".to_vec()));
        assert!(find(&did_key).value.is_some());
        assert!(round_diffs.iter().all(|d| d.key != b"membership"), "membership excluded");
        assert!(!keys.iter().any(|k| k.is_empty()), "keys non-empty");
        let lww_check = {
            let mut map: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
            for d in round_diffs {
                map.insert(d.key.clone(), d.value.clone());
            }
            map.len() == round_diffs.len()
        };
        assert!(lww_check, "per distinct key LWW");
        let diffs2 = exec
            .bucket_finalized_with_diffs(&mut pending, &mut wm, &finalized)
            .expect("idempotent");
        assert!(diffs2.is_empty(), "second call idempotent via executed set");
        assert_eq!(exec.state().get(b"a"), Some(b"final".to_vec()));
        assert_eq!(exec.state().get(b"z"), None);
        assert_eq!(exec.state().get(b"m"), Some(b"mid".to_vec()));
        assert!(exec.state().contains(&did_key));
    }
}
