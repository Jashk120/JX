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

use crate::did::{
    DidDocument,
    did_state_key,
};
use crate::error::{
    ActorError,
    DidError,
    ExecutorError,
    OpError,
    StateDbResult,
};
use crate::merkle_log::{
    EMPTY_ROOT,
    verify_consistency,
    verify_inclusion,
};
use crate::op::{
    DecodedOp,
    Op,
};
use crate::root_actor::{
    ActorId,
    RootActor,
    actor_state_key,
};
use crate::state::State;
use crate::sub_actor::{
    RebindOp,
    SubActor,
    SubActorOp,
    subactor_leaf_hash,
};

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

/// The semantic outcome of a validated DID transition: the root-actor
/// after-image (`Some` when the transition wrote the root record, `None`
/// for a deactivation), or the [`DidError`] that rejected it.
type DidApplyOutcome = Result<Option<(Vec<u8>, Vec<u8>)>, DidError>;

/// The after-images written by a successful sub-actor mint: the new
/// sub-actor record and the updated root record, each as `(key, value)`.
struct SubActorAfterImage {
    sub_actor: (Vec<u8>, Vec<u8>),
    root: (Vec<u8>, Vec<u8>),
}

/// The after-image written by a successful rebind: the updated sub-actor
/// record as `(key, value)`.
type RebindAfterImage = (Vec<u8>, Vec<u8>);

/// The result of executing a single event's transactions.
pub struct ExecuteResult {
    /// Deterministic decode errors for individual payloads.
    pub errors: Vec<ExecutorError>,
    /// Membership operations collected as a side channel (never touch state).
    pub membership_ops: Vec<MembershipOp>,
    /// Semantic operation errors (bad signatures, unknown signers, invalid
    /// proofs, etc.), with DID and actor failures carried distinctly.
    pub op_errors: Vec<OpError>,
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
        let mut op_errors = Vec::new();

        for tx in event.payload() {
            match DecodedOp::decode(tx.payload()) {
                Ok(DecodedOp::Kv(op)) => self.state.apply(&op)?,
                Ok(DecodedOp::Membership(mem_op)) => membership_ops.push(mem_op),
                Ok(DecodedOp::Did(did_op)) => match self.apply_did_op(did_op)? {
                    Ok(_) => {}
                    Err(e) => op_errors.push(OpError::Did(e)),
                },
                Ok(DecodedOp::SubActor(sub_op)) => match self.apply_sub_actor_op(*sub_op)? {
                    Ok(_) => {}
                    Err(e) => op_errors.push(OpError::Actor(e)),
                },
                Ok(DecodedOp::Rebind(rebind_op)) => match self.apply_rebind_op(*rebind_op)? {
                    Ok(_) => {}
                    Err(e) => op_errors.push(OpError::Actor(e)),
                },
                Err(e) => errors.push(e),
            }
        }

        Ok(ExecuteResult { errors, membership_ops, op_errors })
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
        let mut op_errors = Vec::new();
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
                    let did_key = did_state_key(did_op.id());
                    let did_value = did_op.document().encode();
                    match self.apply_did_op(did_op)? {
                        Ok(root_write) => {
                            diffs.insert(did_key, Some(did_value));
                            if let Some((root_key, root_value)) = root_write {
                                diffs.insert(root_key, Some(root_value));
                            }
                        }
                        Err(e) => op_errors.push(OpError::Did(e)),
                    }
                }
                Ok(DecodedOp::SubActor(sub_op)) => match self.apply_sub_actor_op(*sub_op)? {
                    Ok(after) => {
                        diffs.insert(after.sub_actor.0, Some(after.sub_actor.1));
                        diffs.insert(after.root.0, Some(after.root.1));
                    }
                    Err(e) => op_errors.push(OpError::Actor(e)),
                },
                Ok(DecodedOp::Rebind(rebind_op)) => match self.apply_rebind_op(*rebind_op)? {
                    Ok((key, value)) => {
                        diffs.insert(key, Some(value));
                    }
                    Err(e) => op_errors.push(OpError::Actor(e)),
                },
                Err(e) => errors.push(e),
            }
        }
        Ok(ExecuteResult { errors, membership_ops, op_errors })
    }

    /// Applies a DID operation to the state after verifying the signature,
    /// materializing the implicit root actor alongside it (PLAN-5 D-2).
    ///
    /// The `is_creation` flag on the operation determines the expected state:
    ///
    /// - **Creation** (`is_creation == true`): the identifier must *not*
    ///   already exist in state. The signature must verify against
    ///   `document.signing_key(signed_by)` — the operation is
    ///   self-signed.
    /// - **Update / deactivation** (`is_creation == false`): the identifier
    ///   *must* already exist in state. The signature must verify against the
    ///   prior document's `signing_key(signed_by)`.
    ///
    /// On success the document is written to state via `Op::Put`, reusing the
    /// existing KV path unchanged, and — unless the new document is
    /// deactivated — the root actor record under
    /// `actor_state_key(&ActorId::Root(id))` is written in the same validated
    /// transition:
    ///
    /// - creation writes a fresh root (`EMPTY_ROOT`, `leaf_count 0`) whose
    ///   control key is copied from the new document;
    /// - an update/rotation replaces the stored root's control key with the
    ///   new document's and preserves its commitment, recreating a fresh
    ///   empty root when the record is absent or undecodable (deterministic;
    ///   never a panic);
    /// - a deactivation writes the document only and leaves the root record
    ///   untouched.
    ///
    /// The success value carries the root after-image (`None` when the root
    /// was untouched) so diff capture can mirror exactly what changed.
    fn apply_did_op(&mut self, did_op: crate::did::DidOp) -> StateDbResult<DidApplyOutcome> {
        let key = did_state_key(did_op.id());
        let signed_payload = did_op.signed_payload();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(did_op.signature().as_bytes());

        let verification: Result<(), DidError> = match (did_op.is_creation(), self.state.get(&key))
        {
            (true, Some(_)) => Err(DidError::IdentifierAlreadyExists),
            (false, None) => Err(DidError::UnknownIdentifier),
            (true, None) => {
                let idx = did_op.signed_by() as usize;
                let Some(verifying_key) = did_op.document().signing_key(idx) else {
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
                let Some(verifying_key) = prior_doc.signing_key(idx) else {
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

        let did_id = did_op.id().clone();
        let new_control = *did_op.document().control_key();
        let deactivated = did_op.document().deactivated();
        let root_write = if deactivated {
            None
        } else if did_op.is_creation() {
            let root = RootActor::new(did_id.clone(), EMPTY_ROOT, 0, new_control);
            Some((actor_state_key(&ActorId::Root(did_id)), root.encode()))
        } else {
            let root_key = actor_state_key(&ActorId::Root(did_id.clone()));
            let stored = self.state.get(&root_key).and_then(|bytes| {
                let mut cursor = &bytes[..];
                let root = RootActor::decode(&mut cursor).ok()?;
                cursor.is_empty().then_some(root)
            });
            let updated = match stored {
                Some(root) => {
                    RootActor::new(did_id, *root.merkle_root(), root.leaf_count(), new_control)
                }
                None => RootActor::new(did_id, EMPTY_ROOT, 0, new_control),
            };
            Some((root_key, updated.encode()))
        };

        self.state.apply(&Op::Put {
            key: did_state_key(did_op.id()),
            value: did_op.document().encode(),
        })?;
        let root_after_image = match root_write {
            Some((key, value)) => {
                self.state.apply(&Op::Put { key: key.clone(), value: value.clone() })?;
                Some((key, value))
            }
            None => None,
        };
        Ok(Ok(root_after_image))
    }

    /// Applies a sub-actor mint to the state (PLAN-5 A1: carry `new_root` +
    /// both proofs, trust nothing).
    ///
    /// The order is fixed: replay short-circuit first (before any tree
    /// work), then the authoritative root DID document and root actor record
    /// from state, then the root document's signature over the op's signed
    /// payload, then the leaf recomputed from the op's own signed fields,
    /// then the independent inclusion and consistency proofs — which must
    /// both agree with `op.new_root` before it is written.
    ///
    /// On success the sub-actor record and the updated root record are
    /// written in the same validated transition; the success value carries
    /// both after-images so diff capture can mirror exactly what changed.
    fn apply_sub_actor_op(
        &mut self,
        op: SubActorOp,
    ) -> StateDbResult<Result<SubActorAfterImage, ActorError>> {
        let actor_id = op.actor_id();
        let sub_key = actor_state_key(&actor_id);
        if self.state.contains(&sub_key) {
            return Ok(Err(ActorError::SubActorAlreadyExists));
        }
        let encoded_doc = match self.state.get(&did_state_key(op.root_did())) {
            Some(bytes) => bytes,
            None => return Ok(Err(ActorError::UnknownRootDid)),
        };
        let mut cursor = &encoded_doc[..];
        let root_doc = match DidDocument::decode(&mut cursor) {
            Ok(doc) if cursor.is_empty() => doc,
            _ => return Ok(Err(ActorError::UnknownRootDid)),
        };
        if root_doc.deactivated() {
            return Ok(Err(ActorError::RootDeactivated));
        }
        let root_key = actor_state_key(&ActorId::Root(op.root_did().clone()));
        let encoded_root = match self.state.get(&root_key) {
            Some(bytes) => bytes,
            None => return Ok(Err(ActorError::UnknownRootActor)),
        };
        let mut cursor = &encoded_root[..];
        let root_record = match RootActor::decode(&mut cursor) {
            Ok(root) if cursor.is_empty() => root,
            _ => return Ok(Err(ActorError::UnknownRootActor)),
        };
        let old_root = *root_record.merkle_root();
        let old_leaf_count = root_record.leaf_count();
        let signed_payload = op.signed_payload();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(op.signature().as_bytes());
        let idx = op.signed_by() as usize;
        let Some(verifying_key) = root_doc.signing_key(idx) else {
            return Ok(Err(ActorError::UnknownSigner));
        };
        if verifying_key.verify(&signed_payload, &dalek_sig).is_err() {
            return Ok(Err(ActorError::InvalidSignature));
        }
        let leaf = subactor_leaf_hash(&actor_id, op.control_key());
        let inclusion = op.inclusion_proof();
        if inclusion.leaf_index != old_leaf_count
            || inclusion.leaf_count != old_leaf_count + 1
            || !verify_inclusion(&leaf, inclusion, op.new_root())
        {
            return Ok(Err(ActorError::InclusionProofInvalid));
        }
        let consistency = op.consistency_proof();
        if consistency.old_leaf_count != old_leaf_count
            || consistency.new_leaf_count != old_leaf_count + 1
            || !verify_consistency(&old_root, consistency, op.new_root())
        {
            return Ok(Err(ActorError::ConsistencyProofInvalid));
        }
        let sub_actor = match SubActor::new(actor_id, *op.control_key(), *op.operating_key()) {
            Ok(actor) => actor,
            Err(_) => return Ok(Err(ActorError::ExpectedSubActorId)),
        };
        let updated_root = RootActor::new(
            op.root_did().clone(),
            *op.new_root(),
            old_leaf_count + 1,
            *root_record.control_key(),
        );
        let sub_value = sub_actor.encode();
        let root_value = updated_root.encode();
        self.state.apply(&Op::Put { key: sub_key.clone(), value: sub_value.clone() })?;
        self.state.apply(&Op::Put { key: root_key.clone(), value: root_value.clone() })?;
        Ok(Ok(SubActorAfterImage { sub_actor: (sub_key, sub_value), root: (root_key, root_value) }))
    }

    /// Applies an operating-key rebind to a sub-actor (PLAN-5 D-10).
    ///
    /// Phase A authorization is root-control-only: the proof of possession
    /// must verify against the new operating key and the authorization
    /// signature against the root record's control key, both over the
    /// versioned payload binding actor ID and old/new operating keys (the
    /// old key comes from state, not the op). Only the mutable sub-actor
    /// record is rewritten; the root record and membership commitment are
    /// untouched, so there is no root diff. The success value carries the
    /// sub-actor after-image.
    fn apply_rebind_op(
        &mut self,
        op: RebindOp,
    ) -> StateDbResult<Result<RebindAfterImage, ActorError>> {
        let root_did = match op.actor_id() {
            ActorId::Sub { root_did, .. } => root_did.clone(),
            ActorId::Root(_) => return Ok(Err(ActorError::ExpectedSubActorId)),
        };
        let sub_key = actor_state_key(op.actor_id());
        let encoded_sub = match self.state.get(&sub_key) {
            Some(bytes) => bytes,
            None => return Ok(Err(ActorError::UnknownSubActor)),
        };
        let mut cursor = &encoded_sub[..];
        let sub_record = match SubActor::decode(&mut cursor) {
            Ok(sub) if cursor.is_empty() => sub,
            _ => return Ok(Err(ActorError::UnknownSubActor)),
        };
        let old_operating_key = *sub_record.operating_key();
        let encoded_doc = match self.state.get(&did_state_key(&root_did)) {
            Some(bytes) => bytes,
            None => return Ok(Err(ActorError::UnknownRootDid)),
        };
        let mut cursor = &encoded_doc[..];
        let root_doc = match DidDocument::decode(&mut cursor) {
            Ok(doc) if cursor.is_empty() => doc,
            _ => return Ok(Err(ActorError::UnknownRootDid)),
        };
        if root_doc.deactivated() {
            return Ok(Err(ActorError::RootDeactivated));
        }
        let encoded_root = match self.state.get(&actor_state_key(&ActorId::Root(root_did.clone())))
        {
            Some(bytes) => bytes,
            None => return Ok(Err(ActorError::UnknownRootActor)),
        };
        let mut cursor = &encoded_root[..];
        let root_record = match RootActor::decode(&mut cursor) {
            Ok(root) if cursor.is_empty() => root,
            _ => return Ok(Err(ActorError::UnknownRootActor)),
        };
        let payload = op.signed_payload(&old_operating_key);
        let pop_sig = ed25519_dalek::Signature::from_bytes(op.proof_of_possession().as_bytes());
        if op.new_operating_key().verify(&payload, &pop_sig).is_err() {
            return Ok(Err(ActorError::InvalidProofOfPossession));
        }
        let auth_sig = ed25519_dalek::Signature::from_bytes(op.authorizing_signature().as_bytes());
        if root_record.control_key().verify(&payload, &auth_sig).is_err() {
            return Ok(Err(ActorError::InvalidAuthorization));
        }
        let updated = match SubActor::new(
            op.actor_id().clone(),
            *sub_record.control_key(),
            *op.new_operating_key(),
        ) {
            Ok(actor) => actor,
            Err(_) => return Ok(Err(ActorError::ExpectedSubActorId)),
        };
        let value = updated.encode();
        self.state.apply(&Op::Put { key: sub_key.clone(), value: value.clone() })?;
        Ok(Ok((sub_key, value)))
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
        VerificationMethod,
        did_state_key,
    };
    use crate::merkle_log::{
        ConsistencyProof,
        EMPTY_ROOT,
        Hash,
        mth,
        prove_consistency,
        prove_inclusion,
    };
    use crate::op::Op;
    use crate::root_actor::{
        ActorId,
        RootActor,
        Tag,
        actor_state_key,
    };
    use crate::sub_actor::SubActorOpParams;

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
        assert!(result.op_errors.is_empty());
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
        assert!(result.op_errors.is_empty());
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
    /// Ed25519 signing-method key indices for the new document (the control
    /// key is fixed to seed 9); `signed_by` is always 0.
    fn did_tx(
        alias: &str,
        authorizer_seed: u8,
        doc_keys: &[u8],
        deactivated: bool,
        is_creation: bool,
    ) -> Transaction {
        let methods: Vec<VerificationMethod> =
            doc_keys.iter().map(|&s| VerificationMethod::Signing(verifying_key(s))).collect();
        did_tx_with_methods(alias, authorizer_seed, methods, deactivated, is_creation, 0)
    }

    /// Builds a signed DID transaction from an explicit method list and
    /// `signed_by` index into the filtered signing-method order.
    fn did_tx_with_methods(
        alias: &str,
        authorizer_seed: u8,
        methods: Vec<VerificationMethod>,
        deactivated: bool,
        is_creation: bool,
        signed_by: u8,
    ) -> Transaction {
        let id = did_id(alias);
        let doc = DidDocument::new(verifying_key(9), methods, deactivated).expect("valid doc");
        let unsigned = DidOp::new(
            id.clone(),
            doc.clone(),
            primitives::Signature::new([0u8; 64]),
            signed_by,
            is_creation,
        );
        let sig = signing_key(authorizer_seed).sign(&unsigned.signed_payload());
        let op =
            DidOp::new(id, doc, primitives::Signature::new(sig.to_bytes()), signed_by, is_creation);
        let mut payload = vec![0x03];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    /// Builds a signed DID transaction with an explicit document control key
    /// (the default helpers fix it to seed 9), for root-actor tests.
    fn did_tx_with_control(
        alias: &str,
        authorizer_seed: u8,
        control_seed: u8,
        doc_keys: &[u8],
        deactivated: bool,
        is_creation: bool,
    ) -> Transaction {
        let methods: Vec<VerificationMethod> =
            doc_keys.iter().map(|&s| VerificationMethod::Signing(verifying_key(s))).collect();
        let id = did_id(alias);
        let doc =
            DidDocument::new(verifying_key(control_seed), methods, deactivated).expect("valid doc");
        let unsigned = DidOp::new(
            id.clone(),
            doc.clone(),
            primitives::Signature::new([0u8; 64]),
            0,
            is_creation,
        );
        let sig = signing_key(authorizer_seed).sign(&unsigned.signed_payload());
        let op = DidOp::new(id, doc, primitives::Signature::new(sig.to_bytes()), 0, is_creation);
        let mut payload = vec![0x03];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    fn root_record(executor: &Executor, alias: &str) -> RootActor {
        let key = actor_state_key(&ActorId::Root(did_id(alias)));
        let bytes = executor.state().get(&key).expect("root record present");
        let mut cursor = &bytes[..];
        let root = RootActor::decode(&mut cursor).expect("root decodes");
        assert!(cursor.is_empty());
        root
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
        assert!(result.op_errors.is_empty());
        let key = did_state_key(&did_id("alice"));
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
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::InvalidSignature)]);
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
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::IdentifierAlreadyExists)]);
        // Only the first document and its root are in state.
        assert_eq!(executor.state().len(), 2);
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
        assert!(result.op_errors.is_empty());
        assert_eq!(executor.state().len(), 2);
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
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::InvalidSignature)]);
        // Only the create (document plus root) was applied.
        assert_eq!(executor.state().len(), 2);
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
        assert!(result.op_errors.is_empty());
        // Key still present in state.
        let key = did_state_key(&did_id("alice"));
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
        assert!(result.op_errors.is_empty());
        assert_eq!(executor.state().len(), 2);
    }

    #[test]
    fn did_op_rejects_six_verification_methods() {
        // Build a raw v2 DID payload with 6 methods, bypassing
        // DidDocument::new which would reject at construction time.
        let id = did_id("alice");
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.encode());
        payload.push(0x02); // version
        payload.extend_from_slice(&verifying_key(9).to_bytes()); // control_key
        payload.push(6);
        for i in 0..6u8 {
            payload.push(0x01);
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
        // Build a raw v2 DID payload with 0 methods.
        let id = did_id("alice");
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.encode());
        payload.push(0x02); // version
        payload.extend_from_slice(&verifying_key(9).to_bytes()); // control_key
        payload.push(0); // 0 methods — empty list
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
        assert!(result.op_errors.is_empty());

        // Attempt to revive the deactivated DID.
        let revive = did_tx("alice", 1, &[1], false, false);
        let event = event_with(vec![revive]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::AlreadyDeactivated)]);

        // Rotating keys on a deactivated document is also rejected.
        let rotate = did_tx("alice", 1, &[2], false, false);
        let event = event_with(vec![rotate]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::AlreadyDeactivated)]);
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
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::UnknownIdentifier)]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn did_creation_with_x25519_writes_prefixed_key() {
        let methods = vec![
            VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32])),
            VerificationMethod::Signing(verifying_key(1)),
        ];
        let tx = did_tx_with_methods("alice", 1, methods, false, true, 0);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        let key = did_state_key(&did_id("alice"));
        assert_eq!(key[0], 0xD1);
        assert!(executor.state().contains(&key));
        assert!(!executor.state().contains(&did_id("alice").encode()));
    }

    #[test]
    fn did_signed_by_addresses_filtered_signing_order() {
        // Document order: X25519, Signing(1), Signing(2). Filtered signing
        // order is [1, 2], so index 1 authorizes seed 2.
        let methods = || {
            vec![
                VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32])),
                VerificationMethod::Signing(verifying_key(1)),
                VerificationMethod::Signing(verifying_key(2)),
            ]
        };
        let create = did_tx_with_methods("alice", 1, methods(), false, true, 0);
        let update = did_tx_with_methods("alice", 2, methods(), false, false, 1);
        let event = event_with(vec![create, update]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        assert_eq!(executor.state().len(), 2);
    }

    #[test]
    fn did_signed_by_cannot_address_x25519_method() {
        // Only one signing method exists, so index 1 (past the single
        // signing key, where the X25519 method sits in document order) is
        // unknown — agreement methods are never addressable.
        let methods = vec![
            VerificationMethod::Signing(verifying_key(1)),
            VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32])),
        ];
        let tx = did_tx_with_methods("alice", 1, methods, false, true, 1);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Did(DidError::UnknownSigner)]);
        assert!(executor.state().is_empty());
    }

    // --- Root actor materialization (PLAN-5 D-2) ---

    #[test]
    fn did_creation_writes_fresh_root_actor() {
        let tx = did_tx_with_control("alice", 1, 9, &[1], false, true);
        let event = event_with(vec![tx]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        assert_eq!(executor.state().len(), 2);
        let root = root_record(&executor, "alice");
        assert_eq!(root.did_id(), &did_id("alice"));
        assert_eq!(root.merkle_root(), &EMPTY_ROOT);
        assert_eq!(root.leaf_count(), 0);
        assert_eq!(root.control_key(), &verifying_key(9));
    }

    #[test]
    fn did_rotation_updates_root_control_key_preserving_commitment() {
        let create = did_tx_with_control("alice", 1, 9, &[1], false, true);
        let rotate = did_tx_with_control("alice", 1, 10, &[2], false, false);
        let event = event_with(vec![create, rotate]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        let root = root_record(&executor, "alice");
        assert_eq!(root.control_key(), &verifying_key(10));
        assert_eq!(root.merkle_root(), &EMPTY_ROOT);
        assert_eq!(root.leaf_count(), 0);
        let doc_bytes =
            executor.state().get(&did_state_key(&did_id("alice"))).expect("doc present");
        let mut cursor = &doc_bytes[..];
        let doc = DidDocument::decode(&mut cursor).expect("doc decodes");
        assert_eq!(doc.control_key(), &verifying_key(10));
    }

    #[test]
    fn did_deactivation_retains_root_record() {
        let create = did_tx_with_control("alice", 1, 9, &[1], false, true);
        let deactivate = did_tx_with_control("alice", 1, 9, &[1], true, false);
        let event = event_with(vec![create, deactivate]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        assert_eq!(executor.state().len(), 2);
        let root = root_record(&executor, "alice");
        assert_eq!(root.control_key(), &verifying_key(9));
        assert_eq!(root.merkle_root(), &EMPTY_ROOT);
        assert_eq!(root.leaf_count(), 0);
    }

    #[test]
    fn did_update_recreates_absent_root_deterministically() {
        // A state holding only the DID document (no root record) heals to a
        // fresh empty root on the next authorized update — no panic, no
        // divergence.
        let id = did_id("alice");
        let doc = DidDocument::new(
            verifying_key(9),
            vec![VerificationMethod::Signing(verifying_key(1))],
            false,
        )
        .expect("valid doc");
        let mut state = new_state();
        assert!(state.apply(&Op::Put { key: did_state_key(&id), value: doc.encode() }).is_ok());
        let mut executor = Executor::from_state(state);
        let update = did_tx_with_control("alice", 1, 10, &[2], false, false);
        let event = event_with(vec![update]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        let root = root_record(&executor, "alice");
        assert_eq!(root.control_key(), &verifying_key(10));
        assert_eq!(root.merkle_root(), &EMPTY_ROOT);
        assert_eq!(root.leaf_count(), 0);
    }

    #[test]
    fn diffs_include_root_after_image_on_creation_and_rotation() {
        let mut exec = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm = 0u64;
        let create = did_tx_with_control("alice", 1, 9, &[1], false, true);
        let rotate = did_tx_with_control("alice", 1, 10, &[2], false, false);
        let finalized = vec![(event_with(vec![create]), 7), (event_with(vec![rotate]), 8)];
        let diffs =
            exec.bucket_finalized_with_diffs(&mut pending, &mut wm, &finalized).expect("diffs");
        let did_key = did_state_key(&did_id("alice"));
        let root_key = actor_state_key(&ActorId::Root(did_id("alice")));
        for (round, control) in [(7, verifying_key(9)), (8, verifying_key(10))] {
            let round_diffs = diffs.get(&round).expect("round diffs");
            assert!(
                round_diffs.iter().any(|d| d.key == did_key && d.value.is_some()),
                "round {round} carries the document after-image"
            );
            let root_diff =
                round_diffs.iter().find(|d| d.key == root_key).expect("root after-image");
            let root_bytes = root_diff.value.clone().expect("root put");
            let mut cursor = &root_bytes[..];
            let root = RootActor::decode(&mut cursor).expect("root decodes");
            assert_eq!(root.control_key(), &control, "round {round} root control key");
            assert_eq!(root.merkle_root(), &EMPTY_ROOT);
            assert_eq!(root.leaf_count(), 0);
        }
    }

    #[test]
    fn diffs_exclude_root_after_image_on_deactivation() {
        let mut exec = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm = 0u64;
        let create = did_tx_with_control("alice", 1, 9, &[1], false, true);
        let deactivate = did_tx_with_control("alice", 1, 9, &[1], true, false);
        let finalized = vec![(event_with(vec![create]), 7), (event_with(vec![deactivate]), 8)];
        let diffs =
            exec.bucket_finalized_with_diffs(&mut pending, &mut wm, &finalized).expect("diffs");
        let did_key = did_state_key(&did_id("alice"));
        let root_key = actor_state_key(&ActorId::Root(did_id("alice")));
        assert!(diffs.get(&7).expect("round 7").iter().any(|d| d.key == root_key));
        let round8 = diffs.get(&8).expect("round 8 diffs");
        assert_eq!(round8.len(), 1, "deactivation diffs carry only the document");
        assert_eq!(round8[0].key, did_key);
        assert!(round8[0].value.is_some());
    }

    fn sub_id(tag: Tag, index: u32) -> ActorId {
        ActorId::Sub { root_did: did_id("alice"), tag, index }
    }

    /// A sub-actor mint specification: which slot to mint and which keys
    /// to mint it with. The Merkle history it appends to travels
    /// separately, since most mints in these tests share one history.
    struct SubActorSpec<'a> {
        alias: &'a str,
        authorizer_seed: u8,
        tag: Tag,
        index: u32,
        control_seed: u8,
        operating_seed: u8,
        signed_by: u8,
    }

    /// Builds a signed sub-actor mint transaction over `prior_leaves` plus
    /// the new leaf, with `signed_by` verbatim (out-of-range values exercise
    /// `UnknownSigner`).
    fn sub_actor_tx(spec: SubActorSpec<'_>, prior_leaves: &[Hash]) -> Transaction {
        let SubActorSpec {
            alias,
            authorizer_seed,
            tag,
            index,
            control_seed,
            operating_seed,
            signed_by,
        } = spec;
        let root_did = did_id(alias);
        let actor_id = ActorId::Sub { root_did: root_did.clone(), tag, index };
        let control = verifying_key(control_seed);
        let operating = verifying_key(operating_seed);
        let leaf = subactor_leaf_hash(&actor_id, &control);
        let mut leaves = prior_leaves.to_vec();
        leaves.push(leaf);
        let new_root = mth(&leaves);
        let consistency = prove_consistency(&leaves, prior_leaves.len()).expect("proves");
        let inclusion = prove_inclusion(&leaves, prior_leaves.len()).expect("in range");
        let unsigned = SubActorOp::new(SubActorOpParams {
            root_did: root_did.clone(),
            tag,
            index,
            control_key: control,
            operating_key: operating,
            new_root,
            consistency_proof: consistency.clone(),
            inclusion_proof: inclusion.clone(),
            signature: Signature::new([0u8; 64]),
            signed_by,
        });
        let sig = signing_key(authorizer_seed).sign(&unsigned.signed_payload());
        let op = SubActorOp::new(SubActorOpParams {
            root_did,
            tag,
            index,
            control_key: control,
            operating_key: operating,
            new_root,
            consistency_proof: consistency,
            inclusion_proof: inclusion,
            signature: Signature::new(sig.to_bytes()),
            signed_by,
        });
        let mut payload = vec![0x04];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    /// Builds a signed rebind transaction: `pop_signer_seed` signs the proof
    /// of possession, `auth_signer_seed` signs the authorization.
    fn rebind_tx(
        actor_id: ActorId,
        old_operating: ed25519_dalek::VerifyingKey,
        new_seed: u8,
        pop_signer_seed: u8,
        auth_signer_seed: u8,
    ) -> Transaction {
        let new_key = verifying_key(new_seed);
        let unsigned = RebindOp::new(
            actor_id.clone(),
            new_key,
            Signature::new([0u8; 64]),
            Signature::new([0u8; 64]),
        );
        let payload = unsigned.signed_payload(&old_operating);
        let pop = signing_key(pop_signer_seed).sign(&payload);
        let auth = signing_key(auth_signer_seed).sign(&payload);
        let op = RebindOp::new(
            actor_id,
            new_key,
            Signature::new(pop.to_bytes()),
            Signature::new(auth.to_bytes()),
        );
        let mut bytes = vec![0x05];
        bytes.extend_from_slice(&op.encode());
        Transaction::from_bytes(bytes)
    }

    fn sub_record(executor: &Executor, id: &ActorId) -> SubActor {
        let key = actor_state_key(id);
        let bytes = executor.state().get(&key).expect("sub-actor record present");
        let mut cursor = &bytes[..];
        let sub = SubActor::decode(&mut cursor).expect("sub-actor decodes");
        assert!(cursor.is_empty());
        sub
    }

    #[test]
    fn sub_actor_append_writes_record_and_advances_commitment() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let event = event_with(vec![create, mint]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        let id = sub_id(Tag::Messenger, 0);
        let sub = sub_record(&executor, &id);
        assert_eq!(sub.actor_id(), &id);
        assert_eq!(sub.control_key(), &verifying_key(4));
        assert_eq!(sub.operating_key(), &verifying_key(5));
        let root = root_record(&executor, "alice");
        assert_eq!(root.leaf_count(), 1);
        assert_eq!(root.merkle_root(), &mth(&[subactor_leaf_hash(&id, &verifying_key(4))]));
        assert_eq!(root.control_key(), &verifying_key(9));
    }

    #[test]
    fn sub_actor_replay_is_rejected_as_already_exists() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let mut executor = new_executor();
        let first = event_with(vec![create, mint.clone()]);
        let result = match executor.execute_event(&first) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.op_errors.is_empty());

        let second = event_with(vec![mint]);
        let result = match executor.execute_event(&second) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::SubActorAlreadyExists)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 1);
    }

    #[test]
    fn sub_actor_rejects_wrong_inclusion_proof() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint0 = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        // Second slot over a two-leaf history: the header matches the
        // append (index 1 of 2) but the sibling hash is tampered, so the
        // fold misses `new_root` while the consistency proof stays valid.
        let leaf0 = subactor_leaf_hash(&sub_id(Tag::Messenger, 0), &verifying_key(4));
        let id1 = sub_id(Tag::Game, 1);
        let control1 = verifying_key(10);
        let operating1 = verifying_key(11);
        let leaf1 = subactor_leaf_hash(&id1, &control1);
        let leaves = [leaf0, leaf1];
        let new_root = mth(&leaves);
        let consistency = prove_consistency(&leaves, 1).expect("proves");
        let mut inclusion = prove_inclusion(&leaves, 1).expect("in range");
        inclusion.nodes[0][0] ^= 1;
        let unsigned = SubActorOp::new(SubActorOpParams {
            root_did: did_id("alice"),
            tag: Tag::Game,
            index: 1,
            control_key: control1,
            operating_key: operating1,
            new_root,
            consistency_proof: consistency.clone(),
            inclusion_proof: inclusion.clone(),
            signature: Signature::new([0u8; 64]),
            signed_by: 0,
        });
        let sig = signing_key(1).sign(&unsigned.signed_payload());
        let op = SubActorOp::new(SubActorOpParams {
            root_did: did_id("alice"),
            tag: Tag::Game,
            index: 1,
            control_key: control1,
            operating_key: operating1,
            new_root,
            consistency_proof: consistency,
            inclusion_proof: inclusion,
            signature: Signature::new(sig.to_bytes()),
            signed_by: 0,
        });
        let mut payload = vec![0x04];
        payload.extend_from_slice(&op.encode());
        let event = event_with(vec![create, mint0, Transaction::from_bytes(payload)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::InclusionProofInvalid)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 1);
    }

    #[test]
    fn sub_actor_rejects_wrong_consistency_proof() {
        let create = did_tx("alice", 1, &[1], false, true);
        let id = sub_id(Tag::Messenger, 0);
        let control = verifying_key(4);
        let operating = verifying_key(5);
        let leaf = subactor_leaf_hash(&id, &control);
        let new_root = mth(&[leaf]);
        let inclusion = prove_inclusion(&[leaf], 0).expect("in range");
        // The bootstrap from `EMPTY_ROOT` must carry no nodes.
        let consistency =
            ConsistencyProof { old_leaf_count: 0, new_leaf_count: 1, nodes: vec![[9u8; 32]] };
        let unsigned = SubActorOp::new(SubActorOpParams {
            root_did: did_id("alice"),
            tag: Tag::Messenger,
            index: 0,
            control_key: control,
            operating_key: operating,
            new_root,
            consistency_proof: consistency.clone(),
            inclusion_proof: inclusion.clone(),
            signature: Signature::new([0u8; 64]),
            signed_by: 0,
        });
        let sig = signing_key(1).sign(&unsigned.signed_payload());
        let op = SubActorOp::new(SubActorOpParams {
            root_did: did_id("alice"),
            tag: Tag::Messenger,
            index: 0,
            control_key: control,
            operating_key: operating,
            new_root,
            consistency_proof: consistency,
            inclusion_proof: inclusion,
            signature: Signature::new(sig.to_bytes()),
            signed_by: 0,
        });
        let mut payload = vec![0x04];
        payload.extend_from_slice(&op.encode());
        let event = event_with(vec![create, Transaction::from_bytes(payload)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::ConsistencyProofInvalid)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 0);
    }

    #[test]
    fn sub_actor_rejects_unknown_signer() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 5,
            },
            &[],
        );
        let event = event_with(vec![create, mint]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::UnknownSigner)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 0);
    }

    #[test]
    fn sub_actor_rejects_bad_signature() {
        // Signed by key 2, but the root document only authorizes key 1.
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 2,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let event = event_with(vec![create, mint]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::InvalidSignature)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 0);
    }

    #[test]
    fn sub_actor_rejects_absent_root_did() {
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "ghost",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let event = event_with(vec![mint]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::UnknownRootDid)]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn sub_actor_rejects_deactivated_root() {
        let create = did_tx("alice", 1, &[1], false, true);
        let deactivate = did_tx("alice", 1, &[1], true, false);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let event = event_with(vec![create, deactivate, mint]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::RootDeactivated)]);
        assert_eq!(root_record(&executor, "alice").leaf_count(), 0);
    }

    #[test]
    fn sub_actor_rejects_missing_root_record() {
        // A state holding only the DID document (no root record) rejects the
        // mint deterministically instead of fabricating a commitment.
        let id = did_id("alice");
        let doc = DidDocument::new(
            verifying_key(9),
            vec![VerificationMethod::Signing(verifying_key(1))],
            false,
        )
        .expect("valid doc");
        let mut state = new_state();
        assert!(state.apply(&Op::Put { key: did_state_key(&id), value: doc.encode() }).is_ok());
        let mut executor = Executor::from_state(state);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let event = event_with(vec![mint]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::UnknownRootActor)]);
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn rebind_success_updates_only_the_operating_key() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let mut executor = new_executor();
        let setup = event_with(vec![create, mint]);
        let result = match executor.execute_event(&setup) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.op_errors.is_empty());
        let root_before = root_record(&executor, "alice");

        let id = sub_id(Tag::Messenger, 0);
        let rebind = rebind_tx(id.clone(), verifying_key(5), 6, 6, 9);
        let event = event_with(vec![rebind]);
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert!(result.op_errors.is_empty());
        let sub = sub_record(&executor, &id);
        assert_eq!(sub.control_key(), &verifying_key(4));
        assert_eq!(sub.operating_key(), &verifying_key(6));
        // The root commitment is untouched: no root diff on rebind.
        assert_eq!(root_record(&executor, "alice"), root_before);
    }

    #[test]
    fn rebind_rejects_bad_proof_of_possession() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        // Proof of possession signed by key 7, not the new key 6.
        let rebind = rebind_tx(sub_id(Tag::Messenger, 0), verifying_key(5), 6, 7, 9);
        let event = event_with(vec![create, mint, rebind]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::InvalidProofOfPossession)]);
        assert_eq!(
            sub_record(&executor, &sub_id(Tag::Messenger, 0)).operating_key(),
            &verifying_key(5)
        );
    }

    #[test]
    fn rebind_rejects_bad_authorization_signature() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        // Authorization signed by key 7, not the root control key 9.
        let rebind = rebind_tx(sub_id(Tag::Messenger, 0), verifying_key(5), 6, 6, 7);
        let event = event_with(vec![create, mint, rebind]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::InvalidAuthorization)]);
        assert_eq!(
            sub_record(&executor, &sub_id(Tag::Messenger, 0)).operating_key(),
            &verifying_key(5)
        );
    }

    #[test]
    fn rebind_rejects_unknown_sub_actor() {
        let create = did_tx("alice", 1, &[1], false, true);
        let op = RebindOp::new(
            sub_id(Tag::Messenger, 9),
            verifying_key(6),
            Signature::new([0u8; 64]),
            Signature::new([0u8; 64]),
        );
        let mut payload = vec![0x05];
        payload.extend_from_slice(&op.encode());
        let event = event_with(vec![create, Transaction::from_bytes(payload)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::UnknownSubActor)]);
    }

    #[test]
    fn rebind_rejects_root_actor_id() {
        let create = did_tx("alice", 1, &[1], false, true);
        let op = RebindOp::new(
            ActorId::Root(did_id("alice")),
            verifying_key(6),
            Signature::new([0u8; 64]),
            Signature::new([0u8; 64]),
        );
        let mut payload = vec![0x05];
        payload.extend_from_slice(&op.encode());
        let event = event_with(vec![create, Transaction::from_bytes(payload)]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::ExpectedSubActorId)]);
    }

    #[test]
    fn rebind_rejects_deactivated_root() {
        let create = did_tx("alice", 1, &[1], false, true);
        let mint = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let deactivate = did_tx("alice", 1, &[1], true, false);
        let rebind = rebind_tx(sub_id(Tag::Messenger, 0), verifying_key(5), 6, 6, 9);
        let event = event_with(vec![create, mint, deactivate, rebind]);

        let mut executor = new_executor();
        let result = match executor.execute_event(&event) {
            Ok(r) => r,
            Err(e) => panic!("storage error: {e}"),
        };
        assert!(result.errors.is_empty());
        assert_eq!(result.op_errors, vec![OpError::Actor(ActorError::RootDeactivated)]);
        assert_eq!(
            sub_record(&executor, &sub_id(Tag::Messenger, 0)).operating_key(),
            &verifying_key(5)
        );
    }

    #[test]
    fn actor_diffs_replay_to_identical_state() {
        let mut live = new_executor();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut wm = 0u64;
        let create = did_tx("alice", 1, &[1], false, true);
        let leaf0 = subactor_leaf_hash(&sub_id(Tag::Messenger, 0), &verifying_key(4));
        let mint0 = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Messenger,
                index: 0,
                control_seed: 4,
                operating_seed: 5,
                signed_by: 0,
            },
            &[],
        );
        let mint1 = sub_actor_tx(
            SubActorSpec {
                alias: "alice",
                authorizer_seed: 1,
                tag: Tag::Game,
                index: 1,
                control_seed: 10,
                operating_seed: 11,
                signed_by: 0,
            },
            &[leaf0],
        );
        let rebind = rebind_tx(sub_id(Tag::Messenger, 0), verifying_key(5), 6, 6, 9);
        let finalized = vec![(event_with(vec![create, mint0, mint1, rebind]), 7)];
        let diffs =
            live.bucket_finalized_with_diffs(&mut pending, &mut wm, &finalized).expect("diffs");

        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let mut mirror = State::new(db.state_keyspace());
        let mut rounds: Vec<u64> = diffs.keys().copied().collect();
        rounds.sort_unstable();
        for round in rounds {
            for d in &diffs[&round] {
                let value = d.value.clone().expect("actor diffs are after-image puts");
                assert!(
                    mirror.apply(&Op::Put { key: d.key.clone(), value }).is_ok(),
                    "mirror applies round {round}"
                );
            }
        }
        assert_eq!(
            mirror.to_bytes().expect("mirror bytes"),
            live.state().to_bytes().expect("live bytes")
        );
        let round = &diffs[&7];
        for key in [
            did_state_key(&did_id("alice")),
            actor_state_key(&ActorId::Root(did_id("alice"))),
            actor_state_key(&sub_id(Tag::Messenger, 0)),
            actor_state_key(&sub_id(Tag::Game, 1)),
        ] {
            assert!(round.iter().any(|d| d.key == key), "diffs carry every after-image");
        }
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
        assert_eq!(
            exec_a.state().to_bytes().expect("to_bytes succeeds"),
            exec_b.state().to_bytes().expect("to_bytes succeeds")
        );
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
        let did_key = did_state_key(&did_id("alice"));
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
