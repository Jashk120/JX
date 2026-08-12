//! The deterministic executor (Phase 8).
//!
//! Consumes events in finalized consensus order — the order
//! [`Hashgraph::consensus_order`] already produces per round — and folds each
//! transaction's payload into a [`State`] through [`Executor::execute_event`].
//! Execution itself is pure and deterministic: no wall-clock reads, no
//! randomness, no I/O, so the same finalized order and the same starting
//! state yield the same resulting state on every node.

use std::collections::BTreeMap;

use consensus::Hashgraph;
use crypto::MembershipOp;
use primitives::Event;

use crate::error::ExecutorError;
use crate::op::DecodedOp;
use crate::state::State;

/// Applies transactions to a [`State`] in the order they are presented.
///
/// An [`Executor`] never invents an ordering: it only processes the sequence
/// it is given, so the caller (e.g. [`finalized_events`]) owns the consensus
/// ordering and this type owns the deterministic application.
#[derive(Clone, Debug, Default)]
pub struct Executor {
    state: State,
}

impl Executor {
    pub fn new() -> Self {
        Self::default()
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
    /// `State`: they are collected and returned as a side channel. On decode
    /// error the state is left unchanged for that payload — the operation is
    /// not applied — and the deterministic error is collected, without
    /// aborting the remaining transactions of the event.
    pub fn execute_event(&mut self, event: &Event) -> (Vec<ExecutorError>, Vec<MembershipOp>) {
        let mut errors = Vec::new();
        let mut membership_ops = Vec::new();

        for tx in event.payload() {
            match DecodedOp::decode(tx.payload()) {
                Ok(DecodedOp::Kv(op)) => self.state.apply(&op),
                Ok(DecodedOp::Membership(mem_op)) => membership_ops.push(mem_op),
                Err(e) => errors.push(e),
            }
        }

        (errors, membership_ops)
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
            let (_errors, mem_ops) = self.execute_event(event);
            if !mem_ops.is_empty() {
                pending.entry(*round_received).or_default().extend(mem_ops);
            }
        }
        *processed_through_round = new_max;
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
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };

    use super::*;
    use crate::op::Op;

    fn event_with(payload: Vec<Transaction>) -> Event {
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), payload)
            .finalize(Signature::default())
    }

    fn membership_tx() -> Transaction {
        let op = MembershipOp::Add {
            node: NodeId::new(7),
            key: Box::new(SigningKey::from_bytes(&[1u8; 32]).verifying_key()),
            addr: "127.0.0.1:7000".parse().expect("valid addr"),
        };
        let mut payload = vec![0x02];
        payload.extend_from_slice(&op.encode());
        Transaction::from_bytes(payload)
    }

    #[test]
    fn execute_event_applies_all_valid_transactions() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put)]);

        let mut executor = Executor::new();
        let (errors, membership_ops) = executor.execute_event(&event);

        assert!(errors.is_empty());
        assert!(membership_ops.is_empty());
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));
    }

    #[test]
    fn from_state_restores_exactly_the_given_state() {
        let mut state = State::new();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        let executor = Executor::from_state(state.clone());
        assert_eq!(executor.state(), &state);
        assert_eq!(executor.into_state(), state);
    }

    #[test]
    fn execute_event_collects_malformed_payload_errors() {
        let malformed = vec![0x7f];
        let event = event_with(vec![Transaction::from_bytes(malformed)]);

        let mut executor = Executor::new();
        let (errors, _membership_ops) = executor.execute_event(&event);

        assert_eq!(errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert!(executor.state().is_empty());
    }

    #[test]
    fn execute_event_skips_malformed_and_applies_the_rest() {
        let malformed = vec![0x7f];
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event =
            event_with(vec![Transaction::from_bytes(malformed), Transaction::from_bytes(put)]);

        let mut executor = Executor::new();
        let (errors, _membership_ops) = executor.execute_event(&event);

        assert_eq!(errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));
    }

    #[test]
    fn execute_event_separates_membership_op_into_side_channel() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put), membership_tx()]);

        let mut executor = Executor::new();
        let (errors, membership_ops) = executor.execute_event(&event);

        assert!(errors.is_empty());
        assert_eq!(membership_ops.len(), 1);
        // The membership op never touches State.
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));
        assert_eq!(executor.state().len(), 1);
    }

    #[test]
    fn bucket_finalized_is_idempotent() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let finalized = vec![
            (event_with(vec![Transaction::from_bytes(put)]), 1),
            (event_with(vec![membership_tx()]), 2),
        ];

        let mut executor = Executor::new();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut processed_through_round = 0u64;

        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));

        // The same batch again must not re-bucket or re-apply anything.
        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert_eq!(processed_through_round, 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.get(&2).map(Vec::len), Some(1));
    }

    #[test]
    fn bucket_finalized_skips_rounds_below_the_watermark() {
        let finalized = vec![(event_with(vec![membership_tx()]), 3)];
        let mut executor = Executor::new();
        let mut pending: BTreeMap<u64, Vec<MembershipOp>> = BTreeMap::new();
        let mut processed_through_round = 5u64;

        executor.bucket_finalized(&mut pending, &mut processed_through_round, &finalized);
        assert!(pending.is_empty());
        assert_eq!(processed_through_round, 5);
    }
}
