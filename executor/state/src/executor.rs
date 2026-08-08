//! The deterministic executor (Phase 8).
//!
//! Consumes events in finalized consensus order — the order
//! [`Hashgraph::consensus_order`] already produces per round — and folds each
//! transaction's payload into a [`State`] through [`Executor::execute_event`].
//! Execution itself is pure and deterministic: no wall-clock reads, no
//! randomness, no I/O, so the same finalized order and the same starting
//! state yield the same resulting state on every node.

use consensus::Hashgraph;
use primitives::{
    Event,
    Transaction,
};

use crate::error::ExecutorError;
use crate::op::Op;
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

    /// The state accumulated by the transactions applied so far.
    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn into_state(self) -> State {
        self.state
    }

    /// Decodes and applies one transaction.
    ///
    /// On error the state is left unchanged — the operation is not applied —
    /// and the error is deterministic for the given payload bytes.
    pub fn execute_transaction(&mut self, tx: &Transaction) -> Result<(), ExecutorError> {
        let op = Op::decode(tx.payload())?;
        self.state.apply(&op);
        Ok(())
    }

    /// Applies every transaction in `event`, in payload order, collecting the
    /// deterministic error for each malformed payload. Valid transactions are
    /// always applied, so the resulting state is fully determined by the
    /// event order regardless of how many payloads are malformed.
    pub fn execute_event(&mut self, event: &Event) -> Vec<ExecutorError> {
        event.payload().iter().filter_map(|tx| self.execute_transaction(tx).err()).collect()
    }
}

/// Collects every finalized event in the hashgraph's consensus order, ready
/// to feed to [`Executor::execute_event`].
///
/// Rounds are visited in increasing order, and within a round the events come
/// from [`Hashgraph::consensus_order`] unchanged — that function sorts by
/// `roundReceived`, then `consensusTimestamp`, then the signature-derived
/// tie-break. The executor therefore reuses the exact ordering `order.rs`
/// already produces instead of defining its own.
///
/// Rounds with no recorded witnesses (nothing beyond the highest reached
/// round) end the walk; rounds that were decided but assigned zero events
/// simply contribute nothing.
pub fn finalized_events(hashgraph: &Hashgraph) -> Vec<Event> {
    (1..)
        .take_while(|&round| !hashgraph.witnesses_of_round(round).is_empty())
        .flat_map(|round| hashgraph.consensus_order(round))
        .filter_map(|hash| hashgraph.get(&hash).map(|record| record.event().clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        UnsignedEvent,
    };

    use super::*;

    fn event_with(payload: Vec<Transaction>) -> Event {
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), payload)
            .finalize(Signature::default())
    }

    #[test]
    fn execute_event_applies_all_valid_transactions() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let event = event_with(vec![Transaction::from_bytes(put)]);

        let mut executor = Executor::new();
        let errors = executor.execute_event(&event);

        assert!(errors.is_empty());
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));
    }

    #[test]
    fn execute_event_collects_malformed_payload_errors() {
        let malformed = vec![0x7f];
        let event = event_with(vec![Transaction::from_bytes(malformed)]);

        let mut executor = Executor::new();
        let errors = executor.execute_event(&event);

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
        let errors = executor.execute_event(&event);

        assert_eq!(errors, vec![ExecutorError::UnknownOpcode(0x7f)]);
        assert_eq!(executor.state().get(b"k"), Some(&b"v"[..]));
    }
}
