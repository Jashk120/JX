use crate::node::NodeId;
use crate::types::{Signature, Timestamp};
use crate::transaction::Transaction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    creator: NodeId,
    self_parent: Option<EventHash>,
    other_parent: Option<EventHash>,
    timestamp: Timestamp,
    payload: Vec<Transaction>,
    signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventHash([u8; 32]);

impl Event {
    pub fn new(
        creator: NodeId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        timestamp: Timestamp,
        payload: Vec<Transaction>,
        signature: Signature,
    ) -> Self {
        Self {
            creator,
            self_parent,
            other_parent,
            timestamp,
            payload,
            signature,
        }
    }
    pub fn creator(&self) -> &NodeId {
        &self.creator
    }

    pub fn self_parent(&self) -> Option<&EventHash> {
        self.self_parent.as_ref()
    }

    pub fn other_parent(&self) -> Option<&EventHash> {
        self.other_parent.as_ref()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn payload(&self) -> &[Transaction] {
        &self.payload
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

}
impl EventHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        payload: Vec<Transaction>,
    ) -> Event {
        Event::new(
            NodeId::new(1),
            self_parent,
            other_parent,
            123,
            payload,
            Signature::default(),
        )
    }

    #[test]
    fn new_event_stores_all_fields() {
        let creator = NodeId::new(42);
        let timestamp = 12345;
        let signature = Signature::default();

        let event = Event::new(
            creator,
            None,
            None,
            timestamp,
            Vec::new(),
            signature.clone(),
        );

        assert_eq!(event.creator(), &creator);
        assert_eq!(event.self_parent(), None);
        assert_eq!(event.other_parent(), None);
        assert_eq!(event.timestamp(), timestamp);
        assert!(event.payload().is_empty());
        assert_eq!(event.signature(), &signature);
    }

    #[test]
    fn event_preserves_parent_hashes() {
        let self_parent = EventHash::new([1; 32]);
        let other_parent = EventHash::new([2; 32]);

        let event = make_event(
            Some(self_parent.clone()),
            Some(other_parent.clone()),
            Vec::new(),
        );

        assert_eq!(event.self_parent(), Some(&self_parent));
        assert_eq!(event.other_parent(), Some(&other_parent));
    }

    #[test]
    fn payload_returns_all_transactions() {
        let tx1 = Transaction::default();
        let tx2 = Transaction::default();

        let event = make_event(
            None,
            None,
            vec![tx1.clone(), tx2.clone()],
        );

        assert_eq!(event.payload().len(), 2);
        assert_eq!(event.payload()[0], tx1);
        assert_eq!(event.payload()[1], tx2);
    }
}