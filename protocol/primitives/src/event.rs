use crate::event_hash::EventHash;
use crate::node::NodeId;
use crate::signature::Signature;
use crate::timestamp::Timestamp;
use crate::transaction::Transaction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedEvent {
    creator: NodeId,
    self_parent: Option<EventHash>,
    other_parent: Option<EventHash>,
    timestamp: Timestamp,
    payload: Vec<Transaction>,
}

impl UnsignedEvent {
    pub fn new(
        creator: NodeId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
        timestamp: Timestamp,
        payload: Vec<Transaction>,
    ) -> Self {
        Self { creator, self_parent, other_parent, timestamp, payload }
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

    pub fn finalize(self, signature: Signature) -> Event {
        Event { unsigned: self, signature }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    unsigned: UnsignedEvent,
    signature: Signature,
}

impl Event {
    pub fn unsigned(&self) -> &UnsignedEvent {
        &self.unsigned
    }

    pub fn creator(&self) -> &NodeId {
        self.unsigned.creator()
    }

    pub fn self_parent(&self) -> Option<&EventHash> {
        self.unsigned.self_parent()
    }

    pub fn other_parent(&self) -> Option<&EventHash> {
        self.unsigned.other_parent()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.unsigned.timestamp()
    }

    pub fn payload(&self) -> &[Transaction] {
        self.unsigned.payload()
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
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
        UnsignedEvent::new(NodeId::new(1), self_parent, other_parent, Timestamp::new(123), payload)
            .finalize(Signature::default())
    }

    #[test]
    fn new_event_stores_all_fields() {
        let creator = NodeId::new(42);
        let timestamp = 12345;
        let signature = Signature::default();

        let event = UnsignedEvent::new(creator, None, None, Timestamp::new(timestamp), Vec::new())
            .finalize(signature.clone());

        assert_eq!(event.creator(), &creator);
        assert_eq!(event.self_parent(), None);
        assert_eq!(event.other_parent(), None);
        assert_eq!(event.timestamp(), Timestamp::new(timestamp));
        assert!(event.payload().is_empty());
        assert_eq!(event.signature(), &signature);
    }

    #[test]
    fn event_preserves_parent_hashes() {
        let self_parent = EventHash::new([1; 32]);
        let other_parent = EventHash::new([2; 32]);

        let event = make_event(Some(self_parent), Some(other_parent), Vec::new());

        assert_eq!(event.self_parent(), Some(&self_parent));
        assert_eq!(event.other_parent(), Some(&other_parent));
    }

    #[test]
    fn payload_returns_all_transactions() {
        let tx1 = Transaction::default();
        let tx2 = Transaction::default();

        let event = make_event(None, None, vec![tx1.clone(), tx2.clone()]);

        assert_eq!(event.payload().len(), 2);
        assert_eq!(event.payload()[0], tx1);
        assert_eq!(event.payload()[1], tx2);
    }
}
