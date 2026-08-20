use primitives::{
    Event,
    EventHash,
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};

use crate::canonical::CanonicalEncode;

impl CanonicalEncode for NodeId {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.get().to_be_bytes());
    }
}

impl CanonicalEncode for Timestamp {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.get().to_be_bytes());
    }
}

impl CanonicalEncode for Signature {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl CanonicalEncode for EventHash {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl CanonicalEncode for Option<EventHash> {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        match self {
            None => buf.push(0x00),
            Some(hash) => {
                buf.push(0x01);
                hash.encode_canonical(buf);
            }
        }
    }
}

impl CanonicalEncode for Transaction {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        let payload = self.payload();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
    }
}

impl CanonicalEncode for Vec<Transaction> {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for tx in self {
            tx.encode_canonical(buf);
        }
    }
}

impl CanonicalEncode for UnsignedEvent {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        self.creator().encode_canonical(buf);
        self.self_parent().cloned().encode_canonical(buf);
        self.other_parent().cloned().encode_canonical(buf);
        self.timestamp().encode_canonical(buf);
        self.payload().to_vec().encode_canonical(buf);
    }
}

impl CanonicalEncode for Event {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        self.unsigned().encode_canonical(buf);
        self.signature().encode_canonical(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_canonical_encoding_combines_unsigned_and_signature() {
        let unsigned =
            UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(100), Vec::new());
        let signature = Signature::default();
        let event = unsigned.clone().finalize(signature.clone());

        let unsigned_bytes = unsigned.canonical_bytes();
        let signature_bytes = signature.canonical_bytes();
        let event_bytes = event.canonical_bytes();

        let mut expected = Vec::new();
        expected.extend_from_slice(&unsigned_bytes);
        expected.extend_from_slice(&signature_bytes);

        assert_eq!(event_bytes, expected);
    }

    #[test]
    fn empty_transaction_vec_encodes_zero_count() {
        let txs: Vec<Transaction> = Vec::new();
        let bytes = txs.canonical_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), 0);
    }

    #[test]
    fn single_transaction_encoding() {
        let tx = Transaction::from_bytes(vec![0xAA, 0xBB, 0xCC]);
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes.len(), 7);
        assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()), 3);
        assert_eq!(&bytes[4..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn transaction_vec_canonical_order_is_insertion_order() {
        let tx_a = Transaction::from_bytes(vec![1]);
        let tx_b = Transaction::from_bytes(vec![2]);
        let txs1 = vec![tx_a.clone(), tx_b.clone()];
        let txs2 = vec![tx_b, tx_a];
        let bytes1 = txs1.canonical_bytes();
        let bytes2 = txs2.canonical_bytes();
        assert_ne!(bytes1, bytes2, "different tx orderings should produce different bytes");
    }

    #[test]
    fn option_event_hash_none_vs_some_produce_different_bytes() {
        let none: Option<EventHash> = None;
        let some = Some(EventHash::new([0u8; 32]));
        assert_ne!(none.canonical_bytes(), some.canonical_bytes());
        assert_eq!(none.canonical_bytes(), vec![0x00]);
        assert_eq!(some.canonical_bytes()[0], 0x01);
    }

    #[test]
    fn option_event_hash_some_preserves_hash_bytes() {
        let hash = EventHash::new([0xAB; 32]);
        let some = Some(hash);
        let bytes = some.canonical_bytes();
        assert_eq!(bytes.len(), 33);
        assert_eq!(&bytes[1..], hash.as_bytes());
    }

    #[test]
    fn node_id_max_value_encodes_correctly() {
        let node = NodeId::new(u64::MAX);
        let bytes = node.canonical_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), u64::MAX);
    }

    #[test]
    fn timestamp_max_value_encodes_correctly() {
        let ts = Timestamp::new(u64::MAX);
        let bytes = ts.canonical_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), u64::MAX);
    }

    #[test]
    fn two_events_same_fields_different_signature_produce_different_bytes() {
        let unsigned =
            UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(100), Vec::new());
        let sig1 = Signature::new([0x00; 64]);
        let sig2 = Signature::new([0xFF; 64]);
        let event1 = unsigned.clone().finalize(sig1);
        let event2 = unsigned.finalize(sig2);
        assert_ne!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn unsigned_event_parent_order_matters() {
        let hash_a = EventHash::new([1u8; 32]);
        let hash_b = EventHash::new([2u8; 32]);
        let e1 = UnsignedEvent::new(
            NodeId::new(1),
            Some(hash_a),
            Some(hash_b),
            Timestamp::new(100),
            Vec::new(),
        );
        let e2 = UnsignedEvent::new(
            NodeId::new(1),
            Some(hash_b),
            Some(hash_a),
            Timestamp::new(100),
            Vec::new(),
        );
        assert_ne!(e1.canonical_bytes(), e2.canonical_bytes());
    }

    #[test]
    fn empty_payload_is_empty_transaction_vec() {
        let event = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(0), Vec::new())
            .finalize(Signature::default());
        let bytes = event.canonical_bytes();
        let unsigned_bytes = event.unsigned().canonical_bytes();
        let sig_bytes = event.signature().canonical_bytes();
        assert_eq!(bytes.len(), unsigned_bytes.len() + sig_bytes.len());
    }
}
