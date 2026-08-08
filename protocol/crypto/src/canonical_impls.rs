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
}
