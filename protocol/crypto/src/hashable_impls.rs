use primitives::{
    Event,
    EventHash,
    Transaction,
    TransactionHash,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::canonical::CanonicalEncode;
use crate::hash::Hashable;
use crate::membership::MembershipRegistry;

impl Hashable for Event {
    type Hash = EventHash;

    fn hash(&self) -> Self::Hash {
        let bytes = self.canonical_bytes();
        let digest = Sha256::digest(&bytes);
        EventHash::new(digest.into())
    }
}

// Transaction hashing isn't in the spec's Event.hash definition, but you'll
// want it eventually (replay checks, references) — same pattern:
impl Hashable for Transaction {
    type Hash = TransactionHash;

    fn hash(&self) -> Self::Hash {
        let bytes = self.canonical_bytes();
        let digest = Sha256::digest(&bytes);
        TransactionHash::new(digest.into())
    }
}

/// SHA-256 of [`MembershipRegistry::to_bytes`] — the canonical roster hash
/// a checkpoint payload commits to (Phase 3). Deterministic across nodes for
/// the same roster, so every node derives the identical `roster_hash`.
impl Hashable for MembershipRegistry {
    type Hash = [u8; 32];

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };

    use super::*;

    fn make_event(payload: Vec<Transaction>) -> Event {
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(123), payload)
            .finalize(Signature::default())
    }

    #[test]
    fn event_hash_is_deterministic() {
        let event = make_event(Vec::new());
        let h1 = event.hash();
        let h2 = event.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn event_hash_changes_with_payload() {
        let e1 = make_event(Vec::new());
        let e2 = make_event(vec![Transaction::default()]);
        assert_ne!(e1.hash(), e2.hash());
    }
}
