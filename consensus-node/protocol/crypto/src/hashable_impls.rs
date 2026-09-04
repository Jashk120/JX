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

    fn hash(&self) -> crate::error::Result<Self::Hash> {
        let bytes = self.canonical_bytes().map_err(crate::error::CryptoError::Base)?;
        let digest = Sha256::digest(&bytes);
        Ok(EventHash::new(digest.into()))
    }
}

impl Hashable for Transaction {
    type Hash = TransactionHash;

    fn hash(&self) -> crate::error::Result<Self::Hash> {
        let bytes = self.canonical_bytes().map_err(crate::error::CryptoError::Base)?;
        let digest = Sha256::digest(&bytes);
        Ok(TransactionHash::new(digest.into()))
    }
}

impl Hashable for MembershipRegistry {
    type Hash = [u8; 32];

    fn hash(&self) -> crate::error::Result<[u8; 32]> {
        Ok(Sha256::digest(self.to_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;

    fn make_event(payload: Vec<Transaction>) -> Event {
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(123), payload)
            .finalize(Signature::default())
    }

    #[test]
    fn event_hash_is_deterministic() {
        let event = make_event(Vec::new());
        let h1 = event.hash().unwrap();
        let h2 = event.hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn event_hash_changes_with_payload() {
        let e1 = make_event(Vec::new());
        let e2 = make_event(vec![Transaction::default()]);
        assert_ne!(e1.hash().unwrap(), e2.hash().unwrap());
    }

    #[test]
    fn single_bit_mutation_in_payload_changes_event_hash() {
        let original = make_event(vec![Transaction::from_bytes(vec![0x00])]);
        let original_hash = original.hash().unwrap();

        let mutated = make_event(vec![Transaction::from_bytes(vec![0x01])]);
        let mutated_hash = mutated.hash().unwrap();

        assert_ne!(original_hash, mutated_hash);
    }

    #[test]
    fn single_bit_mutation_in_signature_changes_event_hash() {
        let unsigned =
            UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(100), Vec::new());
        let sig1 = Signature::new([0x00; 64]);
        let sig2 = Signature::new([0x01; 64]);
        let event1 = unsigned.clone().finalize(sig1);
        let event2 = unsigned.finalize(sig2);
        assert_ne!(event1.hash().unwrap(), event2.hash().unwrap());
    }

    #[test]
    fn single_bit_mutation_in_creator_changes_event_hash() {
        let e1 = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(100), Vec::new())
            .finalize(Signature::default());
        let e2 = UnsignedEvent::new(NodeId::new(2), None, None, Timestamp::new(100), Vec::new())
            .finalize(Signature::default());
        assert_ne!(e1.hash().unwrap(), e2.hash().unwrap());
    }

    #[test]
    fn single_bit_mutation_in_timestamp_changes_event_hash() {
        let e1 = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(100), Vec::new())
            .finalize(Signature::default());
        let e2 = UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(101), Vec::new())
            .finalize(Signature::default());
        assert_ne!(e1.hash().unwrap(), e2.hash().unwrap());
    }

    #[test]
    fn single_bit_mutation_in_parent_hash_changes_event_hash() {
        let parent = EventHash::new([0u8; 32]);
        let e1 =
            UnsignedEvent::new(NodeId::new(1), Some(parent), None, Timestamp::new(100), Vec::new())
                .finalize(Signature::default());

        let mutated_parent = EventHash::new([0x01; 32]);
        let e2 = UnsignedEvent::new(
            NodeId::new(1),
            Some(mutated_parent),
            None,
            Timestamp::new(100),
            Vec::new(),
        )
        .finalize(Signature::default());
        assert_ne!(e1.hash().unwrap(), e2.hash().unwrap());
    }

    #[test]
    fn transaction_hash_is_deterministic() {
        let tx = Transaction::from_bytes(vec![1, 2, 3]);
        let h1 = tx.hash().unwrap();
        let h2 = tx.hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn transaction_hash_changes_with_payload() {
        let tx1 = Transaction::from_bytes(vec![1]);
        let tx2 = Transaction::from_bytes(vec![2]);
        assert_ne!(tx1.hash().unwrap(), tx2.hash().unwrap());
    }

    #[test]
    fn empty_transaction_hash_differs_from_nonempty() {
        let tx_empty = Transaction::default();
        let tx_nonempty = Transaction::from_bytes(vec![0xFF]);
        assert_ne!(tx_empty.hash().unwrap(), tx_nonempty.hash().unwrap());
    }

    #[test]
    fn membership_registry_hash_is_deterministic() {
        let mut reg = MembershipRegistry::new();
        reg.register(
            NodeId::new(1),
            SigningKey::generate(&mut OsRng).verifying_key(),
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );
        let h1 = reg.hash().unwrap();
        let h2 = reg.hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn membership_registry_hash_changes_with_different_members() {
        let mut reg1 = MembershipRegistry::new();
        reg1.register(
            NodeId::new(1),
            SigningKey::generate(&mut OsRng).verifying_key(),
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );

        let mut reg2 = MembershipRegistry::new();
        reg2.register(
            NodeId::new(2),
            SigningKey::generate(&mut OsRng).verifying_key(),
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );

        assert_ne!(reg1.hash().unwrap(), reg2.hash().unwrap());
    }

    #[test]
    fn membership_registry_hash_independent_of_insertion_order() {
        let mut reg1 = MembershipRegistry::new();
        reg1.register(
            NodeId::new(3),
            SigningKey::generate(&mut OsRng).verifying_key(),
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );
        reg1.register(
            NodeId::new(1),
            SigningKey::generate(&mut OsRng).verifying_key(),
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );

        let mut reg2 = MembershipRegistry::new();
        let key1 = reg1.key_for(&NodeId::new(1)).unwrap().to_owned();
        let key3 = reg1.key_for(&NodeId::new(3)).unwrap().to_owned();
        reg2.register(
            NodeId::new(1),
            key1,
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );
        reg2.register(
            NodeId::new(3),
            key3,
            crate::BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
        );

        assert_eq!(reg1.hash().unwrap(), reg2.hash().unwrap());
    }

    #[test]
    fn event_hash_is_32_bytes() {
        let event = make_event(Vec::new());
        let hash = event.hash().unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn transaction_hash_is_32_bytes() {
        let tx = Transaction::from_bytes(vec![42]);
        let hash = tx.hash().unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }
}
