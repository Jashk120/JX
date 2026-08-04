use ed25519_dalek::{
    Signature as DalekSignature,
    Signer,
    Verifier,
};
use primitives::{
    Event,
    Signature,
    UnsignedEvent,
};

use crate::canonical::CanonicalEncode;
use crate::membership::MembershipRegistry;
use crate::signable::{
    Signable,
    Verifiable,
    VerifiedEvent,
};
use crate::error::{CryptoError, Result};

impl Signable for UnsignedEvent {
    type Signed = Event;

    fn sign(self, key: &ed25519_dalek::SigningKey) -> Event {
        let bytes = self.canonical_bytes();
        let signature = key.sign(&bytes);
        self.finalize(Signature::new(signature.to_bytes()))
    }
}

impl Verifiable for Event {
    fn verify(self, registry: &MembershipRegistry) -> Result<VerifiedEvent> {
        let verifying_key = registry.key_for(self.creator())?;

        let signature = DalekSignature::from_bytes(self.signature().as_bytes());
        let bytes = self.unsigned().canonical_bytes();

        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        Ok(VerifiedEvent::new(self))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Timestamp,
    };
    use rand::rngs::OsRng;

    use super::*;

    fn registry_with(node: NodeId, key: &SigningKey) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        registry.register(node, key.verifying_key());
        registry
    }

    #[test]
    fn signed_event_verifies_against_registered_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_with(node, &signing_key);

        let event = UnsignedEvent::new(node, None, None, Timestamp::new(100), Vec::new())
            .sign(&signing_key);
        let expected = event.clone();

        let verified = event.verify(&registry).expect("signature should verify");

        assert_eq!(verified.event(), &expected);
        assert_eq!(verified.into_inner(), expected);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_with(node, &signing_key);

        let event = UnsignedEvent::new(node, None, None, Timestamp::new(100), Vec::new())
            .sign(&signing_key);

        // Re-sign correctly, then re-derive an event with a different timestamp
        // but the *original* signature, simulating tampering after signing.
        let tampered = UnsignedEvent::new(node, None, None, Timestamp::new(999), Vec::new())
            .finalize(event.signature().clone());

        assert_eq!(
            tampered.verify(&registry),
            Err(CryptoError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn unknown_signer_is_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let empty_registry = MembershipRegistry::new();

        let event = UnsignedEvent::new(node, None, None, Timestamp::new(100), Vec::new())
            .sign(&signing_key);

        assert_eq!(
            event.verify(&empty_registry),
            Err(CryptoError::UnknownSigner { node_id: node })
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let node = NodeId::new(1);
        let registry = registry_with(node, &wrong_key);

        let event = UnsignedEvent::new(node, None, None, Timestamp::new(100), Vec::new())
            .sign(&signing_key);

        assert_eq!(
            event.verify(&registry),
            Err(CryptoError::SignatureVerificationFailed)
        );
    }
}
