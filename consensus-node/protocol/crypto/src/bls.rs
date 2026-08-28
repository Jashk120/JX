use blst::BLST_ERROR;
use blst::min_pk::{
    PublicKey,
    SecretKey,
    Signature,
};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::error::{
    CryptoError,
    Result,
};

pub const CHECKPOINT_DST: &[u8] = b"JKAIN-CHECKPOINT-BLS-V1";
pub const POP_DST: &[u8] = b"JKAIN-BLS-POP-V1";

pub struct BlsIdentity {
    secret: SecretKey,
    pub public: PublicKey,
}

impl BlsIdentity {
    pub fn from_ikm(ikm: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::key_gen(ikm, &[]).map_err(|_| CryptoError::BlsKeyGenFailed)?;
        let public = secret.sk_to_pk();
        Ok(Self { secret, public })
    }

    pub fn generate() -> Result<Self> {
        let mut ikm = [0u8; 32];
        OsRng.fill_bytes(&mut ikm);
        Self::from_ikm(&ikm)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.secret.sign(msg, CHECKPOINT_DST, &[])
    }
}

pub fn aggregate(sigs: &[&Signature]) -> Result<Signature> {
    let agg = blst::min_pk::AggregateSignature::aggregate(sigs, false)
        .map_err(|_| CryptoError::BlsAggregateFailed)?;
    Ok(agg.to_signature())
}

pub fn verify_aggregate(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> bool {
    sig.fast_aggregate_verify(true, msg, CHECKPOINT_DST, pks) == BLST_ERROR::BLST_SUCCESS
}

fn pop_message(pk: &PublicKey) -> Vec<u8> {
    let pk_bytes = pk.to_bytes();
    let mut msg = Vec::with_capacity(POP_DST.len() + pk_bytes.len());
    msg.extend_from_slice(POP_DST);
    msg.extend_from_slice(&pk_bytes);
    msg
}

pub fn sign_pop(id: &BlsIdentity) -> Signature {
    let msg = pop_message(&id.public);
    id.secret.sign(&msg, POP_DST, &[])
}

pub fn verify_pop(pk: &PublicKey, pop: &Signature) -> bool {
    let msg = pop_message(pk);
    pop.verify(true, &msg, POP_DST, &[], pk, true) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_from_byte(fill: u8) -> BlsIdentity {
        let ikm = [fill; 32];
        BlsIdentity::from_ikm(&ikm).expect("key gen from deterministic ikm")
    }

    #[test]
    fn ikm_determinism_same_ikm_yields_same_public_key() {
        let ikm = [42u8; 32];
        let id1 = BlsIdentity::from_ikm(&ikm).expect("key gen");
        let id2 = BlsIdentity::from_ikm(&ikm).expect("key gen");
        assert_eq!(id1.public.to_bytes(), id2.public.to_bytes());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = identity_from_byte(1);
        let msg = b"hello checkpoint";
        let sig = id.sign(msg);
        let ok = sig.verify(true, msg, CHECKPOINT_DST, &[], &id.public, true)
            == BLST_ERROR::BLST_SUCCESS;
        assert!(ok, "single signature should verify");

        let ok_agg = verify_aggregate(&sig, msg, &[&id.public]);
        assert!(ok_agg, "verify_aggregate with single key should succeed");
    }

    #[test]
    fn aggregate_of_three_verifies_against_three_pubkeys() {
        let ids = [identity_from_byte(10), identity_from_byte(20), identity_from_byte(30)];
        let msg = b"checkpoint round 7";
        let sigs: Vec<Signature> = ids.iter().map(|id| id.sign(msg)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate(&sig_refs).expect("aggregate");

        let pks: Vec<&PublicKey> = ids.iter().map(|id| &id.public).collect();
        assert!(verify_aggregate(&agg, msg, &pks));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let id = identity_from_byte(5);
        let msg = b"original message";
        let sig = id.sign(msg);

        let tampered = b"tampered message";
        let ok = verify_aggregate(&sig, tampered, &[&id.public]);
        assert!(!ok, "tampered message must fail");

        // aggregate tampered case
        let ids = [identity_from_byte(11), identity_from_byte(12), identity_from_byte(13)];
        let msg2 = b"round 99 payload";
        let sigs: Vec<Signature> = ids.iter().map(|id| id.sign(msg2)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate(&sig_refs).expect("aggregate");
        let pks: Vec<&PublicKey> = ids.iter().map(|id| &id.public).collect();
        assert!(!verify_aggregate(&agg, b"round 99 payloaX", &pks));
    }

    #[test]
    fn wrong_dst_signature_fails_verification() {
        let id = identity_from_byte(7);
        let msg = b"dst domain test";
        // sign with a different DST manually
        let wrong_sig = id.secret.sign(msg, b"WRONG-DST", &[]);
        let ok = verify_aggregate(&wrong_sig, msg, &[&id.public]);
        assert!(!ok, "signature created with wrong DST must not verify under CHECKPOINT_DST");
    }

    #[test]
    fn pop_roundtrip_passes() {
        let id = identity_from_byte(9);
        let pop = sign_pop(&id);
        assert!(verify_pop(&id.public, &pop));
    }

    #[test]
    fn wrong_key_pop_fails() {
        let id = identity_from_byte(15);
        let other = identity_from_byte(16);
        let pop = sign_pop(&id);
        assert!(
            !verify_pop(&other.public, &pop),
            "pop signed by id must not verify under different key"
        );
    }

    #[test]
    fn aggregate_empty_fails() {
        let err = aggregate(&[]);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), CryptoError::BlsAggregateFailed);
    }

    #[test]
    fn generate_produces_valid_identity() {
        let id = BlsIdentity::generate().expect("generate");
        let msg = b"gen test";
        let sig = id.sign(msg);
        assert!(verify_aggregate(&sig, msg, &[&id.public]));
    }
}
