use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::canonical::CanonicalEncode;
use crate::membership::MembershipRegistry;

/// A value that can transition from an unsigned to a signed form by
/// producing an Ed25519 signature over its canonical byte encoding.
///
/// Kept separate from `CanonicalEncode` and `Hashable` for the same reason
/// those two are separate from each other: encoding, hashing, and signing
/// are distinct concerns, and this trait only needs to know how to *become*
/// its signed counterpart, not how to hash or verify it.
pub trait Signable: CanonicalEncode {
    type Signed;

    fn sign(self, key: &SigningKey) -> Self::Signed;
}

/// A value that carries its own signature and can check it against a
/// `MembershipRegistry`. This is the mirror image of `Signable`: `Signable`
/// is "unsigned -> signed", `Verifiable` is "signed -> checked".
pub trait Verifiable {
    fn verify(&self, registry: &MembershipRegistry) -> Result<(), VerifyError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("no registered key for this event's creator")]
    UnknownSigner,
    #[error("signature does not match the event contents")]
    InvalidSignature,
}
