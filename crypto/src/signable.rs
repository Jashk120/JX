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
/// is "unsigned -> signed", `Verifiable` is "signed -> verified".
///
/// Consumes `self` by value and, on success, hands back a `VerifiedEvent` —
/// the compiler-enforced proof that verification actually happened. There is
/// no public way to construct a `VerifiedEvent` other than through this
/// method, so a function that requires one (e.g. `Hashgraph::insert`, once
/// it exists) cannot be called with an event that was never checked.
pub trait Verifiable: Sized {
    fn verify(self, registry: &MembershipRegistry) -> Result<VerifiedEvent, VerifyError>;
}

/// An `Event` whose signature has been checked against a `MembershipRegistry`.
///
/// Deliberately holds an owned `Event`, not a borrow of the registry used to
/// check it — a `VerifiedEvent` needs to be storable in a `Hashgraph` for the
/// long term (Phase 3), and tying its lifetime to the registry that verified
/// it would fight the borrow checker the moment the registry needs to change
/// (membership updates) while old verified events are still held elsewhere.
///
/// `new` is crate-private: the only way to obtain a `VerifiedEvent` from
/// outside this crate is `Event::verify(registry)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvent(primitives::Event);

impl VerifiedEvent {
    pub(crate) fn new(event: primitives::Event) -> Self {
        Self(event)
    }

    pub fn into_inner(self) -> primitives::Event {
        self.0
    }

    pub fn event(&self) -> &primitives::Event {
        &self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("no registered key for this event's creator")]
    UnknownSigner,
    #[error("signature does not match the event contents")]
    InvalidSignature,
}
