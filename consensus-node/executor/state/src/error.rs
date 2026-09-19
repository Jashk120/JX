use std::fmt;

use thiserror::Error;

/// Errors produced while decoding or applying a transaction payload.
///
/// Every variant is a *deterministic* outcome: identical payload bytes decode
/// to the identical error on every node, so malformed payloads can never make
/// two nodes diverge. The executor records these (see `Executor::execute_event`)
/// without aborting the remaining transactions of an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorError {
    /// The transaction payload has zero bytes; an operation needs at least an
    /// opcode.
    EmptyPayload,
    /// The payload ended before its declared fields were fully present.
    Truncated,
    /// The first payload byte is not a recognized opcode.
    UnknownOpcode(u8),
    /// The payload has bytes left over after the last declared field.
    TrailingBytes,
    /// The `0x02` membership-op body did not decode cleanly.
    MalformedMembershipOp,
    /// The `0x03` DID-op body did not decode cleanly.
    MalformedDidOp,
    /// The `0x04` sub-actor-op body did not decode cleanly.
    MalformedSubActorOp,
    /// The `0x05` rebind-op body did not decode cleanly.
    MalformedRebindOp,
    /// DID identifier or document contains invalid bytes (e.g. non-UTF8
    /// network/alias or ':' in segment).
    InvalidDid,
    /// A generic `Put`/`Delete` targeted a reserved state-key prefix (`0xD1`
    /// DID records or `0xA1` actor records). Carries the offending prefix byte.
    ReservedKeyPrefix(u8),
    /// A `DidDocument` carried a version byte other than `0x02`.
    UnsupportedDidDocumentVersion(u8),
    /// A `DidDocument` verification method carried an unknown type tag.
    UnknownVerificationMethodType(u8),
    /// A `DidDocument` contained no Ed25519 signing method.
    NoSigningMethod,
    /// An `ActorId` carried an unknown variant byte (expected `0x00` for a
    /// root actor or `0x01` for a sub-actor).
    UnknownActorIdVariant(u8),
    /// A sub-actor `ActorId` carried an unknown tag code (expected 0..=3).
    UnknownActorTag(u8),
    /// A sub-actor `ActorId` carried an index `>= 0x8000_0000` (only u31
    /// indices are representable on a derivation path).
    ActorIndexOutOfRange(u32),
    /// A `SubActor` record was constructed from a root actor ID.
    ExpectedSubActor,
}

pub type Result<T> = std::result::Result<T, ExecutorError>;

impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "transaction payload is empty"),
            Self::Truncated => write!(f, "transaction payload is truncated"),
            Self::UnknownOpcode(opcode) => write!(f, "unknown transaction opcode {opcode:#04x}"),
            Self::TrailingBytes => write!(f, "transaction payload has trailing bytes"),
            Self::MalformedMembershipOp => write!(f, "malformed membership-op payload"),
            Self::MalformedDidOp => write!(f, "malformed DID-op payload"),
            Self::MalformedSubActorOp => write!(f, "malformed sub-actor-op payload"),
            Self::MalformedRebindOp => write!(f, "malformed rebind-op payload"),
            Self::InvalidDid => write!(f, "DID identifier contains invalid bytes"),
            Self::ReservedKeyPrefix(prefix) => {
                write!(f, "state key uses reserved prefix {prefix:#04x}")
            }
            Self::UnsupportedDidDocumentVersion(version) => {
                write!(f, "unsupported DID document version {version:#04x}")
            }
            Self::UnknownVerificationMethodType(method_type) => {
                write!(f, "unknown verification method type {method_type:#04x}")
            }
            Self::NoSigningMethod => write!(f, "DID document has no signing method"),
            Self::UnknownActorIdVariant(variant) => {
                write!(f, "unknown actor ID variant {variant:#04x}")
            }
            Self::UnknownActorTag(tag) => write!(f, "unknown actor tag {tag:#04x}"),
            Self::ActorIndexOutOfRange(index) => {
                write!(f, "actor index out of range {index:#010x}")
            }
            Self::ExpectedSubActor => write!(f, "expected sub-actor ID, found root actor ID"),
        }
    }
}

impl std::error::Error for ExecutorError {}

/// Errors produced by the Fjall-backed state database (`StateDb`).
#[derive(Debug, Error)]
pub enum StateDbError {
    /// A Fjall storage error (I/O, corrupt journal, etc.).
    #[error("state database I/O error: {0}")]
    Io(#[from] fjall::Error),
    /// Stored watermark has wrong width (corruption).
    #[error("corrupt watermark: expected 8 bytes, got {len} bytes")]
    CorruptWatermark { len: usize },
}

/// Result alias for [`StateDbError`].
pub type StateDbResult<T> = std::result::Result<T, StateDbError>;

/// Semantic errors from applying a DID operation (post-decode).
///
/// Unlike [`ExecutorError`], which is deterministic and tied to the payload
/// bytes, these errors arise from state-dependent signature verification and
/// identifier existence checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidError {
    /// The `signed_by` index is out of range for the authorizing document's
    /// verification methods.
    UnknownSigner,
    /// The Ed25519 signature did not verify against the expected key.
    InvalidSignature,
    /// A creation was attempted, but the identifier already exists in state.
    IdentifierAlreadyExists,
    /// An update or deactivation was attempted, but the identifier does not
    /// exist in state.
    UnknownIdentifier,
    /// The document is already deactivated and cannot be updated or
    /// re-activated.
    AlreadyDeactivated,
}

impl fmt::Display for DidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSigner => write!(f, "signed_by index out of range"),
            Self::InvalidSignature => write!(f, "DID signature verification failed"),
            Self::IdentifierAlreadyExists => write!(f, "DID identifier already exists"),
            Self::UnknownIdentifier => write!(f, "DID identifier not found"),
            Self::AlreadyDeactivated => write!(f, "DID document is already deactivated"),
        }
    }
}

impl std::error::Error for DidError {}

/// Semantic errors from applying a sub-actor or rebind operation
/// (post-decode).
///
/// Like [`DidError`], these arise from state-dependent authorization and
/// membership-proof checks, not from the payload bytes alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActorError {
    /// The `root_did` names no DID document in state (absent or undecodable).
    UnknownRootDid,
    /// The root DID document is deactivated and rejects actor operations.
    RootDeactivated,
    /// The root actor record for the DID is absent or undecodable.
    UnknownRootActor,
    /// The sub-actor state key is already present (replay short-circuit).
    SubActorAlreadyExists,
    /// The sub-actor record is absent or undecodable.
    UnknownSubActor,
    /// A rebind targeted a root actor ID; Phase A rebinds sub-actors only.
    ExpectedSubActorId,
    /// The `signed_by` index is out of range for the root document's
    /// signing methods.
    UnknownSigner,
    /// The Ed25519 signature did not verify against the expected key.
    InvalidSignature,
    /// The inclusion proof does not fold the new leaf to `new_root` at
    /// `leaf_index == old_leaf_count`.
    InclusionProofInvalid,
    /// The consistency proof does not fold `old_root` to `new_root` for a
    /// single-leaf append.
    ConsistencyProofInvalid,
    /// The proof of possession did not verify against the new operating key.
    InvalidProofOfPossession,
    /// The authorization signature did not verify against the root control key.
    InvalidAuthorization,
}

impl fmt::Display for ActorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRootDid => write!(f, "root DID not found"),
            Self::RootDeactivated => write!(f, "root DID is deactivated"),
            Self::UnknownRootActor => write!(f, "root actor record not found"),
            Self::SubActorAlreadyExists => write!(f, "sub-actor already exists"),
            Self::UnknownSubActor => write!(f, "sub-actor not found"),
            Self::ExpectedSubActorId => write!(f, "expected sub-actor ID, found root actor ID"),
            Self::UnknownSigner => write!(f, "signed_by index out of range"),
            Self::InvalidSignature => write!(f, "sub-actor signature verification failed"),
            Self::InclusionProofInvalid => write!(f, "sub-actor inclusion proof invalid"),
            Self::ConsistencyProofInvalid => write!(f, "sub-actor consistency proof invalid"),
            Self::InvalidProofOfPossession => write!(f, "rebind proof of possession invalid"),
            Self::InvalidAuthorization => write!(f, "rebind authorization signature invalid"),
        }
    }
}

impl std::error::Error for ActorError {}

/// The generalized operation-error channel: semantic (post-decode) failures
/// of DID and actor operations, carried distinctly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpError {
    Did(DidError),
    Actor(ActorError),
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Did(e) => write!(f, "DID operation failed: {e}"),
            Self::Actor(e) => write!(f, "actor operation failed: {e}"),
        }
    }
}

impl std::error::Error for OpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Did(e) => Some(e),
            Self::Actor(e) => Some(e),
        }
    }
}
