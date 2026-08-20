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
