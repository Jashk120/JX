use std::fmt;

use primitives::NodeId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    Base(primitives::Error),
    SignatureVerificationFailed,
    UnknownSigner {
        node_id: NodeId,
    },
    /// A membership operation payload was truncated or had an invalid field.
    MalformedOp,
    /// The first payload byte is not a recognized membership opcode.
    UnknownMembershipOpcode(u8),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<primitives::Error> for CryptoError {
    fn from(error: primitives::Error) -> Self {
        Self::Base(error)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(error) => write!(f, "primitives error: {error}"),
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::UnknownSigner { node_id } => write!(f, "no registered key for node {node_id:?}"),
            Self::MalformedOp => write!(f, "malformed membership operation"),
            Self::UnknownMembershipOpcode(opcode) => {
                write!(f, "unknown membership opcode {opcode:#04x}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
