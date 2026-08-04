use std::fmt;

use primitives::NodeId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    Base(primitives::Error),
    SignatureVerificationFailed,
    UnknownSigner { node_id: NodeId },
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
        }
    }
}

impl std::error::Error for CryptoError {}
