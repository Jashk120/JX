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
    BlsKeyGenFailed,
    BlsAggregateFailed,
    /// A key-derivation path was empty; at least one hardened index is required.
    EmptyDerivationPath,
    /// A derivation index was already hardened (`>= 0x8000_0000`); callers pass
    /// the non-hardened element and the module hardens it internally.
    InvalidDerivationIndex(u32),
    /// An actor tag code was outside the `0..=3` range.
    InvalidTagCode(u8),
    /// HMAC initialisation failed while deriving a key.
    HmacInitFailed,
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
            Self::BlsKeyGenFailed => write!(f, "bls key generation failed"),
            Self::BlsAggregateFailed => write!(f, "bls aggregate failed"),
            Self::EmptyDerivationPath => write!(f, "empty derivation path"),
            Self::InvalidDerivationIndex(index) => {
                write!(f, "invalid derivation index {index:#010x}")
            }
            Self::InvalidTagCode(tag) => write!(f, "invalid actor tag code {tag}"),
            Self::HmacInitFailed => write!(f, "hmac initialisation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
