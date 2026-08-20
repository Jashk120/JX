use std::fmt;

use primitives::EventHash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    AlreadyPresent(EventHash),
    MissingParent(EventHash),
    UnknownCreator,
    UnknownEvent(EventHash),
    AncestorSeqsMismatch { expected: usize, got: usize },
}

pub type Result<T> = std::result::Result<T, ConsensusError>;

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPresent(hash) => {
                write!(f, "event {hash:?} is already present in the hashgraph")
            }
            Self::MissingParent(hash) => {
                write!(f, "parent {hash:?} is not present in the hashgraph")
            }
            Self::UnknownCreator => write!(f, "event creator is not a registered member"),
            Self::UnknownEvent(hash) => write!(f, "event {hash:?} is not present in the hashgraph"),
            Self::AncestorSeqsMismatch { expected, got } => {
                write!(f, "ancestor_seqs length {got} does not match member count {expected}")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}
