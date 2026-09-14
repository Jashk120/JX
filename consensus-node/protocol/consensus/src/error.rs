use std::fmt;

use primitives::EventHash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    AlreadyPresent(EventHash),
    MissingParent(EventHash),
    UnknownCreator,
    UnknownEvent(EventHash),
    AncestorSeqsMismatch {
        expected: usize,
        got: usize,
    },
    EncodingFailed(String),
    InvalidSelfParent,
    /// A reconnect-retained record's `seq` disagrees with the creator chain
    /// the learner already holds: `expected` is `self_parent.seq + 1` when the
    /// self-parent is present, or `1` for a parentless (genesis) event.
    InvalidRetainedSeq {
        expected: u64,
        got: u64,
    },
    /// A reconnect-retained record's `ancestor_seqs` row disagrees with the
    /// elementwise-max recomputation over the parents present in the same
    /// transfer.
    InvalidRetainedAncestors,
    /// A reconnect-retained record's birth `round` is below the `base_round`
    /// of the parents present in the same transfer (`base`).
    InvalidRetainedRound {
        base: u64,
        got: u64,
    },
    /// A reconnect-retained record's ordering metadata is inconsistent: a
    /// `consensus_timestamp` without (or missing with) a `round_received`, a
    /// `round_received` below the birth round, or one past the teacher's
    /// decided watermark.
    InvalidRetainedOrder,
    /// `mark_decided_through` was asked to decide past the highest birth
    /// round the graph actually stores — a peer-supplied watermark the
    /// retained graph does not support.
    DecidedRoundBeyondRetained {
        decided: u64,
        max_retained: u64,
    },
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
            Self::EncodingFailed(reason) => write!(f, "encoding failed: {reason}"),
            Self::InvalidSelfParent => {
                write!(f, "self_parent creator does not match event creator")
            }
            Self::InvalidRetainedSeq { expected, got } => {
                write!(
                    f,
                    "retained seq {got} does not match the creator chain (expected {expected})"
                )
            }
            Self::InvalidRetainedAncestors => {
                write!(f, "retained ancestor_seqs disagree with the present parents' rows")
            }
            Self::InvalidRetainedRound { base, got } => {
                write!(f, "retained round {got} is below the present parents' base round {base}")
            }
            Self::InvalidRetainedOrder => {
                write!(f, "retained round_received/consensus_timestamp are inconsistent")
            }
            Self::DecidedRoundBeyondRetained { decided, max_retained } => {
                write!(
                    f,
                    "decided round {decided} exceeds the highest retained birth round {max_retained}"
                )
            }
        }
    }
}

impl std::error::Error for ConsensusError {}
