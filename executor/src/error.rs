use std::fmt;

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
}

pub type Result<T> = std::result::Result<T, ExecutorError>;

impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "transaction payload is empty"),
            Self::Truncated => write!(f, "transaction payload is truncated"),
            Self::UnknownOpcode(opcode) => write!(f, "unknown transaction opcode {opcode:#04x}"),
            Self::TrailingBytes => write!(f, "transaction payload has trailing bytes"),
        }
    }
}

impl std::error::Error for ExecutorError {}
