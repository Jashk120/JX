use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Validation { reason: String },
    OutOfRange { field: &'static str, got: String },
    SerializationFailed { reason: String },
    InvalidState { reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { reason } => write!(f, "validation failed: {reason}"),
            Self::OutOfRange { field, got } => write!(f, "{field} is out of range: {got}"),
            Self::SerializationFailed { reason } => write!(f, "serialization failed: {reason}"),
            Self::InvalidState { reason } => write!(f, "invalid state: {reason}"),
        }
    }
}

impl std::error::Error for Error {}
