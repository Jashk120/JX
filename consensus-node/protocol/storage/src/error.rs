use thiserror::Error;

/// Errors produced by the durable event log.
#[derive(Debug, Error)]
pub enum EventLogError {
    /// A Fjall storage error (I/O, corrupt journal, etc.).
    #[error("event log I/O error: {0}")]
    Io(#[from] fjall::Error),
    /// A stored record that cannot be decoded — a corrupt log.
    #[error("event log is corrupted: {0}")]
    Corrupt(String),
    /// The internal write lock was poisoned by a panicked thread.
    #[error("event log write lock poisoned")]
    Poisoned,
}
