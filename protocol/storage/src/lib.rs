//! Durable storage for a JKain consensus node (Phase 8).
//!
//! `event_log` implements the Fjall-backed append-only event log: every
//! verified event is appended on insert, keyed by `EventHash`, decoupled from
//! the checkpoint (`.cp`) files. A restarting node replays the log to
//! rebuild its retained graph independently, instead of
//! `request_reconnect()`ing from a live peer.

mod error;
pub mod event_log;

pub use error::EventLogError;
pub use event_log::{
    EventLog,
    EventSink,
};

/// Result alias for the storage crate.
pub type Result<T> = std::result::Result<T, EventLogError>;
