//! Core data types shared across the JKain workspace.
//!
//! This crate defines the consensus-critical value types and their plain
//! serialization forms. It deliberately has zero dependencies, so any crate
//! (crypto, consensus, gossip, tests) can build on it without pulling in
//! extra dependencies.
//!
//! Contents include `Event`/`UnsignedEvent` with two parents and payload
//! transactions, `EventHash` as the 32-byte graph node identifier,
//! `Transaction`/`TransactionHash`, `NodeId`, `Signature`, and `Timestamp`.
//! No cryptography lives here; hashing, canonical encoding, and signature
//! verification are provided by the `crypto` crate.

#![allow(clippy::must_use_candidate)]
mod error;
/// Hashgraph events.
pub mod event;
/// Event hash type.
pub mod event_hash;
/// Node identifier.
pub mod node;
/// Signature type.
pub mod signature;
/// Timestamp type.
pub mod timestamp;
/// Transaction type.
pub mod transaction;
/// Transaction hash type.
pub mod transaction_hash;

pub use error::{
    Error,
    Result,
};
pub use event::{
    Event,
    UnsignedEvent,
};
pub use event_hash::EventHash;
pub use node::NodeId;
pub use signature::Signature;
pub use timestamp::Timestamp;
pub use transaction::Transaction;
pub use transaction_hash::TransactionHash;
