//! Deterministic transaction execution for JKain (Phase 8).
//!
//! Consumes events in finalized consensus order and applies each transaction's
//! payload to a key-value [`State`] through a pure, deterministic function.
//! Execution reads no wall clock, uses no randomness, and performs no I/O:
//! given the same finalized event order and the same starting state, every
//! node derives the same resulting state.
//!
//! Transaction payloads are decoded from a tiny, explicit binary format — see
//! [`op`] for the spec. Membership operations (`0x02`) never touch `State`:
//! [`Executor::execute_event`] returns them as a side channel, and the gossip
//! layer drives membership activation from `RosterHistory` / `add_member`.
//!
//! [`finalized_events`] bridges this crate to the consensus layer: it walks a
//! `Hashgraph`'s rounds in increasing order and yields each round's events in
//! the exact order `consensus`'s `consensus_order` produces (roundReceived,
//! then consensusTimestamp, then the signature-derived tie-break), so this
//! crate never invents its own ordering rule.

mod error;
mod executor;
mod op;
mod state;

pub use error::{
    ExecutorError,
    Result,
};
pub use executor::{
    Executor,
    finalized_events,
};
pub use op::{
    DecodedOp,
    Op,
};
pub use state::State;
