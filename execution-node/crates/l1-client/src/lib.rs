//! The L1 integration boundary for a compute node.
//!
//! The whitepaper (`docs/JKain_Whitepaper.md` §6.3.1) bounds what a compute
//! node may ask of the consensus layer: read-only queries and the submission
//! of already-signed transactions. A compute node never re-derives
//! authorization locally — L1 is the sole source of truth — so this crate is
//! deliberately thin.
//!
//! Reads decode with the same types L1 writes, by linking the `state` crate
//! rather than re-implementing the canonical binary format. That is the
//! property the Rust choice for compute nodes buys: one decoder, one source of
//! truth, no second opinion about the bytes.
//!
//! Not yet implemented: the transport (gRPC per §6.3.1), checkpoint-fetch, and
//! state-proof verification against a committed `state_hash`.

use anyhow::Result;

/// A read-only view of L1 state as a compute node sees it.
///
/// Placeholder for the DID/actor resolution surface: resolving a DID, reading
/// a root actor's commitment, and verifying an RFC-6962 inclusion proof for a
/// sub-actor against the latest committed checkpoint.
pub trait L1Reader {
    /// Fetches the DID document bytes for `id`, if present.
    fn did_document(&self, id: &primitives::NodeId) -> Result<Option<Vec<u8>>>;
}

/// Submits an already-signed transaction payload to L1.
///
/// The payload is built by the caller from the same `state` encodings L1
/// uses; this boundary never authorizes, only forwards.
pub trait L1Submitter {
    /// Submits `payload` (a `state::DecodedOp` encoding) for ordering.
    fn submit(&self, payload: &[u8]) -> Result<()>;
}

/// Placeholder so the crate is non-empty and the boundary shape is reviewable.
#[derive(Debug, Default)]
pub struct Pending;

impl Pending {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
