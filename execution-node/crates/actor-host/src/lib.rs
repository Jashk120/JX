//! Off-chain actor hosting: per-actor manifests, the WASM runtime, and the
//! storage boundary.
//!
//! Whitepaper §6.3.2: actors are WebAssembly components hosted via a
//! Component-Model-capable runtime, with raw networking kept out of the
//! sandbox (the host receives messages and dispatches via host function
//! calls). §6.5: actors are unloaded after idle periods and cold-started on
//! demand.
//!
//! Not yet implemented: the `wasmtime` dependency, the WIT interface, the
//! `blob_get`/`blob_put` host boundary, and encrypted shared buckets. Nothing
//! here is wired to a message transport; the entity types below exist so the
//! manifest and per-actor state shape are reviewable before the runtime lands.

use state::ActorId;

/// The off-chain manifest describing one actor instance.
///
/// Identifies the actor (its on-chain `ActorId`), the code to run, and the
/// storage it owns. The manifest is off-chain per the whitepaper (§6.2: the
/// DID is the permanent identifier, the host is a replaceable resource).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorManifest {
    pub actor_id: ActorId,
    /// Content address or name of the WASM component to instantiate.
    pub module: String,
}

impl ActorManifest {
    #[must_use]
    pub fn new(actor_id: ActorId, module: impl Into<String>) -> Self {
        Self { actor_id, module: module.into() }
    }
}

/// Runtime state for a hosted actor: loaded, or unloaded but retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorStatus {
    /// Resident in memory, serving requests.
    Loaded,
    /// Cold: only metadata and persisted storage retained (whitepaper §6.5).
    Unloaded,
}

/// A host-side handle to one actor instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedActor {
    pub manifest: ActorManifest,
    pub status: ActorStatus,
}

impl HostedActor {
    #[must_use]
    pub fn new(manifest: ActorManifest) -> Self {
        Self { manifest, status: ActorStatus::Unloaded }
    }
}
