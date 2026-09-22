//! Off-chain actor hosting: per-actor manifests and a `wasmtime`-backed runtime.
//!
//! Whitepaper §6.3.2: actors are WebAssembly components hosted via a
//! Component-Model-capable runtime, with raw networking kept out of the
//! sandbox (the host receives messages and dispatches via host function
//! calls). §6.5: actors are unloaded after idle periods and cold-started on
//! demand.
//!
//! Local-hosting milestone: [`Runtime`] compiles one WASM component per
//! actor, instantiates it in its own sandboxed [`wasmtime::Store`], and
//! dispatches inbound requests to the addressed actor's `handle-request`
//! export. On-chain registration and resolution are deliberately stubbed:
//! the caller supplies the [`ActorManifest`] (including the on-chain
//! [`ActorId`](state::ActorId)) directly to [`Runtime::load`]; no L1 lookup
//! happens here.
//!
//! Not built yet: actor discovery, actor-to-actor messaging, the
//! `blob_get`/`blob_put` storage boundary, encrypted shared buckets, idle
//! unload, heartbeats, replication, and any HTTP interface.

mod runtime;

pub use runtime::Runtime;
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
