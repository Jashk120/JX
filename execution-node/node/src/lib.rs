//! The `jkainc` daemon: a compute node that hosts off-chain actors and fronts
//! them with a single HTTP/JSON RPC endpoint (whitepaper §6.3).
//!
//! The counterpart to `jkaind` (the consensus daemon). It does not participate
//! in consensus; L1 is only read for coordination. v1: no app registry, no
//! on-chain deploy, no actor-to-actor messaging, no GAS economics. See
//! `what-it-is.md` §11.

pub mod rpc;

use std::path::PathBuf;

use actor_host::ActorManifest;
use anyhow::Context;

/// Parses argv and runs the daemon.
///
/// # Errors
///
/// Returns an error if configuration cannot be read, the actor cannot be
/// loaded, or the RPC listener fails.
pub fn run() -> anyhow::Result<()> {
    let config = Config::from_args()?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(serve(config))
}

/// The daemon's configuration surface.
pub struct Config {
    /// Address the host RPC binds, e.g. `127.0.0.1:8787`.
    pub listen: String,
    /// The actor to host, as `actor_id_hex=actor_id_kind:value` — see
    /// [`parse_actor_spec`]. v1 hosts one actor per process.
    pub actor: String,
    /// Path to the actor's WASM component.
    pub wasm: PathBuf,
}

impl Config {
    /// Reads configuration from the environment (v1 has no config file):
    /// `JKAINC_LISTEN` (default `127.0.0.1:8787`), `JKAINC_ACTOR` (a
    /// `did:jkain:...` root actor), and `JKAINC_WASM` (path to the actor's WASM).
    ///
    /// # Errors
    ///
    /// Returns an error if a required variable is absent.
    pub fn from_args() -> anyhow::Result<Self> {
        let listen = std::env::var("JKAINC_LISTEN").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
        let actor =
            std::env::var("JKAINC_ACTOR").context("JKAINC_ACTOR is required (did:jkain:...)")?;
        let wasm = std::env::var("JKAINC_WASM")
            .map(PathBuf::from)
            .context("JKAINC_WASM is required (path to the actor .wasm)")?;
        Ok(Self { listen, actor, wasm })
    }
}

async fn serve(config: Config) -> anyhow::Result<()> {
    let actor_id = parse_actor_spec(&config.actor)?;
    let wasm = std::fs::read(&config.wasm)
        .with_context(|| format!("read wasm {}", config.wasm.display()))?;
    let mut host = rpc::HostApi::new()?;
    let module = config.wasm.display().to_string();
    host.load(ActorManifest::new(actor_id.clone(), module), &wasm)?;
    tracing::info!(actor = %config.actor, "actor loaded");
    rpc::serve(&config.listen, host).await
}

/// Parses an actor spec: a `did:jkain:<network>:<alias>:<uuid-hex>` string for
/// a root actor. Sub-actors are deferred in v1.
///
/// # Errors
///
/// Returns an error if the string is not a valid `did:jkain` identifier.
pub fn parse_actor_spec(spec: &str) -> anyhow::Result<state::ActorId> {
    let did =
        state::DidId::parse(spec).map_err(|e| anyhow::anyhow!("invalid actor spec: {e:?}"))?;
    Ok(state::ActorId::Root(did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_actor_spec_accepts_a_did() {
        let id = parse_actor_spec("did:jkain:mainnet:echo:00000000000000000000000000000007");
        assert!(id.is_ok());
    }

    #[test]
    fn parse_actor_spec_rejects_garbage() {
        assert!(parse_actor_spec("not-a-did").is_err());
    }
}
