//! The `wasmtime`-backed hosting [`Runtime`]: one sandboxed component instance
//! per actor, keyed by the on-chain [`ActorId`](state::ActorId).

use std::collections::HashMap;

use state::ActorId;

use crate::{
    ActorManifest,
    ActorStatus,
};

wasmtime::component::bindgen!({ path: "../../wit", world: "actor" });

struct HostState {
    ctx: wasmtime_wasi::WasiCtx,
    table: wasmtime_wasi::ResourceTable,
}

impl wasmtime_wasi::WasiView for HostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}

fn new_host_state() -> HostState {
    HostState {
        ctx: wasmtime_wasi::WasiCtxBuilder::new().build(),
        table: wasmtime_wasi::ResourceTable::new(),
    }
}

struct HostedInstance {
    manifest: ActorManifest,
    store: wasmtime::Store<HostState>,
    bindings: Actor,
}

/// Hosts WASM actor components locally: each actor runs as its own
/// sandboxed [`Actor`] instance with a private [`wasmtime::Store`].
///
/// WASI networking stays denied by default (no `inherit_network`), so actors
/// cannot open sockets; the host dispatches opaque request bytes in and
/// carries reply bytes out.
pub struct Runtime {
    engine: wasmtime::Engine,
    linker: wasmtime::component::Linker<HostState>,
    instances: HashMap<Vec<u8>, HostedInstance>,
}

impl Runtime {
    /// Builds the shared `wasmtime` engine and linker once.
    ///
    /// # Errors
    ///
    /// Returns an error if the WASI linker cannot be extended.
    pub fn new() -> anyhow::Result<Self> {
        let engine = wasmtime::Engine::default();
        let mut linker = wasmtime::component::Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        Ok(Self { engine, linker, instances: HashMap::new() })
    }

    /// Compiles `wasm` as a component, instantiates it, and registers it
    /// under `manifest.actor_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `actor_id` is already loaded or if the
    /// component fails to compile or instantiate.
    pub fn load(&mut self, manifest: ActorManifest, wasm: &[u8]) -> anyhow::Result<()> {
        let key = manifest.actor_id.encode();
        if self.instances.contains_key(&key) {
            return Err(anyhow::anyhow!("actor already loaded"));
        }
        let component = wasmtime::component::Component::from_binary(&self.engine, wasm)
            .map_err(|e| anyhow::anyhow!("compile component: {e}"))?;
        let mut store = wasmtime::Store::new(&self.engine, new_host_state());
        let bindings = Actor::instantiate(&mut store, &component, &self.linker)
            .map_err(|e| anyhow::anyhow!("instantiate component: {e}"))?;
        tracing::debug!(module = %manifest.module, "actor loaded");
        self.instances.insert(key, HostedInstance { manifest, store, bindings });
        Ok(())
    }

    /// Removes the actor from the registry, returning `true` if present.
    pub fn unload(&mut self, id: &ActorId) -> bool {
        self.instances.remove(&id.encode()).is_some()
    }

    /// Reports [`ActorStatus::Loaded`] when the actor is resident, else
    /// `None`.
    #[must_use]
    pub fn status(&self, id: &ActorId) -> Option<ActorStatus> {
        self.instances.contains_key(&id.encode()).then_some(ActorStatus::Loaded)
    }

    /// Dispatches `request` to the addressed actor and returns its reply.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown actor, a `wasmtime` trap, or an
    /// actor-reported failure.
    pub fn dispatch(&mut self, id: &ActorId, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = id.encode();
        let inst = self.instances.get_mut(&key).ok_or_else(|| anyhow::anyhow!("unknown actor"))?;
        let reply = inst
            .bindings
            .jkain_actor_handler()
            .call_handle_request(&mut inst.store, request)
            .map_err(|e| anyhow::anyhow!("wasmtime: {e}"))?
            .map_err(|e| anyhow::anyhow!("actor: {e}"))?;
        Ok(reply)
    }

    /// Returns the manifest an actor was loaded with, if resident.
    #[must_use]
    pub fn manifest(&self, id: &ActorId) -> Option<&ActorManifest> {
        self.instances.get(&id.encode()).map(|inst| &inst.manifest)
    }
}
