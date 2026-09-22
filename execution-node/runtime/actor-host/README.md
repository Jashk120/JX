# actor-host

Local WASM actor hosting for the `execution-node` (whitepaper §6.3.2).

## Milestone

[`Runtime`](https://docs.rs/actor-host) loads one WebAssembly component per
actor, instantiates it in its own sandboxed `wasmtime` `Store`, and
dispatches inbound requests to the addressed actor:

```rust
let mut runtime = Runtime::new()?;
runtime.load(ActorManifest::new(actor_id.clone(), "echo"), &wasm)?;
let reply: Vec<u8> = runtime.dispatch(&actor_id, b"ping")?;
```

## Interface

The single source of truth for host and guest is
[`../../wit/actor.wit`](../../wit/actor.wit) (`jkain:actor@0.0.1`, world
`actor`, interface `handler` with
`handle-request: func(request: list<u8>) -> result<list<u8>, string>`).
The host generates bindings with
`wasmtime::component::bindgen!({ path: "../../wit", world: "actor" })`;
guests use `wit-bindgen` against the same file and world.

## `Runtime` API

- `Runtime::new() -> anyhow::Result<Self>` — builds the shared `Engine` and
  `Linker` (with WASI) once.
- `Runtime::load(&mut self, manifest: ActorManifest, wasm: &[u8])` —
  compiles the component, instantiates it, and registers it under
  `manifest.actor_id`. A duplicate `actor_id` is rejected.
- `Runtime::unload(&mut self, id: &ActorId) -> bool` — removes the actor.
- `Runtime::status(&self, id: &ActorId) -> Option<ActorStatus>` —
  `Some(Loaded)` when resident, else `None`.
- `Runtime::dispatch(&mut self, id: &ActorId, request: &[u8])` — calls the
  actor's `handle-request` and returns its reply; unknown actors error.

The registry is keyed by `actor_id.encode()` bytes because `ActorId` does
not implement `Hash`/`Ord`.

## Isolation

One sandboxed instance per actor: each actor gets its own `Store` and its
own `Actor` bindings, so actors share no linear memory. WASI networking is
denied by default — the host builds the `WasiCtx` without
`inherit_network()`, so guests cannot open TCP/UDP sockets. The host
receives messages and dispatches them via host function calls.

## Not built yet

Deliberately deferred: actor discovery, actor-to-actor messaging, the
`blob_get`/`blob_put` storage boundary and encrypted shared buckets,
on-chain (L1) actor registration and resolution (the caller passes the
manifest directly), lifecycle hooks and idle unload, heartbeats,
replication, and any HTTP interface.
