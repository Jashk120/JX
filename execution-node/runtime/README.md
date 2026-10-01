# runtime

Off-chain actor hosting: the runtime, the per-actor manifests, and the storage
boundary.

Whitepaper §6.3.2: actors are WebAssembly components hosted via a
Component-Model-capable runtime, with raw networking kept out of the sandbox
(the host receives messages and dispatches via host function calls). §6.5:
actors are unloaded after idle periods and cold-started on demand rather than
kept resident.

This umbrella holds one crate:

- `actor-host/` — the `ActorManifest`/`HostedActor` types, the WASM runtime,
  and (later) the `blob_get`/`blob_put` storage boundary and encrypted shared
  buckets.

The actor is an application-specific program bound to its owner's DID, not a
generic container: the DID is the permanent identifier, the hosting node is a
replaceable resource (§6.2).
