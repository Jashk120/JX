# what-it-is


Scope note: this is written from the code and the `execution-node/README.md`
only — no whitepaper. It states plainly what exists, what is stubbed, and what
is a design decision still to be made. It is an understanding, not a plan.

Scope note (v1): the target has been narrowed to a **v1** — see §11. The
app/source registry, smart-contract-like app entity, actor↔actor messaging,
and per-actor SQLite are **deferred out of v1**. §6.4 and parts of §6–§8
describe the fuller model for context only.

---

## 1. What an execution node is

A **second, cooperating node type** (`execution-node/`) whose job is to
**host and execute user actors as WebAssembly components**. It does **not**
join hashgraph consensus. L1 (`consensus-node/`) provides identity, ordering,
and coordination; the execution node only executes. It never authorizes
anything itself — it defers every authorization/ledger-state decision to L1 and
decodes L1 bytes with the same Rust `state` crate rather than re-deriving them
(`execution-node/README.md`, `l1/client/src/lib.rs`).

---

## 2. What exists in code today

### 2.1 On L1 — actor *identity* is real

`consensus-node/executor/state` already models actors as on-chain state:

- `ActorId` (`root_actor.rs:76`): `Root(DidId)` or
  `Sub { root_did, tag, index }` (`tag` ∈ defi/messenger/game/generic;
  `index < 0x8000_0000`). Encoded `0x00 || DidId` / `0x01 || DidId || tag:u8 || index:u32BE`.
- `RootActor` (`root_actor.rs:149`): a DID's **append-only sub-actor
  commitment** (`merkle_root`, `leaf_count`, `control_key`), committed via the
  RFC-6962 `merkle_log`.
- `SubActor` (`sub_actor.rs:43`): `{ actor_id, control_key, operating_key }`;
  the control key is committed in the root log, the operating key is mutable
  (rebinds stay outside the commitment).
- State key prefix `0xA1`: `actor_state_key(id) = 0xA1 || id.encode()`
  (`root_actor.rs:134`). Only validated actor transitions may write this prefix.
- Ops: `0x03 DidOp` (create/update/deactivate a `did:jkain` document; creation
  writes a fresh `RootActor`), `0x04 SubActorOp` (mint a sub-actor; requires
  root-document signature + RFC-6962 inclusion **and** consistency proofs
  agreeing with `new_root`), `0x05 RebindOp` (rotate a sub-actor's operating
  key; root-control-only). All are signed payloads decided by the deterministic
  `Executor`.

So today, "an actor" **on L1** means an identity + keys + membership
commitment, created by a wallet-signed transaction and decided by consensus.

What is **not** on L1: any actor **code**, any **compute-node registry**, or
any binding from an actor to a host.

### 2.2 Off-chain — actor *hosting* is real

`runtime/actor-host` (`runtime.rs`):

- `Runtime { engine: wasmtime::Engine, linker, instances: HashMap<Vec<u8>, HostedInstance> }`.
- `HostedInstance { manifest, store: wasmtime::Store<HostState>, bindings }`.
- API: `new` / `load(manifest, wasm)` / `unload` / `status` / `dispatch` / `manifest`.
- `ActorManifest { actor_id: state::ActorId, module: String }` (`lib.rs:32`) —
  `module` is just a **string label**; there is no code registry behind it.
- Host↔guest contract is one WIT world (`wit/actor.wit`,
  `jkain:actor@0.0.1`): **export only** `handle-request(list<u8>) -> result<list<u8>, string>`.
- Isolation: one sandboxed `Store` + instance per actor, keyed by
  `actor_id.encode()` (because `ActorId` has no `Hash`/`Ord`). WASI is built
  with **no preopens and no networking** (`WasiCtxBuilder::new().build()`), so
  actors have no filesystem and no sockets.

`actors/echo` is a sample guest (returns the request bytes); the integration
test `runtime/actor-host/tests/hosting.rs` builds it to `wasm32-wasip2`, loads
it, and dispatches `b"ping"`.

### 2.3 The L1 boundary — shape only

`l1/client` (`l1/client/src/lib.rs`) has `L1Reader { did_document() }` and
`L1Submitter { submit() }` traits plus a `Pending` placeholder. **No transport**
(gRPC deferred), no checkpoint-fetch, no proof verification. Nothing uses these
traits yet.

### 2.4 The daemon — a stub

`node/src/lib.rs::run()` returns
`anyhow::bail!("jkainc: not implemented yet (scaffold only)")`; `jkainc` just
calls it. No config surface (listen addr, data dir, L1 endpoint), no lifecycle,
no wiring of `l1-client` + `actor-host` (even though `node/Cargo.toml` depends
on both).

---

## 3. What an actor can do today

Only this: **receive one request byte-string and return one reply byte-string**
(or an error). It runs in an isolated component instance with no filesystem, no
network, no L1 access, no storage, no messaging, no lifecycle hooks, no
discovery. The echo actor is the entire working capability.

---

## 4. Can an actor read from L1 today?

**No.** Concretely:

- The WIT world `actor` **exports** `handler` and **imports nothing**. There is
  no `l1-read` (or `blob-get`, `sql`, `send`, …) host interface, so a guest
  cannot call into the host for anything.
- `L1Reader`/`L1Submitter` are unused trait shapes with no transport.
- The host builds no handles to L1; `Runtime` has no L1 field.

Reading from L1 is therefore **not a wiring tweak** — it requires adding an
**imported host interface** to `wit/actor.wit`, implementing it in the host
(backed by a real L1 reader), and deciding capability/authorization policy.
(And separately: whether the host reads L1 over gRPC with proofs, or by linking
the `state` crate directly — an acknowledged open question in
`execution-node/README.md`.)

---

## 5. How actors are created today — two disconnected paths

There are **two independent notions of "actor"** and they do not talk to each
other:

| Path | Where | What "create" means |
|---|---|---|
| **On-chain identity** | L1 `executor/state` | Wallet signs a `DidOp` (creates the DID + `RootActor`) and/or a `SubActorOp` (mints a tagged sub-actor with RFC-6962 proofs). Result: an on-chain `ActorId` + keys + commitment. |
| **Off-chain hosting** | `runtime/actor-host` | A Rust caller does `Runtime::load(manifest, wasm)` in-process. Result: a live sandboxed WASM instance. |

There is **no bridge**: nothing observes an L1 actor creation and instantiates
it, and `ActorManifest.module` is not resolved to anything. In the test, the
manifest is passed directly. So "create an actor" today is two manual,
unconnected steps.

---

## 6. The target model (as I understand your vision)

1. An **on-chain actor registry**: all actors and their **code** live on L1.
2. **App install + wallet sign-in** → the client sends **an L1 transaction to
   deploy an actor for that DID** → the actor is actually deployed/instantiated
   for that user.
3. **actor↔actor** communication with an **SDK** you provide.
4. **app↔actor** communication (also via SDK).
5. A deployed actor has **its own SQLite database**.
6. Question asked: **is this buildable?**

Short answer: **yes — it is buildable, and it maps well onto what already
exists — but it is ~5 new subsystems plus 2 unresolved design decisions, not a
wiring job.** Details below.

### 6.1 Two registries, not one

The word "registry" hides two different things. The code has the first; the
vision needs both.

| Registry | Answers | Status in code |
|---|---|---|
| **Ownership registry** (DID-rooted) | *Who owns this actor instance?* | **exists** — `ActorId::Root(DidId)` / `Sub { root_did, tag, index }`; the `tag` is the app type (`0=defi, 1=messenger, 2=game, 3=generic`); the per-user actor is a `Sub` slot under the user's DID, committed in `RootActor`'s RFC-6962 log. |
| **Source registry** (content-addressed) | *Which actor code may this app run, and where is it?* | **missing** — `ActorManifest.module` is a bare `String`; no op carries a code hash; nothing binds an app to a source. |

So "a Messenger actor for user X" already has an ownership slot:
`ActorId::Sub { root_did: X, tag: Messenger, index }`. What is absent is the
**app → actor-source** binding — the part the smart-contract analogy describes.

### 6.2 The smart-contract analogy, mapped

| Smart contract | Target model | Primitive here |
|---|---|---|
| contract address / code hash | **actor source public address** | content hash of the WASM component (self-certifying) |
| deployer / dapp authority | **app public address** — a standalone app entity, *not* a developer DID and *not* a user DID (see §6.4) | new native `App` record + app authority key |
| `CREATE` / deploy tx | **(app address, source address) deploy tx** | a new op: register a source + bind a per-user actor to it |
| contract instance | **the user's WASM actor** | the `Sub` actor slot under the user's DID, now carrying `source_hash` |

The deploy flow: the client sends `{ app_public_address,
actor_source_public_address, target_did }` carrying **two independent
attestations** — the app's (genuine app, and source S is authorised for it) and
the target DID's operating key (instantiate for *me*). The executor verifies
both, writes the per-user actor record referencing `source_hash`, and a compute
node fetches the blob, **verifies it hashes to `source_hash`**, and instantiates
it. This mirrors how `SubActorOp` already needs the root-document signature plus
the inclusion and consistency proofs.

### 6.3 The WASM source is user-agnostic

The component bytes are pure code — like a web app before sign-in. What makes
an instance "that user's actor" is the **instantiation context**, none of which
is in the code:

- the bound `ActorId`/DID (principal injected by the host),
- a per-actor **storage namespace** (its SQLite / blob space),
- host-injected keys and config,
- the isolation of its own `wasmtime::Store`.

One artifact → N sandboxed instances, one per user. `Runtime` already does the
isolation half (`instances: HashMap<Vec<u8>, HostedInstance>`, one `Store` per
actor); the changes are that the instance key includes the user and the code
comes from a content-addressed registry instead of an in-process `&[u8]`.

### 6.4 The app identity — a standalone on-chain entity

Correcting §6.2's shorthand: the **app** has its own on-chain identity, fully
independent of any user and *not* the developer's DID. It exists to answer two
questions only:

1. **Is this request from the genuine app?** (anti-clone / anti-spoof)
2. **Is this app allowed to use this actor source?**

It never inspects or authorises the user — that is the user's own DID key's job
(§6.2's second attestation). So a deploy needs **both**: the app's signature
("genuine app, and source S is mine") and the target DID's operating-key
signature ("instantiate for me"). Neither side can substitute for the other.

**No contract VM — this is a native rule.** JKaIN's L1 executor is a fixed op
set (`Put`/`Delete`/`DidOp`/`SubActorOp`/`RebindOp`/`MembershipOp`); there is no
general smart-contract VM, so nothing can be "deployed as a contract". The
smart-contract-like app entity must be built as a **new native `App` record +
new executor ops**. If arbitrary on-chain logic is wanted, that is a VM feature
and a much larger project — decide this explicitly.

**The compile-time credential.** The app proves genuineness with something baked
in at build time. The workable form is an **app signing key pair**:

- The app's public key — or `AppId = H(app_key ‖ source_hash)` (CREATE2-style,
  so the address itself commits to the code) — is registered on-chain; the app
  signs its deploy requests with the private key.
- Binding `AppId` to `source_hash` gives the strong property "this address can
  only ever run my code", at the cost of a new identity per source version.

Caveats to be honest about:

- A secret embedded in a client-distributed binary is **extractable**. An app
  key is a **spoofing deterrent** (stops casual clones and forged addresses),
  **not** hard cryptographic proof of genuineness.
- Hard app authentication needs platform attestation, a server-mediated flow, or
  per-install keys — infrastructure this project does not have yet.
- A shared static secret is the weakest option and should be avoided in favour
  of a key pair.

---

## 7. Feasibility — subsystem by subsystem

### 7.1 On-chain actor registry (+ code)
- **Identity registry: mostly exists.** `ActorId` + `RootActor`/`SubActor` +
  `0xA1` state keys already give a canonical, wallet-authorized on-chain actor
  record. A "deploy" is a new op (e.g. `0x06 DeployActor { actor_id,
  module_hash, config }`) signed by the DID/sub-actor operating key, validated
  by the executor. Adding an opcode touches `op.rs`, `FORMAT_VERSION`, the
  record/mirror streams, and golden vectors — a real, reviewable change, not a
  rewrite.
- **Code on-chain: needs a decision.** Options:
  - *Hash on-chain, bytes off-chain* (recommended): L1 stores `module_hash`
    (content address); the WASM blob lives in a content-addressed blob store
    the host fetches and **verifies against the hash** before instantiating.
    This is exactly the `blob_get`/`blob_put` boundary already listed as "not
    built".
  - *Bytes on-chain*: possible (L1 state is KV), but every byte goes into the
    state Merkle tree, checkpoints, `.rsf` streams, and every node's state —
    fine for tiny actors, bad in general.
  - "Source code on-chain" in the literal sense is heavier still; realistically
    store a **content hash / pointer** to source + artifact, not the source
    bytes.

### 7.2 Deploy-on-sign-in flow
Buildable, and it decomposes cleanly:
1. Client SDK: wallet signs the deploy op (reusing the existing domain-tagged
   signed-payload pattern, cf. `DidOp::signed_payload` = `jkain:did:v1 ‖ …`).
2. Submit to L1; consensus orders it; the deterministic executor writes the
   actor's registry record.
3. A **compute-node watcher** observes finalized actor records, fetches/verifies
   the code blob, and instantiates the actor for that DID.
Gap: **which compute node instantiates it.** That is the "location/resolution
(Phase C)" item the README marks **not started — prerequisite for
reachability**. Without a registry of compute nodes + an assignment/placement
rule + a way to find an actor, steps 3 and the SDKs have nowhere to route.

### 7.3 actor↔actor and app↔actor SDKs
- Feasible, but constrained by the sandbox: **actors cannot open sockets**
  (WASI networking is denied). So messaging must be **host-mediated**:
  - Add imported host functions to the WIT world, e.g.
    `send(target: actor-id, bytes)` / an outbound queue the host drains.
  - The host owns addressing (`ActorId` is a stable address), routing,
    delivery semantics (at-least-once?), and wake/cold-start.
  - The **SDK** is then (a) a guest-side library over that host interface and
    (b) a client-side library for apps to reach actors.
- This needs the location/resolution layer from 7.2 to know where the target
  actor currently lives.

### 7.4 Per-actor SQLite
- Feasible; two designs:
  - **In-guest SQLite** compiled to WASM, with a **per-actor directory**
    preopened into that instance's WASI `WasiCtx`. `wasmtime-wasi` already
    exposes the right primitive (preopens + `ResourceTable`); today the host
    opens **zero** preopens, so this is a bounded change. Guest owns the SQL.
  - **Host-side SQLite** behind a `sql` host-function interface; host owns the
    file, durability, quotas, and backup. No SQLite-in-WASM, but the guest must
    go through the host ABI.
- Either way, each actor's DB is a host-managed per-actor resource.

### 7.5 The one real blocker: the replication/state model
The README flags an **unresolved contradiction** between §6.4 and the V3 notes,
and "whether reads link the `state` crate directly or go over gRPC". This
matters because:
- L1's guarantee is **deterministic replicated state** (same order + same
  state → bit-identical Merkle root, `state/README.md`).
- A deployed actor with a **mutable SQLite DB and side effects** is *not*
  deterministic — it cannot be replicated the way L1 KV is.
- So the model must decide: actors are **singly-hosted, non-deterministic**,
  with L1 anchoring **identity, authorization, and (optionally) result
  attestations** — not replicated execution. If instead actors must be
  replicated, the storage/messaging design changes fundamentally.
**Lock this before building 7.3/7.4**, or you build storage and messaging on a
contradictory foundation.

### 7.6 L1 read path
Decide gRPC-with-proofs vs direct `state` linking. gRPC keeps the sandbox
isolated and avoids a second source of truth (matching the "never re-derive
ledger state" rule); direct linking is simpler but couples the compute node to
L1 internals.

---

## 8. Blockers / decisions to lock first

1. **Replication/state model** (§7.5) — the contradiction the README already
   flags. Everything about storage and messaging depends on it.
2. **L1 read path** — gRPC+proofs vs link `state` (§7.6).
3. **Code storage** — content hash + blob store vs on-chain bytes, and who
   verifies `blob_hash` before instantiation.
4. **Compute-node registry + placement** (Phase C) — required for deploy and
   for both SDKs to route anywhere.
5. **Messaging semantics** — host-mediated delivery, ordering, retries,
   cold-start; guest ABI (`send`/receive) and the SDK surface.
6. **Actor storage ABI** — in-guest SQLite + per-actor preopen vs host `sql`
   interface; quotas and durability.
7. **App identity + anti-spoof** (§6.4) — `AppId` derivation (key-only vs
   key+source-hash), the compile-time credential, how strong app authentication
   must be, and whether a native `App` record is enough or a VM is wanted.

---

## 9. Suggested staging (once decisions are locked)

- **A. App + source registry, then deploy op.** Add a native `App` record
  (§6.4) and the content-addressed source registry, then the deploy op carrying
  the app attestation and the DID operating-key attestation; `FORMAT_VERSION` +
  mirror/golden-vector updates. Client can submit; L1 records it.
- **B. Compute-node registry + location/resolution (Phase C).** Registers
  nodes, assigns actors, exposes lookup. Unblocks routing.
- **C. Watcher + instantiate.** Compute node observes finalized deploy records,
  fetches+verifies the code blob, `Runtime::load` for that DID.
- **D. Guest host-ABI + storage.** Add imported interfaces (`l1-read`,
  `blob-get`/`blob-put`, `sql`, `send`) to `wit/actor.wit`, implement them in
  the host, give each actor its private storage.
- **E. SDKs + lifecycle.** actor↔actor and app↔actor SDKs, idle unload /
  cold-start.

Each stage is independently testable (the existing `hosting.rs` test is the
pattern: build a guest, load, dispatch).

---

## 10. Open questions I could not answer from the code

- Is the on-chain registry meant to store **code bytes**, or a **content hash
  pointing off-chain**? (Affects L1 state size and the blob boundary.)
- Is "source code on-chain" literal, or a pointer to source/artifact?
- Are actors **replicated** or **singly-hosted**? (Resolves 7.5.)
- Does the actor get its own DID-derived sub-actor slot (reusing `SubActorOp`),
  or a new actor kind?
- How is `AppId` derived — app key only, or `H(app_key ‖ source_hash)`
  (CREATE2-style)? And how strong must app authentication be, given a
  client-embedded key is extractable (§6.4)?
- Is a native `App` record + executor ops sufficient, or is a general
  smart-contract VM actually wanted? (There is no VM today.)
- Who pays for hosting/compute, and what stops an arbitrary deploy op from
  using all node resources?
- Reads: gRPC or direct `state` link?

---

## Summary

- **Today:** actors are isolated WASM `handle-request` handlers. They cannot
  touch L1, storage, the network, or each other. L1 has actor *identity*
  (`ActorId`/`RootActor`/`SubActor`); off-chain has actor *hosting*; the two are
  not connected; the daemon is a stub.
- **Your target model is buildable.** The identity half largely exists, the
  host runtime works, and the deploy/SDK/storage pieces are additive.
- **But it is a multi-subsystem build**, gated on resolving the
  replication/state model and the L1-read path first, plus building the
  compute-node registry (Phase C) that everything routes through.

---

## 11. v1 — the narrowed target

v1 is deliberately small. **No app registry, no smart-contract-like app entity,
no actor↔actor messaging, no per-actor SQLite, no SDK.** Just:

- **One actor**, in its **own repo**, deployed **manually** for a **specific
  app only**. No on-chain deploy op, no app/source registry, no auto-deploy —
  an operator starts the actor out-of-band.
- **One app** (mobile/web), in a **separate repo**, that talks to that actor.
- **Host-authored data belongs to the actor.** The actor is the source of
  truth; the app is a client.
- **The app caches locally in SQLite.** Client-side cache only — the actor does
  not have its own DB in v1.
- Explicitly **out**: actor↔actor, app↔actor SDK packaging, per-actor SQLite,
  app/source registries, on-chain app identity.

What v1 changes versus §6–§9: **skip 9.A entirely** (deployment is manual, so
the on-chain `App`/source registry and the deploy op do not exist yet), and
**§9.D shrinks** — the actor only needs a request/reply path plus whatever
L1-read it needs; the `sql` and `send` host interfaces are out.

### 11.1 What v1 needs that does not exist yet

1. **A real transport + daemon.** `jkainc` is a stub
   (`bail!("not implemented")`). v1 needs it to: take a config (listen address,
   actor binary path, L1 endpoint, and the bound principal), `Runtime::load` the
   actor, and serve requests over a wire. This is the core of v1.
2. **app↔actor messaging.** `Runtime::dispatch(id, request) -> Result<Vec<u8>>`
   is synchronous and in-process; there is no socket/HTTP/queue. v1 needs a
   request/reply transport in front of `dispatch`. The canonical request/reply
   shape **already exists**: `handle-request(list<u8>) -> result<list<u8>, str>`.
3. **How the app authenticates / which actor it reaches.** With no registry,
   this is out-of-band config: the app is pointed at the actor's endpoint. The
   "which DID owns this actor" binding is manual for v1.
4. **L1 read path — only if the actor needs it.** If the actor is
   self-contained, v1 needs **no** L1 read and `l1/client` stays a scaffold.
   If it must read ledger state, pick gRPC-with-proofs vs linking `state`, and
   add an imported WIT host function for it (`l1-read`).

### 11.2 v1 data-model

- **Actor = source of truth.** It holds the authoritative per-actor data.
  "Host-authored" data lives here.
- **App = cache.** The app keeps a local **SQLite** copy for offline/fast reads
  and syncs against the actor. Pull on launch + on demand; the actor is
  authoritative on conflict.
- Invariant to hold even under the actor's non-deterministic storage: **the app
  can always reconcile from the actor** (resync/replace), so a stale or wiped
  client cache is never data loss.

### 11.3 One RPC endpoint per host, not per actor

The app does **not** talk to the actor directly and does **not** need to know
which actor it is. It speaks to **one RPC URL for the whole `jkainc` host**;
that host multiplexes to the right sandboxed actor instance internally, via
`Runtime::dispatch(actor_id, request)`.

- **N actors on one machine → 1 endpoint.** Ten actors behind one `jkainc` share
  a single RPC URL.
- **The actor_id is a routing parameter**, carried inside the request (in the
  envelope/params), not a per-actor address the app has to discover.
- **The app caches the RPC URL** — the last one it successfully talked to — and
  re-dials it. Discovery of *which* host is therefore an app-side cache, not an
  on-chain lookup (no registry in v1).

So the shape is: `app → [one host RPC URL] → jkainc envelope decode → actor_id
→ Runtime::dispatch → actor handle-request → reply → app`.

Forward-looking: the cached URL is a **rendezvous hint**, not the source of
truth for where the actor *lives*. If placement moves (migration, multi-host),
the host (or a resolution layer) can redirect the app to the new URL; the
protocol should carry a redirect/refresh path so a stale cache is survivable.
No such layer exists in v1 — with manual, singly-hosted actors the URL is fixed.

### 11.3.1 The wire: plain HTTP + JSON

The host RPC is **plain HTTP carrying JSON** — chosen because it is trivial to
call from the app (mobile/web). So `jkainc` serves an HTTP endpoint; the app
POSTs JSON; the host decodes, extracts `actor_id`, and forwards the payload to
`Runtime::dispatch`. The actor's internal request/reply is still the opaque
`handle-request(list<u8>) -> result<list<u8>, string>`; the HTTP/JSON layer is
purely the host-facing envelope.

### 11.3.2 Auth: every message signed by the caller's public key

There is no session/cookie auth. **Each request is signed by the caller's
public key**, and the host verifies it. This is the same pattern L1 already uses
for DID/SubActor ops: a domain-tagged signed payload with an Ed25519 key
(`Signable`/`Verifiable` in `crypto`, e.g. `DidOp::signed_payload` =
`jkain:did:v1 ‖ …`). v1 reuses that machinery: define an actor-RPC signed
envelope (`jkain:rpc:v1 ‖ actor_id ‖ method ‖ body ‖ nonce ‖ …`) and verify with
`ed25519_dalek::VerifyingKey::verify_strict`, exactly as
`Verifiable for Event` does.

The host checks the signature and the **signing key's authorization** against
the actor/DID it is sending the request to; a valid signature by an unrelated
key is rejected. (Which keys are allowed is the same open question the rest of
the design has — for v1 the actor's bound principal is set manually.)

### 11.3.3 GAS: meter every read, no economics yet

The target is that **the wallet must have GAS and every read consumes GAS** —
but v1 introduces **no economics** (no token, no pricing, no settlement). So v1
builds the *meter*, not the *market*:

- **Metering is implemented**: an actor-request charge (a **read cost**) is
  computed and deducted from the wallet's GAS balance. Gas is a plain number in
  state; reads debit it; the host refuses to serve when the balance is
  insufficient.
- **Economics is deferred**: there is no way to buy/earn/transfer GAS, no
  pricing curve, and no relationship between GAS and real value.

Design consequence: **gas accounting is deterministic and on-chain
(authorized)**; **execution is not** (§7.5). The host meters per request, but
the authoritative balance must live where it is tamper-proof — L1 (a native op
that debits the DID's gas) — otherwise a client/host could lie about its own
usage. A local, unsigned counter is fine for a demo but is not the real thing.
So v1 has a fork: (a) accept a host-local counter as a placeholder, or (b) add
an L1 `DebitGas` op and make the host submit it. (b) is the honest path but
couples v1 to L1 writes, which v1 otherwise avoids.

### 11.4 Minimal request path (sketch)

`app → HTTP POST [one JSON endpoint] → jkainc: parse JSON → verify caller
signature → charge/deduct GAS → extract actor_id → Runtime::dispatch(actor_id,
body) → actor handle-request → reply bytes → JSON response → app decodes → app
writes its local SQLite cache`. No discovery, no actor-to-actor routing, no
streaming; TLS at the transport if exposed beyond localhost.

### 11.5 Hosting model (v1)

One actor, manually placed, **singly hosted** — so the **replication/state
model (§7.5) is not a v1 blocker** as long as the actor is treated as the single
authority for its data. Re-visit when actors become multi-tenant or replicated.
