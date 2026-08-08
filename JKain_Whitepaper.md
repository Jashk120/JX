# JKain
### A Hashgraph-Consensus Ledger with Native Identity, Assets, and a User-Owned Compute Layer
**Working Draft — v0.1**

---

## Abstract

JKain is a distributed ledger built on hashgraph consensus (gossip-about-gossip and virtual voting), providing deterministic, non-probabilistic finality and fork-resistance by construction. It brings together, as first-class protocol services rather than smart-contract afterthoughts: a native consensus timestamping service (HCS), a native token service (HTS), a native decentralized identity layer (DID), a market-based fee model driven by on-chain time-weighted average pricing, and account-level programmable authorization.

Beyond the base ledger, JKain's long-term vision (v3) extends the same DID-based identity primitive to compute itself — introducing a compute layer of user-owned, DID-anchored actors, coordinated (but not executed) by the same chain's consensus nodes. This document describes the completed design reasoning for v1 through v3.

This is a personal research and learning project. It is not built for commercial deployment, token value, or external users. It exists to deeply understand distributed consensus, applied cryptography, and decentralized identity by building all three from first principles.

---

## Table of Contents

1. Motivation and Design Philosophy
2. Core Architecture (v1 Foundation)
3. v1 Features — Native Services
4. v1.5 — Privacy Layer
5. v2 Features
6. v3 — The Compute Layer: User-Owned Actors
7. Explicitly Rejected Features
8. Open Questions and Known Limitations
9. Closing Notes

---

## 1. Motivation and Design Philosophy

Most educational and hobby blockchain projects either reimplement an existing chain closely (a Bitcoin or Ethereum clone) or build a toy consensus mechanism disconnected from any real application layer. JKain takes a different approach: build a genuinely different consensus mechanism (hashgraph, rather than Nakamoto-style PoW/PoS chains) and treat several capabilities that most chains bolt on via smart contracts — identity, tokens, ordered messaging, scheduled execution — as native, first-class protocol operations instead.

The guiding design principle across every decision in this document has been **coherent scope over feature count**. Many capabilities from other chains were considered and deliberately rejected (see Section 7) not because they lack merit, but because they would either duplicate functionality already provided elsewhere in the design, or introduce architectural conflicts with features already committed to as core.

A second principle, which shaped the versioning strategy throughout: **build order should follow provable engineering difficulty, not feature excitement.** Novel cryptographic research (v3's original zero-knowledge construction) and the far larger ambitions of v3's compute layer are sequenced last, after the foundational system is complete and well-understood, specifically so that later, harder work is built on top of deep familiarity with the base system rather than guesses about it.

---

## 2. Core Architecture (v1 Foundation)

### 2.1 Consensus: Hashgraph

JKain uses hashgraph consensus: nodes gossip transaction and event data to random peers ("gossip about gossip"), and each node independently derives a total ordering of events using virtual voting over the resulting directed acyclic graph (DAG) of gossip events. Unlike leader-based or longest-chain consensus mechanisms, hashgraph provides:

- **Deterministic finality.** Once virtual voting resolves an event's consensus order, that order is final — not probabilistically final after N confirmations, but final by mathematical proof over the gossip graph structure.
- **Fairness in ordering.** Consensus timestamps are derived from the median timestamp at which nodes received an event, making transaction-ordering manipulation (e.g., front-running by a block producer) structurally harder than in leader-election chains.
- **No forks by construction.** Because ordering emerges from graph structure rather than a race to produce the next block, there is no "longest chain" to contest.

Note on precision: hashgraph does not confer immutability that other correctly-implemented consensus mechanisms lack — any properly finalized ledger, regardless of consensus algorithm, is immutable after finality. Hashgraph's actual differentiators are deterministic (rather than probabilistic) finality, ordering fairness, and structural fork-resistance.

*(Historical note: hashgraph's core algorithm was patent-encumbered by Swirlds, Inc. until January 2022, when the Hedera Governing Council purchased the IP rights and open-sourced the implementation under Apache 2.0. As of this writing, implementing hashgraph-style consensus carries no patent risk.)*

### 2.2 Networking Layer

A peer-to-peer gossip layer handles event propagation between nodes. Transaction submission has no separate broadcast mechanism — submitted transactions enter the gossip stream as part of normal event exchange, the same mechanism used to propagate consensus-relevant data generally.

**Transport protocol choice is deliberately differentiated by traffic type, rather than using one protocol everywhere:**

- **Hashgraph gossip (node-to-node, L1-internal)** — raw TCP with TLS 1.3 (rustls) and length-prefixed canonical frames. This is the single hottest, highest-frequency, most latency-sensitive path in the system, and it is also where consensus correctness is most safety-critical. A conservative, well-understood transport is deliberately chosen here rather than layering on additional protocol machinery (e.g., gRPC/HTTP framing) whose overhead isn't worth paying on this path, and rather than adopting a newer transport (e.g., QUIC) whose maturity risk isn't worth taking on the most safety-critical part of the whole system. Each node's TLS identity derives from a durable Ed25519 seed (a self-signed X.509 certificate is re-wrapped from it at startup and is disposable); peers pin connections by comparing the presented certificate's SPKI fingerprint against their address-book entry, authenticating nodes independently of the consensus key registry. Implemented in the `gossip` crate (see Consensus Spec §5).
- **Compute-node ↔ L1 coordination** (registry reads, DID resolution, transaction submission — see Section 6.3) — gRPC over TCP. This traffic benefits from typed, code-generated contracts and built-in streaming support, and is not latency-critical enough to justify hand-rolled framing.
- **External API** (third-party callers, client applications) — conventional HTTP (JSON or gRPC-Web), prioritizing broad compatibility and ease of integration over raw performance.
- **Actor-to-actor and client-to-actor messaging** (compute layer, Section 6.6) — QUIC. Actor messaging involves many independent, short-lived messages between dynamically-relocating actors; QUIC's per-stream multiplexing (avoiding head-of-line blocking, unlike TCP, where one lost packet stalls all data behind it) and faster connection establishment are a materially better fit for this pattern than TCP-based alternatives.

### 2.3 Account Model

JKain uses an account-based model (balances and state attached to persistent account identifiers) rather than a UTXO model (Bitcoin-style discrete spendable outputs). This choice was made deliberately: JKain's native DID and token-association features are naturally account-centric, and do not map cleanly onto a UTXO structure.

### 2.4 Transaction Format

Every transaction carries:

| Field | Purpose |
|---|---|
| `authorizer` | An `AuthorizerSet` — either `Single(AccountId, Signature)` or `Threshold(Vec<AccountId>, threshold_count, Vec<Signature>)`. Chosen per-account at creation, and mutable thereafter (see 2.5). |
| `fee_payer` | A separate account, distinct from the authorizer, responsible for the transaction fee. Must co-sign or pre-authorize, preventing arbitrary accounts from being named as an unwilling fee payer. |
| `payload` | A versioned enum describing the operation (transfer, token operation, DID operation, HCS message, schedule-create, authorization change, etc.). Versioning is included from v1 so new operation types can be added without breaking deserialization of historical transactions. |
| `signatures` | A structured collection supporting both single-signer and threshold multi-signer verification. |
| `nonce` | Sequence number for replay protection. |
| `schedule_expiry` | Optional; populated only for scheduled transactions (Section 3.5). |
| `access_list` | Optional, unused in v1, reserved for the parallel execution model planned in v2 (Section 5.1). |

**Design rationale for separating `authorizer` and `fee_payer`:** this decouples "whose action this is" from "who pays for it," enabling sponsored-transaction patterns (Section 3.6) without any special-casing in the base transaction structure.

**Design rationale for user-selectable single vs. threshold authorization:** rather than hard-coding multi-signature requirements only for scheduled transactions, JKain treats authorization scheme as a property of the *account*, chosen by the user and applicable to any transaction type. This mirrors how most production account-based chains actually implement multi-sig, and keeps "is this transaction scheduled" fully orthogonal to "does this account require multiple signatures."

### 2.5 Mutable Account State Over an Immutable Ledger

A recurring design question throughout this project was how to reconcile "the ledger must be immutable" with "accounts clearly need to change over time" (balances, token associations, and — notably — authorization rules themselves).

The resolution: **ledger history is immutable; current account state is a derived, mutable value.** Every change to an account, including a change to its own authorization scheme (e.g., converting from single-key to a 2-of-3 threshold), is itself a transaction — authorized under the account's *current* rules at the time of the change, gossiped, ordered by consensus, and permanently recorded. The ledger never forgets that an account was single-key before a given point and threshold-based after it. What changes is the account's *current* effective state, computed as the result of folding its full transaction history — precisely the same pattern already used for something as ordinary as balance updates.

This means account authorization can safely evolve (key rotation, adding co-signers, recovering from a lost key) without ever compromising the immutability guarantee that matters: nobody can rewrite what happened.

### 2.6 Storage Model

Each node persists state in an embedded key-value store (LSM-tree-based, e.g., RocksDB or a Rust-native equivalent such as `sled`), holding two logically distinct categories of data:

- **Immutable event/transaction history** — append-only, growing indefinitely by default in v1.
- **Current state** — a fast-lookup snapshot (account balances, token associations, DID documents, authorization rules) computed from and kept consistent with the immutable history, avoiding the need to replay full history on every query.

**On unbounded growth:** every full node storing complete history is what makes the network trustless, but it is a real, actively-managed problem on every production chain (Bitcoin's chain exceeds 650GB; Ethereum archive nodes run into multiple terabytes). JKain v1 deliberately does not implement pruning or archival tiering — this is named explicitly as a known limitation, with Hedera-style state expiry/rent (Section 5, rejected features discussion) identified as the production-grade solution path, deferred rather than built.

**On node failure and recovery:** because every honest node independently derives and stores full state from the gossip protocol, no single node's disk is authoritative. A node that loses its disk entirely can rejoin the network and fully resynchronize from peers. This property is planned as an explicit, demonstrable test of the architecture (kill a node, wipe its storage, observe successful resync).

**On storage hardware:** JKain nodes are designed for SSD/NVMe storage, consistent with every major production chain (Ethereum, Hedera, Solana). The workload — an LSM-tree key-value store under constant random-access read/write load from consensus and state queries — is specifically the access pattern HDDs handle poorly. Concerns about SSD write-cycle degradation are not a practical constraint at the write volumes of a node at this project's scale; durability, where it matters, is properly addressed through node redundancy rather than choice of a slower storage medium.

### 2.7 Determinism Requirement

Because every honest node executes every transaction independently and must arrive at identical resulting state, all execution logic must be strictly deterministic: no floating-point arithmetic in consensus-critical paths, no reliance on hashmap iteration order, no wall-clock time in execution logic, no thread-scheduling-dependent behavior. A non-deterministic execution layer would cause nodes to silently disagree on state even when consensus on *ordering* is functioning correctly — this is treated as a first-class correctness requirement from the start of implementation, not a bug class to catch later.

### 2.8 Modular Architecture

Following a Cosmos-SDK-inspired philosophy, JKain's codebase is organized into independent modules with clean interfaces — consensus core, HCS, HTS, DID, fee engine, and scheduling as separable crates. This is treated as an ongoing architectural discipline from the first commit, not a phase of work, and is what allows new operation types or features to be added later without the codebase degrading into unmaintainable cross-dependencies.

### 2.9 Formal-Verification-Friendly Discipline

Full formal verification of the implementation is a deferred goal (see Section 9), but v1 code — particularly consensus-critical logic such as event ordering, virtual voting, and signature/authorization validation — is written with verification tooling in mind from the outset: preferring pure functions, minimizing `unsafe` blocks, and documenting invariants explicitly even before they are formally specified. This avoids a costly retrofit later, at near-zero cost now.

---

## 3. v1 Features — Native Services

### 3.1 Hedera Consensus Service (HCS) Equivalent

An ordered, timestamped message/topic log, exposed as a native protocol service. This falls out almost directly from the consensus layer itself — HCS is, in essence, the consensus-ordered event stream exposed as a general-purpose primitive applications can write arbitrary messages into, rather than something requiring its own separate consensus mechanism.

### 3.2 Hedera Token Service (HTS) Equivalent

Native fungible and non-fungible token operations (create, mint, burn, transfer) implemented as protocol-level operations rather than smart contracts. Following Hedera's model, token association is explicit and opt-in per account — an account must actively associate with a token before it can hold or receive it, preventing unsolicited token spam.

### 3.3 Native DID Layer

Decentralized identifiers and associated documents are a native, first-class protocol service, not a smart-contract-based add-on. This is the area of the project with the most directly applicable existing expertise, given prior production work on Hiero's DID SDK ecosystem and cross-SDK AnonCreds interoperability testing.

### 3.4 Fee Model: On-Chain TWAP Pricing

Rather than fees denominated purely in the native token (subject to full price volatility, as in Bitcoin) or fees pegged via an external price oracle (introducing an external trust dependency), JKain computes fees using a **time-weighted average price (TWAP)** derived entirely from on-chain trading data.

This requires a minimal constant-product automated market maker (AMM) primitive, seeded with token trading activity, from which the TWAP is computed over a rolling window — the same general mechanism used by on-chain price oracles such as Uniswap's. This keeps fee-price smoothing self-contained within the ledger's own data, without introducing external oracle infrastructure (a substantial, separate trust and security problem in its own right, deliberately out of scope — see Section 7).

Different operation types (transfer, token creation, DID operation, etc.) carry different base fee schedules, following Hedera's model of cost reflecting operational weight rather than a flat per-transaction fee.

### 3.5 Scheduled Transactions

Transactions may be submitted without full authorization and held in a **pending-signature pool**, distinct from the standard transaction mempool, executing automatically once the account's required signature threshold is met or a specified deadline passes.

Design requirements:

- A pending-transaction pool separate from normal in-flight transactions.
- A signature-threshold model attached at the account level (Section 2.4/2.5), not the transaction level — any account, single-key or threshold, may submit a scheduled transaction.
- An explicit expiry (`schedule_expiry` field), with cleanup on lapse — directly related to the unbounded-storage-growth concern in Section 2.6.
- An explicit decision on whether HCS timestamps the scheduling event, the execution event, or both (Hedera timestamps these as separate events; JKain follows the same separation).

### 3.6 Fee-Payer Delegation (Sponsored Transactions)

By decoupling `authorizer` from `fee_payer` in the base transaction format (Section 2.4), JKain natively supports sponsored transactions — a third party covering transaction fees on behalf of a user. This directly addresses a real onboarding gap in identity-centric systems: a newly created DID should not need to already hold native tokens simply to pay for the transaction that establishes its own identity.

The fee payer must co-sign or otherwise pre-authorize being charged, preventing an attacker from naming an arbitrary unwilling account as fee payer.

**Interaction with scheduled transactions:** a scheduled transaction using fee-payer delegation requires two independent signature-collection processes tracked against the same pending object — the authorizer's threshold, and the fee payer's authorization — modeled explicitly rather than merged, since they are logically separate approvals.

---

## 4. v1.5 — Privacy Layer

### 4.1 Design Problem

A fully public ledger — where HCS orders and timestamps every transaction visibly, and every HTS/DID operation is attributable — is in direct tension with transaction privacy. Naively adding Monero/Zcash-style privacy would conflict with HCS's ordering model, HTS's association tracking, and the DID layer's entire purpose (provable, attributable identity is close to the opposite goal of unlinkability).

### 4.2 Resolution: Separating Ordering from Content

The key insight resolving this tension: **HCS requires that something orderable exist and be timestamped — it does not require that the content be visible.** JKain's shielded pool is architected as follows:

- A shielded transaction is represented on-chain as an opaque cryptographic commitment — HCS timestamps and orders the existence of this commitment exactly as it would any other transaction, without seeing sender, receiver, or amount.
- Transaction validity (sufficient balance, no double-spend) is proven via a zero-knowledge proof (zk-SNARK) attached to the commitment, using an established proving system (`halo2` or `bellman` in Rust) rather than custom cryptography.
- The shielded pool is architected as a **separate transaction pool**, parallel to — not merged with — the transparent HTS/DID transaction model. This mirrors Zcash's transparent/shielded pool separation, and is what prevents the privacy layer from breaking the account-association and attribution guarantees the transparent side depends on.

### 4.3 Credential-Gated Access via AnonCreds

JKain's existing DID layer already supports AnonCreds-style selective-disclosure credentials. These serve a complementary, distinct role from the SNARK-based transfer privacy: AnonCreds can gate **who** is permitted to transact within the shielded pool (e.g., proving possession of a compliance credential without revealing which account holds it), while the SNARK proves the **transfer itself** is valid. These are not substitutes for one another — AnonCreds does not provide private balances or transfers on its own, and the SNARK construction does not provide credential-based access control on its own.

### 4.4 Known, Accepted Limitation

The on-chain TWAP fee oracle (Section 3.4) derives its price data from visible trading activity. Shielded-pool trades are, by design, invisible to this mechanism. Shielded transactions therefore fall back to the last-known transparent-pool price for fee computation. This is not an oversight to be engineered away — it is an inherent tradeoff of transaction privacy, and is documented here explicitly rather than left implicit.

---

## 5. v2 Features

### 5.1 Parallel Transaction Execution

Modeled on Solana's Sealevel runtime: transactions declare their state access requirements upfront (the reserved `access_list` field from Section 2.4), allowing the execution engine to schedule and run non-conflicting transactions concurrently rather than sequentially.

This is architecturally distinct from — and complementary to — hashgraph's contribution. Hashgraph consensus solves *how fast can nodes agree on transaction order*; parallel execution solves a separate problem, *given agreed order, how fast can transactions be executed*. The two are not competing solutions to the same bottleneck, which is what makes combining them coherent rather than redundant.

This is flagged as the single highest architectural-risk item in v2 outside the shielded pool, because it constrains the transaction format decided in v1 — hence the field being reserved from the beginning rather than retrofitted.

### 5.2 Subnets

Following Avalanche's model: independent, purpose-specific sub-chains that share security and validator resources with the primary JKain network. Treated as a scaling/isolation feature, deliberately deferred past v1 since a single-chain deployment does not yet need this.

### 5.3 Inter-Blockchain Communication (IBC)

Following Cosmos's model: standardized cross-chain messaging via light-client verification of a counterparty chain's consensus state. This is explicitly acknowledged as blocked on a **hashgraph light client** — a component with essentially no existing prior art, even within Hedera's own ecosystem. IBC is scoped as a research problem to be tackled when reached, not a conventional engineering task with a known solution shape.

---


## 6. v3 — The Compute Layer: User-Owned Actors

*This section is written with more conceptual detail than a typical "future vision" appendix, at the user's explicit request — the underlying idea has been reasoned through in real depth, even though implementation remains deliberately deferred until v1 through v3 exist and their real constraints are understood firsthand. It should be read as a well-developed design direction, not yet a locked specification.*

### 6.1 The Problem

In essentially every application platform today, a developer who builds an application also ends up owning and operating the infrastructure that runs it for every user — the backend, the database, the hosting. Users' data and compute live inside infrastructure they do not control and cannot take with them. Cross-application interoperability, where it exists at all, is mediated by centralized account systems, OAuth flows, and API keys controlled by each individual platform. Even federated alternatives such as Matrix, which explicitly aim to decouple communication from centralized control, still tie a user's identity to the specific homeserver they registered on — if that homeserver disappears, the identity becomes unreachable, since identity and hosting were never fully separated in the first place.

### 6.2 Core Concept: Actors, Not Servers

JKain's compute layer is built around the **actor model** (in the Erlang/Akka sense): isolated units of computation with their own private state, communicating exclusively via message-passing, with no shared memory between actors. Each application deploys its own actor type — an actor is not a generic container or a shared runtime service, but application-specific logic written by that application's developer.

When a user installs an application, the network provisions a personal instance of that application's actor, bound to the user's own DID — not to the developer, and not to any single hosting provider. Concretely, using a messaging application as the running example: a message-handling actor for a given user's DID receives incoming messages, stores them, and forwards them to whichever client (phone, PC, laptop) is currently connected — the same actor, reachable identically regardless of which physical device the user is using at the time.

Each actor carries:
- An identity anchored to its owner's DID (Section 3.3) — reusing the existing native identity primitive rather than introducing a parallel one
- Its own private state and storage
- A messaging interface for receiving requests and pushing data to connected clients
- Isolation from every other actor, including other actors belonging to the same user but a different application

Critically, **the DID remains the fixed, permanent identifier for reaching a user's actor; the compute node executing that actor is a replaceable resource.** This directly resolves the gap identified in Section 6.1: identity is never tied to any specific host.

### 6.3 Compute Nodes and On-Chain Registration

A **compute node** is a separate node type, distinct from JKain's consensus (L1) nodes, whose role is to host and execute actors. Compute nodes do not participate in hashgraph consensus; they read from and write to the consensus layer only for coordination purposes, described below. This is not a Layer 2 in the rollup sense — there is no batching of compute-layer activity into proofs settled back to L1. It is more accurately a second, cooperating node type on the same chain: L1 nodes provide identity, ordering, and a coordination substrate; compute nodes provide execution, entirely off the consensus path.

Compute nodes **announce themselves on-chain**, via a new `payload` operation type alongside the existing HTS/DID/scheduling operations (Section 2.4) — reusing the existing transaction and consensus machinery rather than introducing a separate registration mechanism. An announcement carries the node's network address and capability metadata, making it discoverable.

**Liveness via re-announcement:** compute nodes periodically re-announce (heartbeat) to signal they remain reachable. This does not cause unbounded storage growth: the heartbeat *transaction* is gossiped and ordered like any other, but the node's *current state* in the registry is a single, overwritten entry (`node_id → last_seen_timestamp, address, capability_metadata`), not an appended history of every heartbeat. Storage for the live registry therefore scales with the number of compute nodes, not the number of heartbeats sent — the same current-state-vs-history pattern already established for account state (Section 2.6). A staleness threshold (an interval after which a node with no recent heartbeat is treated as unreachable) is a tunable parameter, not an open architectural question.

There is no notion of a marketplace, bidding, or resource purchasing in this design — compute nodes announce availability; there is no buying or selling modeled at this layer. (Whether and how compute providers are compensated is a genuinely open question, addressed in Section 6.7.)

### 6.3.1 Compute Node Implementation and the L1 Integration Boundary

Compute nodes are planned to be implemented in **Go**, deliberately distinct from L1's Rust implementation. This is a considered choice, not a default: Go's concurrency model (goroutines, shared thread pools with request queuing) fits the actor-hosting pattern in Section 6.5 more naturally than Rust's async/await model, and a simpler, single-binary operational story is an advantage for infrastructure third parties are expected to eventually run.

The cross-language boundary is bounded by a governing principle: **compute nodes must always defer authorization decisions back to L1, never re-derive them independently.** L1 is the sole source of truth for ledger state, including account authorization rules (Section 2.5); if a compute node made its own independent judgment about whether a request is authorized, it would constitute a second, unsynchronized opinion about ledger state — precisely the failure mode consensus exists to prevent, and a duplicated-logic security risk in a second language. Concretely, this bounds the L1-integration surface compute nodes actually need to:

- **Read-only queries** — DID resolution, reading the compute-node registry and DID-to-actor-location mapping, and querying L1 for authorization decisions on incoming requests (rather than re-implementing authorization logic locally).
- **Constructing and submitting well-defined, signed transactions** — self-registration, heartbeat, and DID-to-actor-location updates, using L1's existing transaction format and signature scheme (Section 2.4).

Both categories are thin, relatively static, well-scoped surface area, which is what makes a second implementation language a reasonable choice here rather than a source of unmanaged long-term drift. This integration is planned over gRPC (Section 2.2).

### 6.3.2 Actor Implementation: WebAssembly and the Component Model

Actors are compiled to **WebAssembly**, hosted inside compute nodes via a Component-Model-capable runtime (e.g., Wasmtime). This choice is deliberate and preserved even where alternatives (native binaries, a modified WASM) were considered:

- **Sandboxing** — untrusted, third-party-authored actor code runs memory-safe and capability-restricted by construction, without the compute node needing to trust it.
- **Portability** — a compiled actor runs identically across compute nodes regardless of underlying OS/architecture, important given compute nodes are expected to be run by arbitrary, uncoordinated third parties.
- **Networking, without modifying WASM itself** — WASI (the WebAssembly System Interface) provides the networking/IO capabilities WASM itself lacks; WASI Preview 2, with native async I/O support, is stable and sufficient for this purpose, requiring no non-standard changes to WASM.
- **Multi-language authoring** — the WebAssembly Component Model, using WIT (WebAssembly Interface Types) to define actor interfaces in a language-neutral way, allows actors to be authored in Rust, Go (via TinyGo), TypeScript, or Python, each compiling to a conformant WASM component with automatically generated typed bindings. An actor's interface — the operations it exposes — is specified once via WIT; the implementation language is the developer's choice.

Actor-to-actor and client-to-actor message delivery is handled by the compute-node host, not by direct socket access from within an actor's sandboxed WASM instance — the host receives messages on the wire (Section 2.2's QUIC-based actor-messaging transport) and dispatches them into the relevant actor via a host function call. This keeps raw networking capability out of the sandbox entirely, simplifying both the security model and the custom protocol's implementation, which lives solely in host-side code.



Rather than attempting live migration of a running process between untrusted hosts — a difficult, largely unsolved problem even in trusted centralized infrastructure — JKain's compute layer treats migration as **cold-starting a fresh actor instance from replicated state**, sidestepping the harder problem entirely.

An actor's state is replicated across a small set of reachable locations — this may include the user's own client devices (a phone actively holding a working copy of recent state) as well as other compute nodes holding backup replicas. When an actor needs to be (re)started on a new compute node — because its previous host went offline, or for load/availability reasons — the new host pulls state from whichever replica is currently reachable and freshest, reconciling via a standard mechanism (e.g., last-write-wins or vector clocks) if multiple replicas have diverged.

This is best understood as a **synthesis of known distributed-systems primitives** applied to a trust model those primitives were not originally designed for: replicated, reconciled state across multiple locations is a well-established pattern (comparable to Dynamo-style quorum replication or CRDT-based reconciliation), but those systems assume all replicas are operated by a single trusted party for that party's own service availability. Here, replicas may span devices the user owns and compute nodes operated by unrelated, mutually untrusting third parties, anchored throughout to a DID the user — not any operator — controls. This specific combination is not, to current knowledge, an existing named system, even though none of its individual components are new.

**Discovery of where an actor currently lives** follows the same on-chain coordination pattern as compute-node registration: a DID-to-current-actor-location mapping, updated on migration, resolved the same way a client looks up which compute node to reach for a given DID's actor.

### 6.5 Actor Lifecycle

Actors are not permanently resident processes. A compute node runs an actor's logic on request — receive a message, perform work, sleep — using an asynchronous, thread-shared execution model: many actors' work is interleaved on a shared pool of threads rather than each actor consuming a dedicated one, with requests queueing briefly if all threads are momentarily busy.

Actors that receive no requests for an extended period (e.g., three months, as an illustrative threshold) are unloaded from active memory entirely, retaining only their metadata and persisted storage, and are reloaded on demand the moment a new request arrives. This mirrors the cold-start model used by existing serverless/edge-compute platforms (e.g., WASM-based edge runtimes), which is deliberately the closest existing prior art to lean on for this mechanism, rather than treating it as a novel problem.

### 6.6 Discovery, Addressing, and Encryption

- **Inter-actor discovery is explicit, not open.** Actors (and the users behind them) discover one another through an explicit connection step analogous to a "friend request," not automatic open discovery. The underlying addressing mechanism — resolving a DID to its actor's current network location — follows the same registry pattern described in 6.3–7.4.
- **Encryption follows an established, standard pattern:** data is encrypted to the recipient's public key and only decrypted client-side using the corresponding private key held on-device. No novel cryptography is introduced here — this is the same approach already used in JKain's DID/AnonCreds layer (Section 4.3) and in existing systems such as Signal and Matrix's end-to-end encryption.
- **Group communication** (illustrative, theoretical at this stage, using a chat application as the motivating example): a group could hold its own DID and keypair, with the group's private key separately encrypted for each member using that member's individual public key — again, a standard pattern, not a new mechanism, mentioned here only to show the identity model extends naturally to multi-party constructs.

### 6.7 Explicitly Deferred: Versioning, Payment, and DDoS

Several real design questions are identified but deliberately left open at this stage, to keep the project's actual scope honest:

- **Actor/protocol version skew** is resolved by a clear separation between two protocol layers, rather than a single undifferentiated notion of "versioning":
  - **Runtime protocols are standardized** — a small, stable set of operations the runtime itself provides to every actor and client, evolved slowly and carefully since every application depends on them. These include operations such as `DeployActor`, `ResolveDID`, `Heartbeat`, and `MigrateActor`, along with a generic message-delivery primitive (opaque-payload delivery to a given actor, not to be confused with any application's own user-facing "send message" action).
  - **Application protocols are user-defined** — each application's own actor exposes whatever operations make sense for that application, evolving independently and as fast as its developer chooses, entirely isolated from every other application. A messaging application's actor might expose operations like `SendMessage`, `CreateGroup`, and `Reaction`; a calendar application's actor might expose `CreateEvent` and `AcceptInvite` — neither affects the other, and neither affects the runtime layer.

  This means strict backward compatibility only needs to be guaranteed at the runtime layer, where a mismatch would be catastrophic (an old client and a new compute node disagreeing on `Heartbeat` or `MigrateActor` breaks the whole system) — application-layer compatibility is correctly left to each application's own developer to manage, since an application-level mismatch is naturally contained to that one application's actor and clients, and cannot cascade into other applications or the runtime itself.
- **Compute provider compensation and metering are explicitly out of scope for now, by deliberate choice rather than oversight.** Introducing a payment/metering model at this stage would shift the project from an open-ended learning exercise into something carrying real economic and user expectations — pressure the project is intentionally avoiding while it remains a personal research effort. This is revisited only if and when that framing changes.
- **DDoS resistance and other adversarial-network hardening** are not addressed at this stage, consistent with the project's current non-production, non-commercial scope.

### 6.8 Relationship to Existing Systems

The closest existing prior art is Matrix's homeserver model, which already aims at decentralized, user-controlled communication infrastructure but has struggled to fully decouple user identity from the specific server a user registered on. JKain's compute layer differs by starting from DID-native identity as the foundation rather than retrofitting portability onto a server-first design, and by targeting new, purpose-built applications (each with their own actor logic) rather than migrating existing centralized applications onto the platform. Generic decentralized compute platforms (e.g., Akash Network, Flux) are a related but distinct category: they provide commoditized container/GPU rental with no concept of per-user identity-bound, persistent, migratable execution — closer to "cheaper decentralized cloud hosting" than to a personal, identity-anchored compute layer.

### 6.9 Realistic Adoption Path

There is, at present, no strong reason for a developer to choose this model over a conventional server or smart contract — this is acknowledged plainly rather than assumed away. A realistic path to any real-world traction would require, at minimum: usable SDKs (JavaScript and Python are the intended starting points, as thin wrappers around runtime APIs), the project's own developer building and dogfooding real applications on the platform, and genuine outreach/marketing effort — this is treated as a distribution and adoption problem, not merely an engineering one, and is not expected to solve itself by virtue of the underlying technology being sound. The most plausible early audience is privacy- and data-ownership-conscious users and independent developers who would rather build applications than operate and maintain backend infrastructure — a real, if currently small, demonstrated market (evidenced by sustained interest in self-hosted and local-first software), rather than a broad mainstream audience from the outset. Large, advertising-revenue-dependent platforms are correctly expected to have little incentive to adopt a model built explicitly around user data ownership.

### 6.10 Path Forward

The current intent is to continue treating this section as a living design document, refined as understanding deepens, rather than to begin implementation or reserve interfaces for it inside JKain's v1 codebase ahead of time. Any interface stubbed in now, before v1 through v3 are built and their real constraints are known firsthand, would necessarily be a guess rather than an informed extension point.

A lightweight, low-stakes validation of the underlying consensus layer's real-world networking behavior — running a handful of independent nodes across separate hosts and observing live gossip propagation, and separately, hosting a single actor and observing it replicate across nodes — is planned early, independent of and prior to any deeper compute-layer implementation work.

---

## 7. Explicitly Rejected Features

The following were considered during design and deliberately excluded, with reasoning:

- **EVM / general-purpose smart contract VM.** The largest available scope trap: implementing or embedding a full virtual machine teaches nothing specific to hashgraph consensus and duplicates functionality (tokens, identity, messaging) already provided natively and more directly by HTS, DID, and HCS.
- **Real decentralized oracle network.** The on-chain TWAP mechanism (Section 3.4) meets JKain's actual fee-stability requirement without needing an external, trust-dependent price-feed network — itself a substantial, separate distributed-systems and security problem.
- **Governance council / validator staking economics.** Meaningful primarily in the context of a real economic network with real token value; not applicable to a non-commercial research chain with no intended external users.
- **Ethereum's zkEVM-style optional execution proofs (e.g., EIP-8025-style block verification).** This class of feature solves a specific pain point — the cost of every validator re-executing every transaction as a chain scales — that does not apply to hashgraph consensus in the same way, since JKain's ordering does not depend on a shared, re-executed VM in the way Ethereum's does. Importing this would be solving a problem JKain's architecture does not have.
- **Bitcoin-style UTXO model.** Considered and rejected in favor of the account model (Section 2.3), since DIDs and token associations map naturally onto persistent accounts and awkwardly onto discrete unspent outputs.

---

## 8. Open Questions and Known Limitations

Recorded explicitly, rather than left implicit, per the project's design philosophy:

- **State growth is unbounded in v1.** No pruning, archival tiering, or state-rent mechanism is implemented initially. Hedera-style state expiry is identified as the eventual production-grade answer, deferred by design (Section 2.6).
- **Formal verification is deferred, not designed away.** v1 code follows verification-friendly discipline (Section 2.9), but the actual choice of tooling — specification-level model checking (e.g., TLA+, verifiable at any stage with no code changes) versus code-level verification (e.g., `kani`/`creusot`, which benefits from — but does not strictly require — being planned from the start) — remains an open decision, to be made once v1 exists and can be evaluated concretely.
- **Shielded-pool fee pricing has an inherent blind spot** (Section 4.4), accepted as a tradeoff rather than solved.
- **IBC is blocked on a hashgraph light client with minimal existing prior art** (Section 5.3) and is scoped as research, not conventional engineering.
- **v3's novel zero-knowledge construction requires a substantial, separate period of mathematical study** (Section 6) not yet undertaken, and may ultimately be pursued as independent research output rather than strictly as a JKain feature.
- **v3 remains unspecified by design** (Section 6.4) until the foundational system is complete enough to inform it honestly.

---

## 9. Closing Notes

JKain is, first and foremost, a personal, long-horizon learning project — an attempt to genuinely understand distributed consensus, applied cryptography, and decentralized identity by building meaningful, working versions of each, rather than treating any of them as a black box. Its scope is deliberately staged: a complete, coherent v1 before ambition is layered on top, hard research-grade cryptography deferred until the necessary mathematical foundation is actually in place, and its most ambitious, platform-scale idea (v3) held at arm's length as a living vision rather than folded prematurely into a codebase not yet ready to support it.

No part of this project is built with the expectation of external users, adoption, or commercial value. Its measure of success is the depth of understanding gained in building it.
