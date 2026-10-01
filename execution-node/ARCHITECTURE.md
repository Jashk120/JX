# Architecture — execution-node

The compute node's deep dive. For the monorepo map see `../ARCHITECTURE.md`;
for the consensus node see `../consensus-node/ARCHITECTURE.md`.

## Position in the system

```text
jkaind (L1, Rust)              jkainc (compute node, Rust)
  hashgraph consensus            no consensus participation
  deterministic executor   <--   read-only queries (§6.3.1)
  checkpoints / state            signed transaction submission
  DID + actor layer               actor hosting (WASM) + storage
```

A compute node is not a Layer 2: there is no batching of compute-layer
activity into proofs settled back to L1. It is a second cooperating node type
on the same chain — L1 supplies identity, ordering, and coordination; the
compute node supplies execution, entirely off the consensus path.

## Crate stack

```text
l1/client    the §6.3.1 boundary (reads + submits; never authorizes)
    ↑
runtime/actor-host   manifests, WASM runtime, blob/storage boundary
    ↑
node         the jkainc daemon: config, lifecycle, wiring
```

Crates live under role directories (`l1/`, `runtime/`), matching
`consensus-node/`'s `protocol/` + `executor/` convention. Each umbrella
directory and each crate has its own `README.md`.

Both `l1-client` and `actor-host` depend on `state` (the L1 executor crate)
for the actor identity and commitment types. That shared dependency is the
point of the Rust choice: one decoder for the L1 wire format.

## The L1 boundary (whitepaper §6.3.1)

Governing rule: **compute nodes must always defer authorization decisions to
L1, never re-derive them independently.** L1 is the sole source of truth for
ledger state. A compute node's L1 surface is therefore bounded to:

- **Read-only queries** — DID resolution, the compute-node registry, the
  DID-to-location mapping, and asking L1 for an authorization decision.
- **Constructing and submitting signed transactions** — self-registration,
  heartbeat, and location updates, using L1's existing formats.

Planned over gRPC. Both categories are thin and static, which is what keeps a
second implementation from drifting.

## Blocking design questions

### 1. Replication model — §6.4 contradicts the V3 notes

The whitepaper (§6.4) describes state **replicated across a small set of
reachable locations** (including the user's own devices), with migration as a
**cold-start from replicated state** and reconciliation via last-write-wins or
vector clocks.

`docs/V3_Compute_Layer_Notes.md` §4 describes a different system: **2–3
replicas, active-passive single-writer**, migration via a **redirect/forwarding
pointer**, and failover by promoting a passive replica — with promotion
quorum/split-brain named as "the most important unresolved item."

These are not compatible. The notes themselves flag that they contradict
§6.4. This must be resolved before storage exists, because it defines what a
compute node's local store *is*: a replica to be reconciled, or a passive
backup to be promoted.

### 2. Link `state` or go over gRPC

§6.3.1 specifies gRPC. But a Rust compute node *could* link the `state` crate
directly for reads and skip the wire boundary. The trade:

- **Link**: shared types, no duplicated decoding, but couples the compute node
  to the L1 crate graph and its version.
- **gRPC**: clean boundary matching §6.3.1, at the cost of building the client.

The likely answer is both — gRPC for the transport, `state` linked for
decoding — but it is not decided.

## Deferred (whitepaper §6.7)

Compute-provider compensation and metering are explicitly out of scope by
deliberate choice, which is why the actor layer has no value/account model.
Versioning and DDoS are likewise deferred.
