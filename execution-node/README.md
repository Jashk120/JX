# execution-node

Off-chain **actor compute** for JKaIN: a second, cooperating node type that
hosts and executes actors. It does **not** participate in hashgraph consensus —
L1 nodes provide identity, ordering, and a coordination substrate; compute
nodes provide execution (whitepaper §6.3).

This project is a **scaffold**. The crate layout and the L1 boundary shape are
in place; the runtime and transport are not.

## Role

- Hosts per-user actors as WebAssembly components (§6.3.2).
- Keeps raw networking out of the sandbox: the host receives messages and
  dispatches them into an actor via host function calls.
- Treats compute as a replaceable resource — the DID stays the permanent
  identifier (§6.2).
- Defers every authorization decision to L1; it never re-derives ledger state
  independently (§6.3.1).

## Why Rust, not Go

Whitepaper §6.3.1 planned compute nodes in Go. That is reversed here: compute
nodes are Rust.

The decisive reason is the L1 integration boundary. §6.3.1 requires compute
nodes to always defer authorization to L1 and never form a second opinion
about ledger state. The L1 wire format — the `0xD1`/`0xA1` reserved state
keys, the RFC-6962 membership proofs, and the domain-tagged actor-op signed
payloads — is defined only in Rust, in the `state` crate. A Go compute node
would have to re-implement the decoding of those bytes, which is exactly the
duplicated-logic risk §6.3.1 warns about. A Rust compute node links the
`state` crate and decodes with the same code that produced the bytes.

Secondary reasons: one toolchain, one CI matrix, and one dependency-audit
story for a single-developer project; and `wasmtime` (the §6.3.2 runtime) is
itself Rust, so the actor host uses the reference implementation natively.

The §6.3.1 concurrency argument — goroutines suiting actor hosting — does not
transfer as stated: each actor is a separate sandboxed instance with its own
memory, so the model is a scheduler over isolated instances, not a
shared-state concurrent program.

## Layout

```text
execution-node/
  Cargo.toml            # [workspace] members = l1/client, runtime/actor-host, node
  rust-toolchain.toml   # pins the same toolchain as consensus-node
  rustfmt.toml
  l1/                   # umbrella: the §6.3.1 L1 integration boundary
    README.md
    client/             # read-only queries + signed transaction submission
  runtime/              # umbrella: off-chain actor hosting
    README.md
    actor-host/         # manifests, the WASM runtime, the storage boundary
  node/                 # the jkainc daemon (wires the crates to a lifecycle)
  README.md
  ARCHITECTURE.md
```

Crates sit under a role directory (`l1/`, `runtime/`) rather than a generic
`crates/`, matching `consensus-node/`'s `protocol/` + `executor/` convention.
Each umbrella directory and each crate carries its own `README.md`.

## Build

```bash
cd execution-node
cargo build --workspace
cargo +nightly fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
```

## Status

| Piece | State |
|---|---|
| `l1-client` boundary traits | scaffold (no transport) |
| `actor-host` hosting runtime | local hosting (`Runtime` loads WASM components per `wit/actor.wit`, dispatches `handle-request`) |
| `jkainc` daemon | scaffold (exits with "not implemented") |
| location/resolution (Phase C) | not started — prerequisite for reachability |
| replication/state model (§6.4 vs V3 notes) | **unresolved** |

Two design questions block real implementation and are recorded in
`ARCHITECTURE.md`: the §6.4 / V3-notes replication contradiction, and whether
reads link the `state` crate directly or go over gRPC.

## Documents

- [`../docs/JKain_Whitepaper.md`](../docs/JKain_Whitepaper.md) §6 — the compute layer.
- [`../docs/V3_Compute_Layer_Notes.md`](../docs/V3_Compute_Layer_Notes.md) — non-normative notes (contains unresolved items and an active contradiction with §6.4).
- [`../.omo/plans/PLAN-5-actor-layer.md`](../.omo/plans/PLAN-5-actor-layer.md) — the actor layer; Phase D covers compute-node execution.
