# JKaIN — Monorepo

JKaIN is a multi-project monorepo. Each product lives in its own top-level directory with its own `Cargo` workspace (or build system) and toolchain.

## Layout

```text
JKaIN/
  consensus-node/   Hashgraph consensus node (Rust workspace) — see consensus-node/README.md
    protocol/         consensus-critical network layer (primitives, crypto, consensus, gossip, storage, stream)
    executor/         deterministic execution layer (state + DID)
    node/             jkaind daemon (config, persistence, restart recovery)
    cluster-init/     example genesis cluster.toml + secrets for local deploy
    Cargo.toml        workspace manifest (resolver = 3)
    Cargo.lock, rust-toolchain.toml, rustfmt.toml
    README.md, ARCHITECTURE.md
  proto/            Shared protobuf schemas (jkain_stream.proto for mirror streams)
  docs/             Whitepaper, consensus spec, DID method, optimization notes (shared)
  .github/          CI / release workflows (run inside consensus-node via working-directory)
  AGENTS.md         Development rules for contributors & AI agents (repo-wide)
  ROADMAP.md        Phased roadmap (currently consensus-node focused)
```

Additional projects will be added alongside `consensus-node/` (e.g. `mirror-node/`, `sdk/`, `frontend/`).

## Working with consensus-node

All Rust commands run **inside** `consensus-node/`:

```bash
cd consensus-node

cargo build --workspace
cargo +nightly fmt --all            # never use stable fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace

# or from repo root without cd:
cargo test --manifest-path consensus-node/Cargo.toml --workspace --locked
```

The node's binary is `jkaind`:

```bash
cd consensus-node
cargo run --bin jkaind -- --help
cargo run --bin jkaind -- init --member 1:127.0.0.1:7000:127.0.0.1:7001 --out ./cluster
cargo run --bin jkaind -- run --cluster ./cluster/cluster.toml --node-id 1 --secret ./cluster/secret-1.bin --data ./data
```

See `consensus-node/README.md` for the full cluster/runbook and `consensus-node/ARCHITECTURE.md` for the gossip-sync walkthrough.

## CI

`.github/workflows/ci.yml` and `release.yml` set `defaults.run.working-directory: consensus-node` so formatting, clippy and tests run against `consensus-node/Cargo.toml`. `rust-toolchain.toml` and `rustfmt.toml` are intentionally inside `consensus-node/` — each project owns its toolchain.

## Docs

- `docs/JKain_Whitepaper.md` — design whitepaper
- `docs/JKain_Consensus_Spec.md` — consensus spec (implemented by `consensus-node/protocol/consensus`)
- `docs/DID_method.md` — `did:jkain` method spec
- `docs/OPTIMIZATION.md` — scaling design (locked)
- `AGENTS.md` — contributor / AI-agent rules
- `ROADMAP.md` — roadmap
