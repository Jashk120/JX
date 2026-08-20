# Architecture — Monorepo

This file maps the **monorepo** layout. For the consensus node's deep dive (crate stack, gossip sync sequence, finalization, recovery), see `consensus-node/ARCHITECTURE.md`.

## Repo layout

```text
JKaIN/                          # git root — monorepo
  consensus-node/               # Rust workspace: the Hashgraph consensus node
    Cargo.toml                  # [workspace] members = protocol/*, executor/state, node
    rust-toolchain.toml         # pins stable + rustfmt/clippy (consensus-node only)
    rustfmt.toml
    protocol/                   # network layer (primitives, crypto, consensus, gossip, storage, stream, test-support)
    executor/state              # deterministic KV executor + Merkle + did:jkain
    node/                       # jkaind daemon (wires protocol+executor to filesystem)
    cluster-init/               # example genesis cluster.toml + secrets
    README.md                   # node-specific build/run docs
    ARCHITECTURE.md             # node internals deep dive
  proto/                        # shared protobuf schemas (jkain_stream.proto → consensus-node/protocol/stream)
  docs/                         # shared design docs (whitepaper, spec, DID, optimization)
  .github/workflows/            # CI/release — each job sets working-directory: consensus-node
  AGENTS.md                     # repo-wide contributor rules
  ROADMAP.md                    # repo roadmap (currently consensus-node phases)
```

## Why `consensus-node/` owns its toolchain

The monorepo is deliberately **not** a single Cargo workspace. Each top-level project is isolated:

- `consensus-node/rust-toolchain.toml` and `consensus-node/rustfmt.toml` only apply inside `consensus-node/`.
- CI uses `working-directory: consensus-node` / `cache-workspaces: consensus-node` so other projects can pin different toolchains later.
- `node/build.rs` reads `../../.git/HEAD` (repo root) to embed `JKAIN_GIT_HASH` and `protocol/stream/build.rs` reads `../../../proto` — the two cross-boundary references.

## Adding a new project

1. Create `my-project/` at repo root with its own manifest/lock/toolchain.
2. Add its ignores to root `.gitignore` (`my-project/target/` etc.).
3. Add a CI job (or matrix entry) with `working-directory: my-project`.
4. Document it in root `README.md` and this file. No changes to `consensus-node/` required.

## Consensus-node internals (summary)

Full detail lives in `consensus-node/ARCHITECTURE.md:1`. In brief:

- `protocol/primitives` → vocab, `protocol/crypto` → signing/membership, `protocol/consensus` → Hashgraph ordering, `protocol/storage|stream` + `executor/state` → persistence, `protocol/gossip` → pinned-TLS gossip, `node` → daemon lifecycle.
- One gossip sync = `SyncRequest(known frontier)` → `SyncResponse(topo-sorted delta)` → verify+insert → create own `Event(self_parent, other_parent)` → push back.
- Finalization drains finalized rounds → execute → activate `MembershipOp::Add` → checkpoint + `>2/3` quorum → prune.
- Recovery is log-first (`consensus-node/data/eventlog/`), reconnect (`Frame::Behind` / `MissingParent`) is fallback.
