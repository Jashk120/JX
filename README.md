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

## Benchmarks — 6-node direct LAN (2026-08-29, Arch 15.2G, `sync_interval 25ms`)

Live `tests/harness/` on `consensus-node/target/debug/jkaind` (`cargo build --workspace`, `rambo` protected). See `tests/README.md` for harness + `pytest -m smoke|finality|tps`.

### Lowest latency (isolated, `concurrency=1`)

`measure_finality_batch(20, conc=1)` — `submit→ordered` (gossip) 100%, `ordered→decided` <50ms (virtual voting), `decided→checkpoint` 2s grace.

| metric | value |
|---|---:|
| p50 decided | 0.536s |
| p95 decided | 1.14s |
| p99 decided | 1.82s |
| mean decided | 0.72s |
| gossip p50 (submit→ordered) | 0.536s |
| consensus p50 (ordered→decided) | 0.000s |
| best single tx | **0.210s** |

### Highest throughput (sustained, round-robin 6 nodes, `decided` finality)

| total | conc | submit TPS | **decided TPS** | submit_dur | decided_dur | rounds |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 20 | 10,512 | **471** | 0.05s | 1.06s | 1→3 |
| 1,000 | 30 | 8,519 | **890** | 0.12s | 1.12s | 1→3 |
| 1,500 | 30 | 9,934 | **1,298** | 0.15s | 1.16s | 1→3 |
| 2,000 | 40 | 10,479 | **1,673** | 0.19s | 1.20s | 1→3 |
| **2,500** | **40** | **10,474** | **2,002** | **0.24s** | **1.25s** | 1→3 |

Peak **2,002 TPS decided (10,474 TPS submit) @ 2,500tx conc40** — `MAX_PENDING 1024` per node ×6.

### Event gap 80ms (prod default) vs 250ms vs 500ms — projection

Gap = `ClusterConfig(sync_interval_ms)` / `node/src/cli/run.rs:DEFAULT_SYNC_INTERVAL 80ms`. Latency ≈ `k·gap·logN`, Throughput ≈ `64·6/gap·0.13`.

| sync_interval | vs 25ms | **latency p50** | **decided TPS** | submit TPS | `k10temp` |
|---:|---:|---:|---:|---:|---:|
| **25ms** (harness) | 1× | **0.54s** | **2,002** | 10,474 | 90-97°C (rambo kill unless `protect`) |
| **80ms** (prod `DEFAULT_SYNC_INTERVAL`) | 3.2× | **~1.7s** | **~625** | ~3,270 | ~70°C |
| **250ms** | 10× | **~5.4s** | **~200** | ~1,047 | ~50°C |
| **500ms** | 20× | **~10.7s** | **~100** | ~523 | ~45°C |

Verify: `ClusterConfig(num_nodes=6, sync_interval_ms=80)` / `250` / `500`.

### Concurrent fanout k=4 (T12, N=6, `sync_interval 25ms`, `FanoutMode::Auto`)

`tokio::JoinSet` + `Semaphore(k)` fanout, `PeerManager::pick_k` scored selection, `LruCache` hot-pool `10@N=6`, per-peer `DedupState` (`self 1000 ms / ancestor 250 ms / non-ancestor 3000 ms`), `GossipMetrics` (`p50/p95_rtt`), QUIC `QuicTransport` (`quinn`+SPKI, TCP fallback).

| fanout | transport | dedup | **p50 decided** | vs k=1 (0.54s) |
|---|--- |---|---:|---|
| **k=1** (baseline, serial TCP) | TCP | off | **0.54s** | 1× |
| **k=4 auto** (`effective_k(6)=4`, `ratio 0.6`, `JoinSet+Semaphore`) | TCP | off | **~0.35s** | ~1.5× faster |
| **k=4 auto** | **QUIC** (`quinn`+SPKI) | off | **~0.25s** | ~2.2× faster |
| **k=4 auto** | **QUIC** | **on** (`SyncConfig 1000/250/3000 ms`) | **~0.20s** | ~2.7× faster |

Fanout `k` from `FanoutMode::Auto` (`protocol/gossip/src/peer_manager.rs:effective_k`): `k=ceil(N*ratio)` clamped to `[k_min,k_max]`, `ratio 0.6@N≤10 → 0.3@N≥30`, `k_max 4@N=6, 12@N=100`.

Verify: `FanoutMode::Auto` at `N=6` (`effective_k=4`) / `cargo test --workspace -- --nocapture fanout`.
