# JKaIN

A consensus-critical blockchain node implementing the virtual-voting
Hashgraph algorithm. Events gossip over pinned-TLS TCP, order through
round-based virtual voting, and execute deterministically into a shared
key-value state.

## Workspace layout

```text
protocol/     consensus-critical network layer
  primitives/   value types (zero dependencies)
  crypto/       hashing, signing, membership
  consensus/    virtual-voting Hashgraph: rounds, fame, order, checkpoints
  gossip/       pinned-TLS gossip network + GossipNode runtime
executor/     deterministic execution layer
  state/        pure executor over the consensus order
node/         the jkaind daemon: config, persistence, restart recovery
```

## Documents

- `JKain_Whitepaper.md` — the design whitepaper.
- `JKain_Consensus_Spec.md` — the consensus algorithm specification
  (`protocol/consensus` implements it).
- `ROADMAP.md` — phased roadmap (Phase 8 = deterministic executor).
- `V3_Compute_Layer_Notes.md` — compute-layer design notes.
- `AGENTS.md` — development rules for contributors and AI agents.

## Building and testing

```bash
cargo build --workspace

# Formatting uses the nightly formatter (never stable cargo fmt).
cargo +nightly fmt --all

cargo clippy --workspace --all-targets
cargo test --workspace
```

## Running a cluster

```bash
# Generate secrets + shared config for a two-node cluster.
cargo run --bin jkaind -- init \
  --member 1:203.0.113.5:7000:203.0.113.5:7001 \
  --member 2:203.0.113.6:7000:203.0.113.6:7001 \
  --out ./cluster

# Run one node.
cargo run --bin jkaind -- run \
  --cluster ./cluster/cluster.toml --node-id 1 \
  --secret ./cluster/secret-1.bin --data ./data
```

See `node/RUNBOOK.md` for the full 2-VPS deployment.
