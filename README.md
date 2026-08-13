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

The `:reconnect-addr` part of `--member` is optional — a member given as just
`<id>:<gossip-addr>` runs gossip-only and cannot serve checkpoints to a behind
peer, so the reconnect address is recommended for availability.

## Controlling a running node

`jkaind run` opens a Unix control socket (default `<data>/jkaind.sock`) so a
live node can be inspected and told to submit transactions from the terminal:

```bash
jkaind status                              # members, peers, watermarks
jkaind tx put --key balance --value 100
jkaind tx delete --key balance
```

## Growing the cluster (dynamic membership)

The genesis `cluster.toml` is never rewritten. To add node 3 to a 1,2 cluster,
provision node 3's secret + local config, submit the add-member op to node 1
or 2, then start node 3:

```bash
jkaind member init --node-id 3 --gossip 203.0.113.7:7000 \
  --reconnect 203.0.113.7:7001 --cluster ./cluster/cluster.toml --out ./cluster
jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 \
  --reconnect 203.0.113.7:7001 --key <hex-from-member-init>
jkaind run --cluster ./cluster/cluster-3.toml --node-id 3 \
  --secret ./cluster/secret-3.bin --data ./data
```

`member init` writes the new member's local config as `cluster-3.toml`, so the
shared genesis `cluster.toml` is never rewritten; deploy `cluster-3.toml` only
to node 3.

Membership changes are `MembershipOp::Add` transactions that propagate through
consensus and activate one round after `roundReceived` is decided.

See `node/RUNBOOK.md` for the full 2-VPS deployment.
