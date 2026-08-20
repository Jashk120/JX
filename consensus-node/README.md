# JKaIN

A consensus-critical blockchain node implementing the virtual-voting
Hashgraph algorithm. Events gossip over pinned-TLS TCP, order through
round-based virtual voting, and execute deterministically into a shared
key-value state.

## Workspace layout

```text
protocol/     consensus-critical network layer
  primitives/    value types (zero dependencies)
  crypto/        hashing, signing, membership
  consensus/     virtual-voting Hashgraph: rounds, fame, order, checkpoints
  storage/       Fjall-backed durable event log + roster history
  stream/        mirror stream files: .esf events + .rsf records
  gossip/        pinned-TLS gossip network + GossipNode runtime
  test-support/  shared test timing helpers (SYNC_INTERVAL, DEADLINE)
executor/     deterministic execution layer
  state/        Fjall-backed KV executor + Merkle tree + DID (did:jkain)
node/         the jkaind daemon: config, persistence, restart recovery
```

## Documents

- [`../docs/JKain_Whitepaper.md`](../docs/JKain_Whitepaper.md) — the design whitepaper.
- [`../docs/JKain_Consensus_Spec.md`](../docs/JKain_Consensus_Spec.md) — the consensus algorithm specification
  (`protocol/consensus` implements it).
- [`../ROADMAP.md`](../ROADMAP.md) — phased roadmap (Phase 8 = deterministic executor, Phase 9 = scalingLocked + DID).
- [`../docs/DID_method.md`](../docs/DID_method.md) — `did:jkain` method spec (executor/state `DidDocument`/`DidOp`).
- [`../docs/OPTIMIZATION.md`](../docs/OPTIMIZATION.md) — scaling design (gossip QUIC + parallel execution), locked.
- [`../docs/V3_Compute_Layer_Notes.md`](../docs/V3_Compute_Layer_Notes.md) — compute-layer design notes.
- [`../AGENTS.md`](../AGENTS.md) — development rules for contributors and AI agents.

## Building and testing

```bash
cargo build --workspace

# Formatting uses the nightly formatter (never stable cargo fmt).
cargo +nightly fmt --all

cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
```

## Running a cluster

Two-node deployment needs one binary per VPS and one shared `cluster.toml` plus one `secret-<id>.bin` per node. How you get the binary there is up to you — the docs show the simplest path, but building directly on each VPS works too.

**Option A — build once, copy (recommended for identical binaries):**

```bash
# On your build machine (laptop or one VPS):
cargo build --release --bin jkaind
scp target/release/jkaind user@203.0.113.5:/usr/local/bin/jkaind
scp target/release/jkaind user@203.0.113.6:/usr/local/bin/jkaind
```

**Option B — build on each VPS:**

```bash
# SSH into each VPS separately and build there:
# on VPS-A (203.0.113.5):
git clone <repo> && cd JKaIN && cargo build --release --bin jkaind
sudo cp target/release/jkaind /usr/local/bin/jkaind

# on VPS-B (203.0.113.6): same steps
```

In either case, **generate the cluster config once, on one machine only**:

```bash
# Generate secrets + shared config for a two-node cluster (run ONCE, anywhere).
cargo run --bin jkaind -- init \
  --member 1:203.0.113.5:7000:203.0.113.5:7001 \
  --member 2:203.0.113.6:7000:203.0.113.6:7001 \
  --out ./cluster
# Creates: ./cluster/cluster.toml, ./cluster/secret-1.bin, ./cluster/secret-2.bin
```

Then distribute the *matching* files — never run `init` twice (you would get mismatched keys and the nodes would silently stall):

```bash
scp ./cluster/cluster.toml ./cluster/secret-1.bin user@203.0.113.5:/etc/jkaind/
scp ./cluster/cluster.toml ./cluster/secret-2.bin user@203.0.113.6:/etc/jkaind/
```

Run one node per VPS:

```bash
# On VPS-A:
jkaind run --cluster /etc/jkaind/cluster.toml --node-id 1 --secret /etc/jkaind/secret-1.bin --data /var/lib/jkaind
# On VPS-B:
jkaind run --cluster /etc/jkaind/cluster.toml --node-id 2 --secret /etc/jkaind/secret-2.bin --data /var/lib/jkaind

# Local dev (single machine, two nodes on localhost):
cargo run --bin jkaind -- run --cluster ./cluster/cluster.toml --node-id 1 --secret ./cluster/secret-1.bin --data ./data-1 --gossip-port 7000 --reconnect-port 7001
cargo run --bin jkaind -- run --cluster ./cluster/cluster.toml --node-id 2 --secret ./cluster/secret-2.bin --data ./data-2 --gossip-port 7002 --reconnect-port 7003

# With all run flags (all optional except --cluster/--node-id/--secret):
cargo run --bin jkaind -- run \
  --cluster ./cluster/cluster.toml --node-id 1 \
  --secret ./cluster/secret-1.bin --data ./data \
  --gossip-port 7000 --reconnect-port 7001 \
  --control-socket ./data/jkaind.sock \
  --sync-interval 500 --sync-timeout 10000 \
  --log-level info --log-file ./data/logs/jkaind.log
```

The `:reconnect-addr` part of `--member` is optional — a member given as just
`<id>:<gossip-addr>` runs gossip-only and cannot serve checkpoints to a behind
peer, so the reconnect address is recommended for availability.

Available `run` flags:

| Flag | Default | Description |
|---|---|---|
| `--cluster <path>` | *(required)* | Genesis `cluster.toml` |
| `--node-id <id>` | *(required)* | This node's `NodeId` |
| `--secret <path>` | *(required)* | `secret-<id>.bin` (64-byte genesis or 32-byte single-seed for dynamic members) |
| `--data <dir>` | `data` | Data dir for checkpoints (`<data>/checkpoints/`), state DB (`<data>/statedb/`), event log (`<data>/eventlog/`), streams (`<data>/streams/`) |
| `--gossip-port <port>` | from `cluster.toml` | Override gossip listen port |
| `--reconnect-port <port>` | from `cluster.toml` | Override reconnect listen port (or force one for a gossip-only member) |
| `--control-socket <path>` | `<data>/jkaind.sock` | Unix control socket (0600) |
| `--sync-interval <ms>` | `500` | Gossip sync interval (25 ms in tests via `test-support::SYNC_INTERVAL`) |
| `--sync-timeout <ms>` | `10000` | Per-sync timeout |
| `--log-level <level>` | `info` | `trace`/`debug`/`info`/`warn`/`error` (EnvFilter) |
| `--log-file <path\|->` | `<data>/logs/jkaind.log` | Daily rolling file; `-` logs to stderr |

Key rotation is a membership change, not an init operation: `jkaind init
--force` regenerates keys that no longer match any persisted checkpoint roster,
so every node that restores one silently stalls consensus. `init --force`
refuses when it detects local checkpoints (override with
`--i-understand-this-rotates-keys-and-breaks-existing-data`); always wipe
`data/` on every node after regenerating.

Other top-level flags: `jkaind --version` / `-V` prints `version (git hash)`, `jkaind --help` / `-h` prints usage.

## Controlling a running node

`jkaind run` opens a Unix control socket (default `<data>/jkaind.sock`, override with `--control-socket`) so a
live node can be inspected and told to submit transactions from the terminal. The socket is **local-only** (`0600`, not TCP) — to talk to a remote VPS, `ssh` into that VPS first, then run the command there:

```bash
# On VPS-A (node 1):
ssh user@203.0.113.5
jkaind status                              # members, checkpoint roster, peers, watermarks
jkaind status --socket /var/lib/jkaind/jkaind.sock  # explicit socket path
jkaind tx put --key balance --value 100
jkaind tx put --key balance --value 100 --socket /var/lib/jkaind/jkaind.sock
jkaind tx delete --key balance
jkaind tx delete --key balance --socket /var/lib/jkaind/jkaind.sock

# On VPS-B (node 2) — ssh separately:
ssh user@203.0.113.6
jkaind status --socket /var/lib/jkaind/jkaind.sock
jkaind tx put --key balance --value 100 --socket /var/lib/jkaind/jkaind.sock

# Local dev (no ssh needed):
jkaind status --socket ./data-1/jkaind.sock
jkaind status --socket ./data-2/jkaind.sock

# Dynamic membership via the control socket (run on any existing node):
jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 --reconnect 203.0.113.7:7001 --key <hex>
jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 --key <hex> --socket ./data/jkaind.sock
```

`jkaind status` also prints the roster embedded in the latest accepted
checkpoint and warns when it disagrees with the live member set — the
signature of a restored node that is silently stalled because its events no
longer verify.

## Growing the cluster (dynamic membership)

The genesis `cluster.toml` is never rewritten. Once a cluster is running, you **never** re-run `init` with more `--member`s to add a node — that would generate new mismatched keys and require wiping `data/` on every node (`node/src/bin/jkaind.rs:160`). Instead, new nodes join via consensus:

**If you started with 1 node and want to add a 2nd (same for 2 → 3, 3 → 4, etc.):**

To add node 3 to a 1,2 cluster, provision node 3's secret + local config, submit the add-member op to node 1
or 2, then start node 3:

```bash
jkaind member init --node-id 3 --gossip 203.0.113.7:7000 \
  --reconnect 203.0.113.7:7001 --cluster ./cluster/cluster.toml --out ./cluster
jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 \
  --reconnect 203.0.113.7:7001 --key <hex-from-member-init>
# --reconnect is optional in add-member (omit for gossip-only):
# jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 --key <hex>
jkaind run --cluster ./cluster/cluster-3.toml --node-id 3 \
  --secret ./cluster/secret-3.bin --data ./data
```

`member init` writes the new member's local config as `cluster-3.toml`, so the
shared genesis `cluster.toml` is never rewritten; deploy `cluster-3.toml` only
to node 3. `init` is only for genesis; `member init` + `add-member` is for every later node, whether you started with 1 node or 2.

**For 4 or 5 nodes:** same steps, one at a time. Do not batch:

```bash
# Add node 4 after node 3 has activated (wait for roundReceived+1 to be decided):
jkaind member init --node-id 4 --gossip 203.0.113.8:7000 --reconnect 203.0.113.8:7001 --cluster ./cluster/cluster.toml --out ./cluster
jkaind add-member --node-id 4 --gossip 203.0.113.8:7000 --reconnect 203.0.113.8:7001 --key <hex>
# wait: jkaind status should show node 4 in `members` before adding node 5
jkaind member init --node-id 5 --gossip 203.0.113.9:7000 --reconnect 203.0.113.9:7001 --cluster ./cluster/cluster.toml --out ./cluster
jkaind add-member --node-id 5 --gossip 203.0.113.9:7000 --reconnect 203.0.113.9:7001 --key <hex>
```

Each `add-member` is a `MembershipOp::Add` transaction ordered through consensus and activated one round after its `roundReceived` is decided. A new node's local `cluster.toml` (e.g. `cluster-4.toml`) only contains genesis members + itself — later members' addresses propagate via consensus, not via the file (see `node/RUNBOOK.md:240`). Deploying a stale genesis `cluster.toml` to an existing node would make it start with the new node already in its roster and is explicitly warned against.

If you knew upfront you wanted 4-5 nodes, you can also create them all in genesis: `jkaind init --member 1:... --member 2:... --member 3:... --member 4:... --member 5:... --out ./cluster` — then distribute `cluster.toml` + `secret-<id>.bin` to each VPS and start. No `add-member` needed.

## CLI reference

```
jkaind --version | -V
jkaind --help | -h
jkaind init --member <id>:<gossip-addr>[:<reconnect-addr>] [--member ...] --out <dir> [--force] [--i-understand-this-rotates-keys-and-breaks-existing-data]
jkaind run --cluster <path> --node-id <id> --secret <path> [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>] [--control-socket <path>] [--sync-interval <ms>] [--sync-timeout <ms>] [--log-level <level>] [--log-file <path|->]
jkaind status [--socket <path>]
jkaind tx put --key <k> --value <v> [--socket <path>]
jkaind tx delete --key <k> [--socket <path>]
jkaind add-member --node-id <id> --gossip <ip:port> [--reconnect <ip:port>] --key <hex> [--socket <path>]
jkaind member init --node-id <id> --gossip <ip:port> --reconnect <ip:port> --cluster <genesis cluster.toml> --out <dir>
```

`run` logs to `<data>/logs/jkaind.log` (daily rolling) by default; use `--log-file -` for stderr, `--log-level trace` for verbose.

See `node/RUNBOOK.md` for the full 2-VPS deployment.
