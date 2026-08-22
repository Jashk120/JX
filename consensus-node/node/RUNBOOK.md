# RUNBOOK — running a 2-VPS JKain cluster

`jkaind` runs one long-lived JKain node per process. Two VPSes form the
cluster; each runs one node. This runbook covers key generation, deployment,
systemd supervision, firewall ports, restart/recovery, and — after the cluster
is up — controlling the running node and growing the cluster dynamically
through its Unix control socket.

## Architecture recap

- One `cluster.toml` (shared, no secrets) describes the **genesis** members:
  node id, gossip address, reconnect address, Ed25519 verifying key, TLS SPKI
  fingerprint. It is written once by `jkaind init` and never modified — later
  members join through consensus, not by editing this file.
- One `secret-<id>.bin` per node. Genesis members get 64 bytes (consensus
  signing seed ‖ TLS seed). Dynamically-added members (`jkaind member init`)
  get a single 32-byte seed used for both signing and TLS — that is what makes
  the runtime add path's TLS pinning work.
- Each node persists accepted checkpoints + state snapshots under its `--data`
  directory. On restart it reloads the latest checkpoint (verifying the
  signature quorum and that the state hashes to the committed `state_hash`)
  and reconnects from its live peer for the event window.
- Each running node serves a **Unix control socket** (default
  `<data>/jkaind.sock`, mode `0600`) for terminal-driven inspection and
  transaction submission.

## 0. One-command deployment

`jkaind deploy genesis` automates §1–5 below from a single admin machine. It
installs the binary, creates the `jkaind` service user plus `/etc/jkaind` and
`/var/lib/jkaind`, generates each member's secret **on its own node** (the
`jkaind keygen` helper prints only the public verifying key and TLS SPKI
fingerprint; a secret never exists outside the machine it belongs to),
assembles and distributes `cluster.toml` from those public keys, writes the
§4 unit file verbatim, optionally applies the §5 `ufw` rules (`--ufw`),
starts every node, and waits until each control socket answers:

```bash
cargo build --release --bin jkaind
jkaind deploy genesis \
  --member 1=root@203.0.113.5 \
  --member 2=root@203.0.113.6 \
  --binary ./target/release/jkaind --ufw
```

- Targets are `[user@]host[:ssh-port]`; the host doubles as the gossip address,
  so it must be an IP literal unless an explicit advertise address is appended
  (`=<advertise-ip>`). SSH aliases and custom users/ports resolve through your
  `~/.ssh/config`.
- Privileged remote steps run under non-interactive `sudo -n`; key-based auth
  is required.
- The only local artifact is a public `cluster.toml` copy under `--out`
  (default `./jkaind-deploy/`) — keep it: `member init` consumes it later.
- Re-running against existing nodes refuses to overwrite secrets or persist
  over live checkpoints unless `--force` is passed (same hazard as
  `init --force`: wipe data dirs first).
- After genesis, growth stays manual-by-design: `member init` + `add-member`
  flow through consensus (§8+), never through this tool.

### 0a. Deploying to ARM64 nodes from an x86_64 admin machine

One binary, two builds: an x86_64 copy stays on the admin machine purely to
*run* `deploy genesis`; the copy pushed to the nodes via `--binary` must be
aarch64. The orchestrator never executes the payload locally, so any file
path works.

**Route A — build on one VPS (no cross toolchain):** even when the VPSes
cannot reach each other, the admin machine relays:

```bash
ssh root@vps-a 'apt install -y cargo && cd JKaIN/consensus-node \
  && cargo build --release --bin jkaind'
scp root@vps-a:JKaIN/consensus-node/target/release/jkaind ./jkaind-arm64
jkaind deploy genesis --member 1=root@vps-a-ip --member 2=root@vps-b-ip \
                      --binary ./jkaind-arm64 --ufw
```

(Prefer the distro `rustup` over `apt cargo` where available; the apt package
is often stale.)

**Route B — cross-compile on the x86_64 machine:**

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu      # cross linker, needed by `ring`
cat >> .cargo/config.toml <<'EOF'
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
EOF
cargo build --release --target aarch64-unknown-linux-gnu --bin jkaind

jkaind deploy genesis --member 1=root@vps-a-ip --member 2=root@vps-b-ip \
  --binary target/aarch64-unknown-linux-gnu/release/jkaind --ufw
```

For fully static binaries immune to glibc version differences between nodes,
use the `aarch64-unknown-linux-musl` target with a musl cross toolchain or
[`cross`](https://github.com/cross-rs/cross). Whichever route you take, both
nodes must receive the *same* binary.

## 1. Build

On the build machine:

```bash
cargo build --release --bin jkaind
```

Copy `target/release/jkaind` to both VPSes (e.g. `/usr/local/bin/jkaind`).

## 2. Generate keys and config

Run once, on any machine. Replace the addresses with your real public IPs:

```bash
jkaind init \
  --member 1:203.0.113.5:7000:203.0.113.5:7001 \
  --member 2:203.0.113.6:7000:203.0.113.6:7001 \
  --out ./cluster
```

The `:reconnect-addr` is optional: `--member 2:203.0.113.6:7000` creates a
gossip-only member. Such a node can still pull checkpoints from a peer that
serves reconnect, but cannot serve them itself, so it is a single point of
failure for behind peers — give every member a reconnect port for full
availability.

This writes `cluster.toml`, `secret-1.bin`, and `secret-2.bin`, then prints
the copy plan.

> **Key rotation is a membership change, not an init operation.** Running
> `jkaind init --force` regenerates every member's keys. Those keys no longer
> match the roster embedded in any already-persisted checkpoint, so a node
> that restores one would sign events no peer can verify and **silently stall
> consensus** (`ordered round` frozen at its current value). `jkaind init
> --force` refuses to run when it detects local checkpoints, and warns
> otherwise. To rotate keys you must **wipe `data/` on every node** (after
> backing up what you need) so all nodes re-genesis under the new roster, and
> confirm on each VPS that no live checkpoints remain. Pass
> `--i-understand-this-rotates-keys-and-breaks-existing-data` only after doing
> so.

## 3. Copy keys and config

```bash
# VPS A (node 1):
mkdir -p /etc/jkaind
scp ./cluster/cluster.toml ./cluster/secret-1.bin user@vps-a:/etc/jkaind/

# VPS B (node 2):
scp ./cluster/cluster.toml ./cluster/secret-2.bin user@vps-b:/etc/jkaind/
```

`secret-*.bin` are `chmod 600` by `init`; keep them on their node only. Do
not commit them to git (`.gitignore` excludes them).

## 4. systemd units

`/etc/systemd/system/jkaind.service` on **VPS A** (node 1):

```ini
[Unit]
Description=JKain node 1
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/jkaind run \
    --cluster /etc/jkaind/cluster.toml \
    --node-id 1 \
    --secret /etc/jkaind/secret-1.bin \
    --data /var/lib/jkaind
Restart=on-failure
RestartSec=2
User=jkaind
Group=jkaind
LimitNOFILE=65536
# systemd sends SIGTERM on stop; jkaind drains and exits.
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

On **VPS B** change only `--node-id 2` and `--secret .../secret-2.bin`.

Enable and start:

```bash
sudo useradd -r -s /usr/sbin/nologin jkaind
sudo mkdir -p /var/lib/jkaind && sudo chown jkaind:jkaind /var/lib/jkaind
sudo systemctl daemon-reload
sudo systemctl enable --now jkaind
journalctl -u jkaind -f        # watch startup / shutdown logs
```

## 5. Firewall

Allow the gossip and reconnect ports for both cluster members. Example with
`ufw` (adjust `203.0.113.6` on VPS A, and vice versa):

```bash
sudo ufw allow from 203.0.113.6 to any port 7000 proto tcp   # gossip
sudo ufw allow from 203.0.113.6 to any port 7001 proto tcp   # reconnect
```

On a 2-node cluster only the two members need to reach each other; do not
expose the ports publicly.

## 6. Verify the cluster

Each node logs `[jkaind] node <id>: gossip on 0.0.0.0:7000, reconnect on
0.0.0.0:7001` at startup. With both running, each node periodically syncs,
orders events, and accepts checkpoints, which are written under
`/var/lib/jkaind/checkpoints/`:

```bash
sudo ls -l /var/lib/jkaind/checkpoints/   # checkpoint-<round>.cp files
```

The per-round state snapshot that hashes to each checkpoint's `state_hash` is
stored in the Fjall state database's `snap` keyspace (`/var/lib/jkaind/statedb/`),
not as a `.snap` file.

## 7. Restart / recovery

- `sudo systemctl restart jkaind` stops the node with SIGTERM (drain, exit)
  and restarts it. On boot it reads its latest persisted checkpoint and
  reconnects from the live peer.
- A node whose `--data` directory is intact recovers its committed state even
  after a full machine reboot.
- A node whose persisted checkpoint roster no longer matches its configured
  secret refuses to start instead of silently stalling. The error tells you
  which case you hit: either the secret was swapped without wiping the data
  dir (`restore the original secret or wipe data/ to re-genesis`), or the
  node's key is not in the checkpoint roster at all (`wipe data/ and use
  `add-member` to join from the current round`).
- If **both** nodes are down simultaneously and restart before either can
  sync, they recover their state up to their respective persisted checkpoints
  and continue from there (re-genesis above the restored state). Wipe
  `/var/lib/jkaind` **and** the secrets only when you intend to start a
  brand-new cluster.

## 8. Control a running node

Each node serves a Unix control socket at `<data>/jkaind.sock` (override with
`--control-socket <path>`). The client subcommands connect over it:

```bash
jkaind status                    # members, peers, ordering/checkpoint watermarks
jkaind tx put --key balance --value 100
jkaind tx delete --key balance
```

`tx put`/`tx delete` encode a KV transaction (`Op::Put`/`Op::Delete`) and queue
it on the node; it is included in the node's next own event and executed by
every node once consensus orders it. The socket is `0600`; point the client at
it with `--socket <path>` if the data dir is not `./data`.

## 9. Add a third member (dynamic membership)

Adding a member never edits the genesis `cluster.toml`. It is a consensus
operation: a `MembershipOp::Add` transaction is submitted to any running node,
orders through the hashgraph, and activates one round after its `roundReceived`
is decided. Until then the new node has no place in the cluster, so the order
is:

**1. Provision the new member's secret + local config** (on any machine with
the genesis `cluster.toml`):

```bash
jkaind member init \
  --node-id 3 --gossip 203.0.113.7:7000 --reconnect 203.0.113.7:7001 \
  --cluster ./cluster/cluster.toml --out ./cluster
```

This writes `secret-3.bin` (a single 32-byte seed used for both consensus
signing and TLS) and a **local** config for node 3 (genesis members 1,2 +
node 3) as `cluster-3.toml`, then prints the `--key <hex>` to pass to
`add-member`. The node-specific filename means it can never overwrite the
shared `./cluster/cluster.toml` on nodes 1 and 2, which stays untouched —
and **never** deploy `cluster-3.toml` to nodes 1 or 2, or they would start
with node 3 already in their genesis roster.

**2. Submit the add-member transaction** on node 1 **or** node 2:

```bash
jkaind add-member \
  --node-id 3 --gossip 203.0.113.7:7000 --reconnect 203.0.113.7:7001 \
  --key <hex-from-member-init>
```

The node queues the op; once ordered and activated, nodes 1 and 2 can gossip
with node 3 and pin its TLS identity + reconnect port. `add-member` prints the
`ufw` commands to open the gossip/reconnect ports in both directions.

**3. Start node 3** (deploy `cluster-3.toml` + `secret-3.bin` to VPS C and run):

```bash
jkaind run --cluster ./cluster/cluster-3.toml --node-id 3 \
           --secret ./cluster/secret-3.bin --data ./data
```

Because node 3's TLS identity derives from the same 32-byte seed as its
consensus key, the fingerprint nodes 1,2 pin via `add_peer_from_key` matches
node 3's real certificate, and its reconnect port is pinned too — so node 3
can serve as a reconnect source, keeping the reconnect graph symmetric.

## Boundaries

- The retained event graph is not persisted. A restarting node reloads state
  and roster from its checkpoint and reconnects from a live peer for the event
  window; a single-node restart is fully covered.
- `MembershipOp::Remove` is not implemented: membership only grows. Removal is
  deferred consensus work (roster shrinkage, quorum math, hashgraph removal).
- Addresses of *later* members (node 4, 5, …) are only propagated to nodes that
  observe their `MembershipOp::Add`; a brand-new joiner's local `cluster.toml`
  only lists the genesis members plus itself. Fine for adding one member at a
  time; multi-hop membership needs a future address-propagation mechanism.
- The control socket trusts Unix file permissions (`0600`), not a shared secret
  or client certificate.
