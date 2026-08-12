# RUNBOOK — running a 2-VPS JKain cluster

`jkaind` runs one long-lived JKain node per process. Two VPSes form the
cluster; each runs one node. This runbook covers key generation, deployment,
systemd supervision, firewall ports, and restart/recovery.

## Architecture recap

- One `cluster.toml` (shared, no secrets) describes both members: node id,
  gossip address, reconnect address, Ed25519 verifying key, TLS SPKI
  fingerprint.
- One `secret-<id>.bin` per node (64 bytes = consensus signing seed ‖ TLS
  seed), generated once by `jkaind init` and kept **only on that node**.
- Each node persists accepted checkpoints + state snapshots under its `--data`
  directory. On restart it reloads the latest checkpoint (verifying the
  signature quorum and that the state hashes to the committed `state_hash`)
  and reconnects from its live peer for the event window.

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

This writes `cluster.toml`, `secret-1.bin`, and `secret-2.bin`, then prints
the copy plan.

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
sudo ls -l /var/lib/jkaind/checkpoints/   # checkpoint-<round>.cp / .snap files
```

## 7. Restart / recovery

- `sudo systemctl restart jkaind` stops the node with SIGTERM (drain, exit)
  and restarts it. On boot it reads its latest persisted checkpoint and
  reconnects from the live peer.
- A node whose `--data` directory is intact recovers its committed state even
  after a full machine reboot.
- If **both** nodes are down simultaneously and restart before either can
  sync, they recover their state up to their respective persisted checkpoints
  and continue from there (re-genesis above the restored state). Wipe
  `/var/lib/jkaind` **and** the secrets only when you intend to start a
  brand-new cluster.

## Boundaries

- The retained event graph is not persisted. A restarting node reloads state
  and roster from its checkpoint and reconnects from a live peer for the
  event window; a single-node restart is fully covered.
- Transaction submission from the terminal is not wired in this pass;
  transactions are queued in-process via `GossipNode::submit_transaction`.
