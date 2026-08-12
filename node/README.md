# node

The `jkaind` daemon: runs one real JKain node per process, configured from
the terminal rather than compiled in, with checkpoint persistence and
restart recovery.

This crate wires the `protocol/` and `executor/` crates to a filesystem and
a process lifecycle. It adds no consensus logic of its own.

## Layout

- `src/bin/jkaind.rs` — the CLI: `jkaind init` generates per-node secrets
  and the shared `cluster.toml`; `jkaind run` loads the config, restores
  from the last persisted checkpoint if one exists, and runs a
  `gossip::GossipNode` on 0.0.0.0 until SIGINT/SIGTERM.
- `src/config.rs` — the `cluster.toml` file format and its conversion to
  `gossip::ClusterConfig`.
- `src/storage.rs` — atomic checkpoint persistence under the `--data`
  directory. `Storage` implements `gossip::CheckpointSink`, so the daemon
  just hands a `Storage` to the node.
- `src/restart.rs` — loads the latest persisted checkpoint, verifies its
  signature quorum and state hash, and rebuilds a node via
  `GossipNode::from_checkpoint` plus a reconnect for the event window.
- `tests/` — config/CLI round-trips, storage round-trips, transaction
  propagation, and a restart-recovery end-to-end test.

## Deployment

See `RUNBOOK.md` for the 2-VPS deployment: systemd units, firewall ports,
and key/config copy steps.

## Boundaries

- The retained event graph is not persisted. A restarting node reloads state
  and roster from its checkpoint and reconnects from a live peer for the
  event window; a single-node restart is fully covered.
- Transaction submission from the terminal is not wired in this pass;
  transactions are queued in-process via `GossipNode::submit_transaction`.
