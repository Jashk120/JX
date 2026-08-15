# node

The `jkaind` daemon: runs one real JKain node per process, configured from
the terminal rather than compiled in, with checkpoint persistence and
restart recovery.

This crate wires the `protocol/` and `executor/` crates to a filesystem and
a process lifecycle. It adds no consensus logic of its own.

## Layout

- `src/bin/jkaind.rs` — the CLI: `jkaind init` generates per-node secrets and
  the shared genesis `cluster.toml`; `jkaind run` loads the config, restores
  from the last persisted checkpoint if one exists, and runs a
  `gossip::GossipNode` on 0.0.0.0 until SIGINT/SIGTERM. Client subcommands
  (`status`, `tx`, `add-member`, `member init`) drive a running node over its
  Unix control socket and provision new members.
- `src/control.rs` — the Unix-socket control plane: line-delimited JSON
  requests (`status`, `peers`, `submit_tx`) served over a `0600` socket, plus
  the transaction payload encodings (`kv_op_payload`, `membership_op_payload`).
- `src/config.rs` — the `cluster.toml` file format and its conversion to
  `gossip::ClusterConfig`.
- `src/storage.rs` — atomic checkpoint persistence under the `--data`
  directory (`checkpoint-<round>.cp` files only; the per-round state snapshot
  lives in the state database's `snap` keyspace). `Storage` implements
  `gossip::CheckpointSink`, so the daemon just hands a `Storage` to the node.
- `src/restart.rs` — loads the latest persisted checkpoint, verifies its
  signature quorum and state hash (against the `snap`-keyspace snapshot),
  checks that its embedded roster still holds this node's current key
  (refusing to restore a checkpoint written under rotated keys), and rebuilds
  a node via `GossipNode::from_checkpoint`. When the durable event log
  (Phase 8) is present, the retained graph is replayed from it —
  independently, with no live peer; otherwise the node reconnects for the
  event window.
- `tests/` — config/CLI round-trips, the single-seed pin-match regression,
  control-socket protocol tests, storage round-trips, transaction propagation,
  a restart-recovery end-to-end test, an event-log no-peer restart test, and
  dynamic add-member via the socket.

## Deployment

See `RUNBOOK.md` for the 2-VPS deployment: systemd units, firewall ports,
key/config copy steps, and the add-a-third-member flow.

## Boundaries

- A restarting node reloads state and roster from its checkpoint (state from
  the Fjall state database's `snap` keyspace) and replays the retained event
  window from the local event log (`<data>/eventlog/`, Fjall), so it recovers
  independently; when the log is empty it reconnects from a live peer instead.
- `MembershipOp::Remove` is not implemented; membership only grows.
- The control socket trusts Unix file permissions (`0600`), not a shared
  secret or client certificate.
