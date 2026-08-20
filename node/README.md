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
  lives in the state database's `snap` keyspace). Writes use
  `storage::atomic::atomic_write` (temp + `sync_all` + rename + dir fsync).
  `Storage` implements `gossip::CheckpointSink`, so the daemon just hands a
  `Storage` to the node.
- `src/restart.rs` — loads the latest persisted checkpoint, verifies its
  signature quorum and state hash (against the `snap`-keyspace snapshot) via
  `verify_persisted` (non-destructive, over a temp DB), checks that its
  embedded roster still holds this node's current key (refusing to restore a
  checkpoint written under rotated keys), and rebuilds a node via
  `GossipNode::from_checkpoint`. Two paths: `latest_for_restart` (empty
  retained graph, `request_reconnect()` from a peer) and
  `latest_for_restart_with_log` (replay the durable event log, verifying
  each event against the roster at its birth round). Watermark restoration
  takes `max(persisted watermark, newest retained own-event timestamp)`.
- `tests/` — config/CLI round-trips, the single-seed pin-match regression,
  control-socket protocol tests, storage round-trips, transaction propagation,
  a restart-recovery end-to-end test, an event-log no-peer restart test, and
  dynamic add-member via the socket.

## Deployment

See `RUNBOOK.md` for the 2-VPS deployment: systemd units, firewall ports,
key/config copy steps, and the add-a-third-member flow.

## Persistence and recovery

- Checkpoints: `Storage` writes `checkpoint-<round>.cp` files under
  `<data>/checkpoints/` atomically (`temp + sync_all + rename + dir fsync`
  via `protocol/storage/src/atomic.rs`), so a crash never leaves a torn file.
  The per-round state snapshot lives in the Fjall state database's `snap`
  keyspace (`<data>/statedb/`), not as a sidecar file. `verify_persisted`
  checks both the `>2/3` quorum and that the snapshot rebuilds to the
  committed `state_hash` over a temporary DB (non-destructive).
- Event log (Phase 8): every verified event is appended to
  `<data>/eventlog/` (Fjall, `by_seq` + `by_hash` + `roster` keyspaces).
  A restarting node replays the log to rebuild its retained graph
  independently, verifying each event against the roster active at its birth
  round — no live peer required. When the log is empty (pre-Phase-8 data
  dir) the node falls back to `request_reconnect()` from a peer's reconnect
  port.
- Timestamp watermark: `GossipNode::next_timestamp` monotonically clamps
  `SystemTime` against `last_timestamp` (AtomicU64) so equal/decreasing wall
  clocks (e.g. Windows 15.6 ms resolution) cannot emit duplicate timestamps.
  The watermark is persisted per checkpoint (`StateDb::set_watermark`) and
  restored on reconnect/restart, taking the max of the persisted watermark
  and the newest retained own-event timestamp.
- Mirror streams: `<data>/streams/` holds `.esf`/`.rsf` files plus
  `.esf_sig`/`.rsf_sig` signature files (Ed25519, atomic writes). Both are
  chained by a running hash and verified by `stream::verify`.

## Boundaries

- `MembershipOp::Remove` is not implemented; membership only grows.
- The control socket trusts Unix file permissions (`0600`), not a shared
  secret or client certificate.
- `state::StateDb::snapshot_for` is the source of truth for a checkpoint
  round's state; the live `state` partition is not trusted on restart.
