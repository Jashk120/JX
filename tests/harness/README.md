# Harness – Hard-testing JKaIN consensus nodes

Python 3.10+ asyncio harness that drives real `jkaind` processes for
convergence / partition / latency tests.

## Architecture

```
tests/harness/
  __init__.py    re-exports
  cluster.py     ClusterManager – spawns N jkaind, manages ports, proxy mesh, logs, cleanup
  control.py     ControlClient  – async Unix-socket JSON client + Op encoding
  proxy.py       LatencyProxy / LatencyMesh – TCP forwarding with delay/jitter/loss/partition
  metrics.py     collect_statuses + wait_for_* helpers
tests/requirements.txt
```

### ClusterManager

* Finds `jkaind` binary (search `consensus-node/target/debug/jkaind`,
  `target/debug/jkaind`, `$JKAIND_BIN`, or builds via `cargo build --workspace`).
* Allocates free ports: tries `7000+id` offsets, falls back to ephemeral `bind(0)`.
* Generates 6-node `cluster.toml + secret-*.bin` via `jkaind init --member … --out`.
* Spawns `jkaind run --cluster --node-id --secret --data --gossip-port --reconnect-port
  --control-socket --sync-interval 25 --sync-timeout 500 --log-level info --log-file`.
* When `use_proxy=True`, creates a `LatencyMesh` (2·N proxies) and advertises proxy addrs
  in `cluster.toml` while nodes listen on hidden real ports.
* Polls control sockets to confirm health; exposes `submit_tx`, `stop/kill/restart_node`,
  `collect_logs`, and `cleanup` (atexit-safe, removes temp dir).

Typed dataclasses:

```python
from harness.cluster import ClusterManager, ClusterConfig

mgr = ClusterManager(ClusterConfig(num_nodes=6, sync_interval_ms=25, sync_timeout_ms=500))
await mgr.start()
```

### ControlClient

```python
from harness.control import ControlClient, encode_put

client = ControlClient("/tmp/data-1/jkaind.sock")
status = await client.status()          # -> StatusReport
await client.submit_tx(b"opaque")
await client.submit_put(b"key", b"value")
await client.submit_delete(b"key")
```

Op encoding matches `executor/state/src/op.rs`:

```
Put    = 0x00 || u32 BE len(key) || key || u32 BE len(value) || value
Delete = 0x01 || u32 BE len(key) || key
```

Low-level request is `asyncio.open_unix_connection` with line-delimited JSON,
timeout + retries.

### LatencyProxy / LatencyMesh

`LatencyProxy` forwards `listen -> target` with:

* `mean_latency_ms` + uniform `jitter_ms`
* `drop_prob` (random connection close)
* `set_latency` / `set_drop_prob` dynamic control
* `set_blocked` for partition

`LatencyMesh` creates one gossip (+ one reconnect) proxy per node:

```python
from harness.proxy import LatencyMesh

mesh = LatencyMesh()
await mesh.allocate({1:(7000,7001), ...})
await mesh.start()
mesh.set_latency(30, jitter_ms=10)
mesh.isolate_node(6)          # ingress block for node 6; others stay connected
mesh.set_partition([1,2,3],[4,5,6])
mesh.heal()
await mesh.stop()
```

*Partition note*: per-node proxies multiplex all sources, so precise per-edge
partition needs source identification unavailable over TCP. `isolate_node`
provides asymmetric ingress isolation (rest of mesh stays healthy); general
`set_partition` blocks the involved groups.

### Metrics

```python
from harness.metrics import collect_statuses, wait_for_decided_round, wait_for_checkpoint

statuses = await collect_statuses(mgr.nodes())
await wait_for_decided_round(mgr.nodes(), min_round=5, timeout=30)
await wait_for_checkpoint(mgr.nodes(), min_round=3, timeout=30)
```

Checks: `frontiers_within_bound(statuses, bound=2)`, `checkpoint_roster_consistent`.

## Usage example

```python
import asyncio
from harness.cluster import ClusterManager, ClusterConfig
from harness.metrics import wait_for_decided_round

async def main():
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    await mgr.start()
    try:
        await mgr.submit_put(b"balance", b"100")
        await wait_for_decided_round(mgr.nodes(), min_round=3, timeout=20)
        print("converged")
        mgr.stop_node(6)
        await asyncio.sleep(2)
        await mgr.restart_node(6)
        await wait_for_decided_round(mgr.nodes(), min_round=5, timeout=20)
    finally:
        mgr.cleanup()

asyncio.run(main())
```

## Requirements

stdlib only (`asyncio`, `socket`, `subprocess`, `json`, `struct`, `dataclasses`).
Optional: `pytest`, `pytest-asyncio` for tests (see `tests/requirements.txt`).

## Safety

* All processes are killed via process group (`os.setsid`) on `cleanup` / `atexit`.
* Temp dir under `mkdtemp(jkain-harness-*)` is removed on cleanup.
* No absolute-path hardcoding; `jkaind` discovery is relative to repo root.
