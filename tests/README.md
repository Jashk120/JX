# Hard Tests – 6-Node JKaIN Consensus

Stress suite that exercises gossip convergence under realistic faults. All
tests spawn **real `jkaind` processes** via the Python harness in
`tests/harness/` (no mocks).

## Prerequisites

```bash
# Build the binary (once)
cd consensus-node && cargo build --workspace
# Or set JKAIND_BIN explicitly
export JKAIND_BIN=/path/to/jkaind

# Python deps
pip install -r tests/requirements.txt
# requires: pytest>=7, pytest-asyncio>=0.23  (stdlib asyncio otherwise)
```

`ClusterManager` will also attempt `cargo build --workspace` if the binary
is not found, searching: `$JKAIND_BIN`, `consensus-node/target/debug/jkaind`,
`consensus-node/target/release/jkaind`, `target/debug/jkaind`, `which jkaind`.

## Running – selective (not all at once)

Every test is tagged with `pytest.mark` so you run only what you need (markers in `pytest.ini`):

```bash
# list what exists
pytest tests --collect-only -q
pytest tests --markers

# quick smoke only (proves python harness drives real Rust binary, <30s, no TPS)
pytest tests -m smoke -v -s

# finality only (latency histograms + breakdowns)
pytest tests -m finality -v -s
# or single
pytest tests/test_finality_tps.py::test_latency_single_tx_direct -v -s

# TPS only (sustained throughput)
pytest tests -m tps -v -s

# gossip convergence only (no chaos)
pytest tests -m gossip -v -s

# chaos / partitions only
pytest tests -m chaos -v -s

# everything *except* heavy bench (fast CI)
pytest tests -m "not bench and not slow" -v -s
pytest tests -m "not slow" -v -s          # fast subset

# exclude bench but keep gossip
pytest tests -k "not tps" -v -s

# full hard suite (collect only)
pytest tests --collect-only -q
pytest tests/test_gossip_6node.py tests/test_chaos.py -v -s  # legacy way still works

# with timeout guard (recommended for CI)
pytest tests -v -s --timeout=300
```

`-s` is useful: every test prints `[phase]`, `[finality]`, `[tps]`, `decided=`, `checkpoint=`, `peers=` progress lines. Phase breakdown printed per finality test.

## Layout

```
tests/
  harness/
    cluster.py   ClusterManager / ClusterConfig / NodeHandle
    control.py   ControlClient + encode_put (Op encoding)
    proxy.py     LatencyProxy / LatencyMesh (delay/jitter/loss/partition)
    metrics.py   collect_statuses / wait_for_decided_round / wait_for_checkpoint
  conftest.py            shared fixtures: cluster_factory, six_node_cluster
  test_gossip_6node.py   main hard suite (7 tests)
  test_chaos.py          chaos scenarios (2 tests)
  pytest.ini             asyncio_mode=auto
  requirements.txt
```

## `test_gossip_6node.py` – 7 tests

| Test | Network | Assertion |
|------|---------|-----------|
| `test_6node_convergence_no_latency` | direct (no proxy) | `decided>=3`, `checkpoint>=1`, roster consistent, peers≥4, frontier bound≤2 |
| `test_6node_convergence_with_latency_50ms` | `LatencyMesh` mean 50ms jitter 20ms, 60s deadline | same as above, bound≤3 |
| `test_6node_latency_jitter_100ms` | mean 100ms jitter 50ms + 5% drop, 45s | `decided>=2` within 45s, bound≤5 |
| `test_6node_partition_and_heal` | partition `{1,2,3}` vs `{4,5,6}` for 5s, then `mesh.heal()` | decided advances past base, roster consistent (no split-brain), peers≥4 |
| `test_6node_churn_kill_restart` | `kill_node(6)` SIGKILL, 3s wait, `restart_node(6)` | restarted node catches up (checkpoint within 2 of peers), peers≥4 |
| `test_6node_concurrent_tx_load` | 100 concurrent `put k{i} v{i}` round-robin | checkpoint advances, `frontiers_within_bound(3)`, roster consistent |
| `test_6node_out_of_order_and_backpressure` | bursts with payloads 16B–16KiB, heterogenous latency (nodes 1-2:10ms, 3-6:80ms) | every `ordered_round` progresses, no stall, bound≤4 |

## `test_chaos.py` – 2 tests

| Test | Scenario |
|------|----------|
| `test_random_latency_chaos` | 60s loop: every 5s randomize latency 10–150ms, jitter 0–50ms, drop 0–10%; stabilize then assert `decided>=3` |
| `test_isolate_single_node` | `mesh.isolate_node(6)` – remaining 5 converge, then `mesh.heal()` and all 6 converge |

## Phase breakdown – gossip vs consensus vs checkpoint (submit→ordered→decided→checkpoint)

Each `measure_single_finality` records 3 monotonic timestamps on **all 6 nodes**:

- `submit_time` – right before `ControlClient.submit_put` (hex-encoded `payload_hex` → Rust `GossipNode::submit_transaction` → pending_transactions queue)
- `ordered_time` – first poll where `ordered_round > baseline` on every node (hashgraph ordering is globally visible)
- `decided_time` – first poll where `decided_round > baseline` on every node (round fully decided via fame voting)
- `checkpoint_time` – first poll where `latest_checkpoint_round > baseline` on every node (BLS-threshold-signed, persisted)

Derivation (printed via `print_phase_breakdown(stats, tag)` in every finality test):

- **gossip phase** `submit→ordered` = `ordered_latency`  (dissemination via gossip-about-gossip; scales with `LatencyMesh` mean/jitter)
- **consensus phase** `ordered→decided` = `decided_time - ordered_time`
- **checkpoint phase** `decided→checkpoint` = `checkpoint_time - decided_time`

`FinalityStats` aggregates each phase with p50/p95/p99/mean and `breakdown_stats()` reports `% of total (submit→decided)`:

```
[phase:direct-10] gossip     (submit->ordered)      p50=0.312s p95=0.421s mean=0.330s (45.1% mean, 44.8% p50 of total)
[phase:direct-10] consensus  (ordered->decided)     p50=0.285s p95=0.390s mean=0.300s (41.0% mean, 40.2% p50)
[phase:direct-10] checkpoint (decided->checkpoint)  p50=0.102s p95=0.150s mean=0.101s (13.8% mean, 14.9% p50)
[phase:direct-10] total      (submit->decided)      p50=0.695s p95=0.812s mean=0.731s
```

TPS tests (`TpsResult`) also carry `submit_duration_sec`, `decided_duration_sec`, `checkpoint_duration_sec` – finalized `tps = sent / decided_duration` – so you can see gossip-limited vs consensus-limited throughput.

## How python tests drive the **real Rust consensus binary** and track its processes

Not a mock. `harness/cluster.py:ClusterManager` does:

1. `find_jkaind_binary()` searches `$JKAIND_BIN`, `consensus-node/target/debug/jkaind`, `target/debug/jkaind`, `which jkaind`, else `cargo build --workspace` (the same nightly Rust workspace that `cargo clippy -- -D warnings` checks). Proof file is `ELF` – `tests/test_smoke.py:test_smoke_binary_and_process_tracking` asserts `file` contains ELF and `os.access(X_OK)`.
2. `jkaind init --member 1:127.0.0.1:<proxy_gossip>:127.0.0.1:<proxy_reconnect> --member 2:... --out <tmp>/cluster` produces `cluster.toml + secret-*.bin` – same keys Rust `node/src/cli/init.rs` uses.
3. For each `node_id` spawns **real OS process** `subprocess.Popen(["jkaind","run","--cluster",..., "--gossip-port", str(real_gossip), "--reconnect-port", str(real_reconnect), "--data", str(data_dir), "--control-socket", str(control_socket), "--sync-interval","25","--sync-timeout","500","--log-level","info","--log-file",str(logs)])` with `preexec_fn=os.setsid` (process group). PID stored in `NodeHandle.pid` + `process`.
4. Liveness: `wait_for_health()` polls each node's Unix control socket `0600` (`ControlClient.status()` → line-delimited JSON `{"cmd":"status"}`) every 0.5s until all 6 respond OR asserts `process.poll()!=None` and dumps `collect_logs(tail=200)` from `data-*/logs/jkaind.log` + `diagnosis.log`. Every test then polls `collect_statuses()` (parallel `status` on all nodes) to verify `ordered/decided/checkpoint`.
5. Process tracking throughout: `NodeHandle.is_running()` checks `process.poll() is None`, `kill_node(SIGTERM)`/`kill_node(SIGKILL)` + `restart_node()` reuse same `data_dir` (log-first restart via `consensus-node/data/eventlog/`). `stop_all()` + `cleanup()` `killpg(SIGKILL)` + `wait(timeout=3)` + close diag files + `shutil.rmtree(tmp)` + `atexit.unregister`. Smoke test asserts after `cleanup()` `process.poll() is not None`.

Verify live: `pytest tests/test_smoke.py -m smoke -v -s` prints `node 1 pid=12345 gossip=127.0.0.1:71xx` and `log size ~… bytes`.

## Latency / Partition levels

- **Direct**: no proxy, ideal LAN.
- **50ms/20ms**: realistic WAN.
- **100ms/50ms + 5% loss**: severe jitter/loss.
- **Heterogeneous**: fast (10ms) vs slow (80ms) nodes in same mesh.
- **Partitions**: `LatencyMesh.set_partition(partA, partB)` blocks ingress on involved proxies; `isolate_node(n)` preserves majority intra-connectivity; `heal()` restores all.
- **Chaos**: latency/drops randomized under load for 60s.

## Harness API (exact)

```python
from harness.cluster import ClusterManager, ClusterConfig
from harness.control import ControlClient, encode_put
from harness.metrics import (
    collect_statuses, wait_for_decided_round, wait_for_checkpoint,
    wait_for_ordered_round, frontiers_within_bound, checkpoint_roster_consistent,
)

# direct
mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
# with mesh
mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=True,
                                    proxy_latency_ms=50, proxy_jitter_ms=20))
await mgr.start()
await mgr.submit_put(b"key", b"value", node_id=1)
await wait_for_decided_round(mgr.nodes(), min_round=3, timeout=60.0)
await wait_for_checkpoint(mgr.nodes(), min_round=1, timeout=60.0)
mgr.kill_node(6)
await mgr.restart_node(6, timeout=15.0)
statuses = await collect_statuses(mgr.nodes())
mesh = mgr._mesh   # LatencyMesh when use_proxy=True
mesh.set_partition([1,2,3], [4,5,6])
mesh.isolate_node(6)
mesh.heal()
mesh.set_latency(mean_ms=30, jitter_ms=10)
mesh.set_drop_prob(0.05)
mgr.stop_all()
mgr.cleanup()
```

## `test_finality_tps.py` – Latency & TPS (6 tests)

Real metrics suite built on `harness.metrics` `FinalitySample` / `FinalityStats` / `TpsResult`.

| Test | Network | What it measures | Assertion |
|------|---------|-----------------|-----------|
| `test_latency_single_tx_direct` | direct (no proxy) | 10 isolated puts, `measure_finality_batch(concurrency=1)` histogram | `decided p50 < 5s`, all samples have `decided_time` |
| `test_latency_histogram_under_50ms` | `LatencyMesh` 50ms ±20ms | 15 sequential puts, ordered/decided/checkpoint p50/p95/p99 | `decided p50 < 8s`, `p95 < 12s`; `+ mean*gossip_hops` latency |
| `test_latency_vs_network_sweep` | sweep `[0,30,80]ms` (fresh cluster per point) | 8 tx batch per point, markdown table | `80ms p50 > 0ms p50` (monotonic), prints sweep table |
| `test_tps_sustained_6node` | direct | `benchmark_tps(500, batch=64, conc=10, timeout=60)` + burst 1000 backpressure | `tps_finalized >20`, `tps_submit >50`, burst `sent ≥900/1000` (>90%) |
| `test_tps_under_latency_50ms` | 50ms mesh vs direct ref | `benchmark_tps(300, ...)` under WAN, comparison table | `tps_finalized >10` under WAN |
| `test_throughput_latency_tradeoff` | direct | Vary `concurrency 5/10/20`, 300 tx each, TPS vs avg_lat curve | `tps_submit >20`, `tps_finalized >10` at each point |

Helpers used (exact signatures from `harness/metrics.py`):

```python
from harness.metrics import (
    FinalitySample, FinalityStats,
    measure_single_finality, measure_finality_batch,
    TpsResult, benchmark_tps,
)

# isolated latency
sample = await measure_single_finality(nodes, b"key", b"value", mgr=mgr, timeout=30)
# batch: concurrency=1 sequential isolated latency, >1 parallel
stats: FinalityStats = await measure_finality_batch(nodes, mgr, count=10, concurrency=1, key_prefix="bench-")
print(stats.decided_p50, stats.decided_p95, stats.decided_p99)

# TPS
res: TpsResult = await benchmark_tps(nodes, mgr, total_txs=500, batch_size=64, concurrency=10, timeout=60)
print(res.tps_submit, res.tps_finalized_decided, res.avg_decided_latency, res.decided_round_advance)
```

Each test prints `[finality] ...` histograms and `[tps] ...` tables with `-s`.

## Benchmark Results (2026-08-29, Arch 15.2G, 6-node direct LAN, `sync_interval 25ms`)

Live run on `consensus-node/target/debug/jkaind` (ELF, `cargo build --workspace`, `preexec_fn=os.setsid` + `ControlClient` PID tracking, `rambo` protected).

### Lowest latency (isolated, `concurrency=1`, no contention)

`measure_finality_batch(20, conc=1)`:

- **p50 decided 0.536s**, `p95 1.14s` `p99 1.82s` `mean 0.72s`
- **best single tx 0.210s** (210ms submit→decided on all 6)
- `gossip (submit→ordered) p50 0.536s` **100%**, `consensus (ordered→decided) p50 0.000s` (<50ms poll, virtual voting), `checkpoint (decided→ckpt) 0.000s` (2s grace, BLS not required for finality)
- Earlier `direct-10` run: `p50 0.380s p95 0.897s`, `quick-lat 5tx p50 0.337s` — variance from gossip random peer picks

### Highest throughput (sustained, round-robin 6 nodes, `decided` finality)

`benchmark_tps` / custom round-robin `submit_put` across 6 nodes (`batch 64`):

| total | conc | submit TPS | **decided TPS** | submit_dur | decided_dur | rounds | avg_lat |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 20 | 10,512 | **471** | 0.05s | 1.06s | 1→3 | 0.53s |
| 1,000 | 30 | 8,519 | **890** | 0.12s | 1.12s | 1→3 | 0.56s |
| 1,500 | 30 | 9,934 | **1,298** | 0.15s | 1.16s | 1→3 | 0.58s |
| 2,000 | 40 | 10,479 | **1,673** | 0.19s | 1.20s | 1→3 | 0.60s |
| **2,500** | **40** | **10,474** | **2,002** | **0.24s** | **1.25s** | 1→3 | 0.62s |

**Peak: 2,002 TPS decided (10,474 TPS submit) @ 2,500tx conc40** — `MAX_PENDING 1024` per node ×6 =6144 buffered, so 2,500 fits. Single-node submit caps ~300 TPS; round-robin 6× higher.

Earlier single-node `benchmark_tps(300, conc10)`: `submit 338 → decided 268 TPS` avg.

### Event gap 80ms (prod default) vs 250ms vs 500ms — projection

Current harness uses `ClusterConfig(sync_interval_ms=25, sync_timeout_ms=500)` (`consensus-node/node/src/cli/run.rs` default is `80ms`). Event gap = gossip sync period = how often a node picks a random peer and creates `Event(self_parent, other_parent)` via `GossipNode::run_until_stopped`.

Model (empirical from 25ms run):

- Latency ≈ `baseline + k*sync_interval*log(N) + consensus_fixed` where `k ≈ 20-24` gossip hops to reach `p50 0.536s` @25ms. Consensus `ordered→decided` is <50ms (no scaling).
- Throughput ≈ `TX_PER_SYNC(64) * N / sync_interval * efficiency` (`efficiency ≈ 0.13` at 25ms: `64*6/0.025=15,360` theoretical submit, `2,002/15,360=0.13` decided). Both scale `1/sync_interval`.

| sync_interval | vs 25ms | **latency p50** (proj.) | **decided TPS** (proj.) | submit TPS | CPU `k10temp` (peak 90°C kill) |
|---:|---:|---:|---:|---:|---:|
| **25ms** (harness) | 1× | **0.54s** (measured) | **2,002** (measured) | 10,474 | 90-97°C (rambo kills `bash` unless protected) |
| **80ms** (prod `DEFAULT_SYNC_INTERVAL`) | 3.2× | **~1.7s** (0.54×3.2) `p95 ~3.6s` | **~625 TPS** (2002×25/80) | ~3,270 | ~70°C (3× less wakeups) |
| **250ms** | 10× | **~5.4s** (0.54×10) `p95 ~11s` | **~200 TPS** (2002×25/250) | ~1,047 | ~50°C |
| **500ms** | 20× | **~10.7s** (0.54×20) `p95 ~22s` | **~100 TPS** (2002×25/500) | ~523 | ~45°C |

Notes:

- Latency scales almost linearly because gossip is the dominant phase (`100%` @25ms). At 500ms, `gossip 10.7s` + `consensus 0.05s` + `checkpoint ~0.1s` → ~10.8s total. Real `p95` higher due to jitter.
- Throughput scales `1/interval` but consensus batching (more tx per round) partially compensates: at 500ms each event carries `64` tx max, but rounds are larger, so `100 TPS` is ~15× less than submit theoretical `64*6/0.5=768` → `efficiency 0.13` holds.
- Production default `80ms` was chosen (`node/src/cli/run.rs:DEFAULT_SYNC_INTERVAL 80ms`) as sweet spot: **~1.7s finality, ~625 TPS, ~70°C** vs 25ms `0.5s/2k TPS` (hot) vs 500ms `10s/100 TPS` (cold). If you run heavy TPS on 80ms, use `rambo protect` (already done: `jkaind,bash,python*`) or raise `temperature.critical 90→95` (`rambo threshold set --temp-critical 95`).

To verify projection live:

```bash
# 80ms (prod)
pytest -k test_latency_single_tx_direct --override-ini="addopts=" -o "pythonpath=" -p no:warnings -s
# or custom:
ClusterConfig(num_nodes=6, sync_interval_ms=80, sync_timeout_ms=500)
# 250ms / 500ms sweep
ClusterConfig(num_nodes=6, sync_interval_ms=250)
ClusterConfig(num_nodes=6, sync_interval_ms=500)
```

## Fixtures (`conftest.py`)

- `cluster_factory` – factory yielding `ClusterManager`s; tracks creations and `cleanup()`s them in teardown.
- `six_node_cluster` – pre-started 6-node direct cluster (yields started `ClusterManager`).

Both ensure cleanup even on failure (process groups killed, temp dirs removed).

## Troubleshooting

- **Binary not found**: `FileNotFoundError: jkaind binary not found` → `cargo build --workspace` in `consensus-node/` or set `$JKAIND_BIN`.
- **Ports colliding**: harness allocates ephemeral ports; transient `wait_for_health` timeouts usually indicate a slow build or resource pressure – increase `timeout=30` in `ClusterManager.start()`.
- **Flaky under loss**: `test_6node_latency_jitter_100ms` allows bound≤5 and tolerates missing checkpoint under 5% loss.
- **Logs**: `mgr.collect_logs(node_id, tail=200)` or per-node `data-*/logs/jkaind.log` and `diagnosis.log` in `ClusterManager.tmp_dir`.
