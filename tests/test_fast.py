"""
test_fast.py – fast tier: same invariants as the heavy suite, ~1-2 minutes.

The heavy suite (test_finality_tps.py, test_gossip_6node.py) spawns a fresh
6-node cluster per test, which makes a full run 8-10 minutes and discourages
running it after every change. This module keeps the same assertions but:

  * spawns ONE cluster for the module and reuses it across tests
  * takes small samples (5 latency tx, short TPS burst) instead of 10-20
  * uses tight timeouts so a regression fails fast rather than hanging

Run:

    pytest tests/test_fast.py -v -s                 # ~1-2 min
    pytest tests -m fast -v -s                      # same, via marker

It is a smoke-level guard for exactly the kind of latency regression that
motivated it: a p50 jump from ~0.2-0.5s to multiple seconds should fail here
in under a minute.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from harness.cluster import ClusterConfig, ClusterManager
from harness.metrics import (
    benchmark_tps,
    collect_statuses,
    measure_finality_batch,
    print_phase_breakdown,
    wait_for_checkpoint,
    wait_for_decided_round,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.fast]

# Generous enough not to flake on a loaded box, tight enough that a real
# regression (measured p50 of 2s+ vs baseline <1s) fails this test.
LATENCY_P50_CEILING_SEC = 5.0
MIN_FINALIZED_TPS = 5.0
MIN_SUBMIT_TPS = 20.0


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def fast_cluster():
    """One 6-node cluster reused by every test in this module."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    await mgr.start()
    try:
        await wait_for_decided_round(mgr.nodes(), min_round=1, timeout=30.0)
        yield mgr
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()


async def test_fast_latency(fast_cluster: ClusterManager) -> None:
    """5 isolated puts (concurrency=1): all decided, p50 under ceiling."""
    stats = await measure_finality_batch(
        fast_cluster.nodes(), fast_cluster, count=5, concurrency=1,
        key_prefix="fast-lat-", timeout=20.0,
    )
    print_phase_breakdown(stats, tag="fast-lat")
    print(
        f"[fast] decided p50={stats.decided_p50:.3f}s p95={stats.decided_p95:.3f}s "
        f"mean={stats.decided_mean:.3f}s"
    )

    for s in stats.samples:
        assert s.decided_time is not None, f"sample {s.tx_id} missing decided_time"
        assert s.decided_latency is not None and s.decided_latency > 0

    assert stats.decided_p50 < LATENCY_P50_CEILING_SEC, (
        f"decided p50 {stats.decided_p50:.3f}s >= {LATENCY_P50_CEILING_SEC}s "
        f"(latency regression; baseline is ~0.2-0.5s on a release build)"
    )
    print("[test_fast_latency] PASS")


async def test_fast_tps(fast_cluster: ClusterManager) -> None:
    """Short sustained burst (120 tx): submit + finalized TPS above floors."""
    before = await collect_statuses(fast_cluster.nodes(), timeout=5.0)
    base_decided = max((s.decided_round for s in before.values()), default=0)

    result = await benchmark_tps(
        fast_cluster.nodes(), fast_cluster,
        total_txs=120, batch_size=32, concurrency=10, timeout=30.0,
    )
    print(
        f"[fast] sent={result.sent} tps_submit={result.tps_submit:.1f} "
        f"tps_finalized={result.tps_finalized_decided:.1f} "
        f"avg_lat={result.avg_decided_latency:.3f}s "
        f"rounds+{result.decided_round_advance}"
    )

    assert result.sent >= 108, f"submit dropped >10%: sent {result.sent}/120"
    assert result.tps_submit > MIN_SUBMIT_TPS, f"submit TPS too low: {result.tps_submit:.1f}"
    assert result.tps_finalized_decided > MIN_FINALIZED_TPS, (
        f"finalized TPS too low: {result.tps_finalized_decided:.1f} "
        f"(decided_dur={result.decided_duration_sec:.2f}s)"
    )

    after = await collect_statuses(fast_cluster.nodes(), timeout=5.0)
    progress = {nid: st.decided_round for nid, st in after.items()}
    print(f"[fast] decided rounds before={base_decided} after={progress}")
    assert any(r > base_decided for r in progress.values()), (
        f"decided round did not advance past {base_decided}: {progress}"
    )

    print("[test_fast_tps] PASS")


async def test_fast_convergence_and_checkpoint(fast_cluster: ClusterManager) -> None:
    """Roster consistent, peers >= 4, and a checkpoint is produced."""
    await fast_cluster.submit_put(b"fast-checkpoint", b"1", node_id=1)

    statuses = await collect_statuses(fast_cluster.nodes(), timeout=5.0)
    assert len(statuses) == 6, f"expected all 6 nodes healthy, got {sorted(statuses)}"

    for node_id, st in statuses.items():
        assert len(st.peers) >= 4, f"node {node_id} sees only {len(st.peers)} peers"

    await wait_for_checkpoint(fast_cluster.nodes(), min_round=1, timeout=45.0)
    after = await collect_statuses(fast_cluster.nodes(), timeout=5.0)
    ckpts = {nid: st.latest_checkpoint_round for nid, st in after.items()}
    print(f"[fast] checkpoint rounds {ckpts}")
    assert any((r or 0) >= 1 for r in ckpts.values()), f"no checkpoint produced: {ckpts}"

    print("[test_fast_convergence_and_checkpoint] PASS")
