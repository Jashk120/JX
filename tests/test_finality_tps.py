"""
test_finality_tps.py – latency-to-finality and TPS hard test suite.

Measures real metrics:
  - latency to finality (submit -> ordered/decided/checkpoint)
  - sustained TPS at 6 nodes under varying network latency

All metrics use harness.metrics helpers (no invented signatures).
"""

from __future__ import annotations

import pytest

from harness.cluster import ClusterConfig, ClusterManager
from harness.metrics import (
    FinalityStats,
    TpsResult,
    benchmark_tps,
    collect_statuses,
    measure_finality_batch,
    measure_single_finality,
    print_phase_breakdown,
    wait_for_decided_round,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _print_histogram(tag: str, stats: FinalityStats) -> None:
    """Print p50/p95/p99 for ordered/decided/checkpoint + phase breakdown."""
    print(f"[finality:{tag}] count={stats.count}")
    print(
        f"[finality:{tag}] ordered    p50={stats.ordered_p50:.3f}s "
        f"p95={stats.ordered_p95:.3f}s p99={stats.ordered_p99:.3f}s mean={stats.ordered_mean:.3f}s"
    )
    print(
        f"[finality:{tag}] decided    p50={stats.decided_p50:.3f}s "
        f"p95={stats.decided_p95:.3f}s p99={stats.decided_p99:.3f}s mean={stats.decided_mean:.3f}s"
    )
    print(
        f"[finality:{tag}] checkpoint p50={stats.checkpoint_p50:.3f}s "
        f"p95={stats.checkpoint_p95:.3f}s p99={stats.checkpoint_p99:.3f}s mean={stats.checkpoint_mean:.3f}s"
    )
    # phase breakdown: gossip (submit->ordered), consensus (ordered->decided), checkpoint (decided->checkpoint)
    print_phase_breakdown(stats, tag=tag)
    # per-sample latency dump for triage (includes phase fields)
    for s in stats.samples:
        print(
            f"[finality:{tag}]   sample {s.tx_id} "
            f"ordered={s.ordered_latency:.3f} decided={s.decided_latency:.3f} checkpoint={s.checkpoint_latency} "
            f"gossip={s.gossip_phase} consensus={s.consensus_phase} ck_phase={s.checkpoint_phase}"
        )


def _print_tps(tag: str, result: TpsResult) -> None:
    print(f"[tps:{tag}] sent={result.sent} tps_submit={result.tps_submit:.1f} "
          f"tps_decided={result.tps_finalized_decided:.1f} "
          f"tps_checkpoint={result.tps_finalized_checkpoint:.1f} "
          f"avg_lat={result.avg_decided_latency:.3f}s "
          f"submit_dur={result.submit_duration_sec:.2f}s decided_dur={result.decided_duration_sec:.2f}s "
          f"rounds +{result.decided_round_advance} / +{result.checkpoint_round_advance} "
          f"baseline_decided={result.baseline_decided} final_decided={result.final_decided}")


async def _wait_baseline_decided(mgr: ClusterManager) -> None:
    """Ensure cluster has at least one decided round before measuring."""
    # Drive a couple puts then wait – gives baseline rounds for latency helpers.
    for i in range(3):
        await mgr.submit_put(f"k-baseline-{i}".encode(), b"v", node_id=(i % 6) + 1)
    await wait_for_decided_round(mgr.nodes(), min_round=1, timeout=30.0, poll_interval=0.5)
    st = await collect_statuses(mgr.nodes(), timeout=5.0)
    print(f"[finality] baseline decided: {{{', '.join(f'{nid}:{s.decided_round}' for nid, s in st.items())}}}")


# ---------------------------------------------------------------------------
# 1 – single isolated TX, direct (no proxy)
# ---------------------------------------------------------------------------


@pytest.mark.finality
@pytest.mark.slow
async def test_latency_single_tx_direct() -> None:
    """6 nodes no proxy, 10 isolated puts concurrency=1, median decided <5s."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()
        await _wait_baseline_decided(mgr)

        stats: FinalityStats = await measure_finality_batch(
            mgr.nodes(), mgr, count=10, concurrency=1, key_prefix="direct-", timeout=30.0
        )
        _print_histogram("direct-10", stats)

        # All samples must have decided_time
        for s in stats.samples:
            assert s.decided_time is not None, f"sample {s.tx_id} missing decided_time"
            assert s.decided_latency is not None and s.decided_latency > 0

        print(f"[finality] decided p50={stats.decided_p50:.3f}s p95={stats.decided_p95:.3f}s p99={stats.decided_p99:.3f}s")
        assert stats.decided_p50 < 5.0, f"median decided latency too high direct: {stats.decided_p50:.3f}s"

        print("[test_latency_single_tx_direct] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 2 – 50ms mesh, 15 sequential samples
# ---------------------------------------------------------------------------


@pytest.mark.finality
@pytest.mark.slow
async def test_latency_histogram_under_50ms() -> None:
    """LatencyMesh mean 50ms jitter 20ms, 15 sequential samples, p50<8s p95<12s."""
    mgr = ClusterManager(
        ClusterConfig(
            num_nodes=6,
            use_proxy=True,
            proxy_latency_ms=50.0,
            proxy_jitter_ms=20.0,
        )
    )
    try:
        await mgr.start()
        await _wait_baseline_decided(mgr)

        stats = await measure_finality_batch(
            mgr.nodes(), mgr, count=15, concurrency=1, key_prefix="mesh50-", timeout=30.0
        )
        _print_histogram("mesh50-15", stats)

        for s in stats.samples:
            assert s.decided_time is not None, f"sample {s.tx_id} missing decided_time"

        print(f"[finality] mesh50 decided p50={stats.decided_p50:.3f}s p95={stats.decided_p95:.3f}s p99={stats.decided_p99:.3f}s")
        assert stats.decided_p50 < 8.0, f"mesh50 p50 too high: {stats.decided_p50:.3f}s"
        assert stats.decided_p95 < 12.0, f"mesh50 p95 too high: {stats.decided_p95:.3f}s"

        print("[test_latency_histogram_under_50ms] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 3 – sweep [0,30,80] ms
# ---------------------------------------------------------------------------


@pytest.mark.finality
@pytest.mark.bench
@pytest.mark.slow
async def test_latency_vs_network_sweep() -> None:
    """Spawn fresh cluster per latency point, measure 8 tx batch, build markdown table."""
    sweep = [0, 30, 80]
    results: list[tuple[int, FinalityStats]] = []

    for mean_ms in sweep:
        use_proxy = mean_ms != 0
        # jitter ~ 40% of mean
        jitter = int(mean_ms * 0.4) if mean_ms else 0
        cfg = ClusterConfig(
            num_nodes=6,
            use_proxy=use_proxy,
            proxy_latency_ms=float(mean_ms) if use_proxy else 0.0,
            proxy_jitter_ms=float(jitter) if use_proxy else 0.0,
        )
        mgr = ClusterManager(cfg)
        try:
            await mgr.start()
            await _wait_baseline_decided(mgr)

            stats = await measure_finality_batch(
                mgr.nodes(), mgr, count=8, concurrency=1,
                key_prefix=f"sweep{mean_ms}-", timeout=30.0,
            )
            _print_histogram(f"sweep-{mean_ms}ms", stats)
            results.append((mean_ms, stats))
        finally:
            mgr.stop_all()
            if mgr._mesh is not None:
                try:
                    await mgr._mesh.stop()
                except Exception:
                    pass
            mgr.cleanup()

    # build markdown table
    print("[finality] latency vs network sweep")
    print("| mesh mean (ms) | decided p50 (s) | p95 (s) | p99 (s) | mean (s) | ordered p50 (s) | checkpoint p50 (s) |")
    print("|---:|---:|---:|---:|---:|---:|---:|")
    for mean_ms, stats in results:
        print(
            f"| {mean_ms} | {stats.decided_p50:.3f} | {stats.decided_p95:.3f} | "
            f"{stats.decided_p99:.3f} | {stats.decided_mean:.3f} | "
            f"{stats.ordered_p50:.3f} | {stats.checkpoint_p50:.3f} |"
        )

    # Assert monotonic-ish: 80ms p50 > 0ms p50
    p50_0 = results[0][1].decided_p50
    p50_80 = results[2][1].decided_p50
    print(f"[finality] sweep p50: 0ms={p50_0:.3f}s  30ms={results[1][1].decided_p50:.3f}s  80ms={p50_80:.3f}s")
    assert p50_80 > p50_0, f"expected 80ms p50 ({p50_80:.3f}s) > 0ms p50 ({p50_0:.3f}s)"

    print("[test_latency_vs_network_sweep] PASS")


# ---------------------------------------------------------------------------
# 4 – TPS sustained 6 node
# ---------------------------------------------------------------------------


@pytest.mark.tps
@pytest.mark.bench
@pytest.mark.slow
async def test_tps_sustained_6node() -> None:
    """No proxy, 500 tx burst, then 1000 tx backpressure check."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()
        await _wait_baseline_decided(mgr)

        result: TpsResult = await benchmark_tps(
            mgr.nodes(), mgr,
            total_txs=500, batch_size=64, concurrency=10, timeout=60.0,
        )
        _print_tps("direct-500", result)
        print(f"[tps] phase1: sent={result.sent} duration={result.duration_sec:.2f}s "
              f"tps_submit={result.tps_submit:.1f} tps_finalized={result.tps_finalized_decided:.1f} "
              f"avg_lat={result.avg_decided_latency:.3f}s rounds+{result.decided_round_advance}")

        assert result.tps_finalized_decided > 20.0, f"TPS finalized too low: {result.tps_finalized_decided:.1f}"
        assert result.tps_submit > 50.0, f"TPS submit too low: {result.tps_submit:.1f}"
        assert result.decided_round_advance is not None and result.decided_round_advance >= 1

        # Second phase: burst to test backpressure (MAX_PENDING 1024)
        # Need a small pause to let previous checkpoint catch up, then burst 1000
        await wait_for_decided_round(mgr.nodes(), min_round=(result.final_decided or 0) + 1, timeout=30.0)

        result2: TpsResult = await benchmark_tps(
            mgr.nodes(), mgr,
            total_txs=1000, batch_size=64, concurrency=10, timeout=60.0,
        )
        _print_tps("direct-1000", result2)
        print(f"[tps] phase2 burst 1000: tps_submit={result2.tps_submit:.1f} tps_finalized={result2.tps_finalized_decided:.1f}")

        # Not dropping >10% : sent should be 1000
        assert result2.sent >= 900, f"burst dropped >10%: sent {result2.sent}/1000"
        assert result2.tps_finalized_decided > 10.0, f"burst TPS too low: {result2.tps_finalized_decided:.1f}"

        print("[test_tps_sustained_6node] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 5 – TPS under 50ms mesh
# ---------------------------------------------------------------------------


@pytest.mark.tps
@pytest.mark.bench
@pytest.mark.slow
async def test_tps_under_latency_50ms() -> None:
    """50ms mesh TPS, show degradation vs direct."""
    # First capture direct TPS for comparison (short run to avoid duplication with test 4)
    direct_res: TpsResult | None = None
    mgr_direct = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr_direct.start()
        await _wait_baseline_decided(mgr_direct)
        direct_res = await benchmark_tps(
            mgr_direct.nodes(), mgr_direct,
            total_txs=300, batch_size=64, concurrency=10, timeout=60.0,
        )
        _print_tps("direct-300-ref", direct_res)
    finally:
        mgr_direct.stop_all()
        if mgr_direct._mesh is not None:
            try:
                await mgr_direct._mesh.stop()
            except Exception:
                pass
        mgr_direct.cleanup()

    # Under latency
    mgr = ClusterManager(
        ClusterConfig(num_nodes=6, use_proxy=True, proxy_latency_ms=50.0, proxy_jitter_ms=20.0)
    )
    try:
        await mgr.start()
        await _wait_baseline_decided(mgr)

        wan_res: TpsResult = await benchmark_tps(
            mgr.nodes(), mgr,
            total_txs=300, batch_size=64, concurrency=10, timeout=60.0,
        )
        _print_tps("wan50-300", wan_res)

        assert wan_res.tps_finalized_decided > 10.0, f"WAN TPS too low: {wan_res.tps_finalized_decided:.1f}"

        # Comparison table
        assert direct_res is not None
        print("[tps] comparison (300 tx)")
        print("| network | tps_submit | tps_finalized | avg_lat (s) | decided rounds |")
        print("|---|---:|---:|---:|---:|")
        print(f"| direct | {direct_res.tps_submit:.1f} | {direct_res.tps_finalized_decided:.1f} | "
              f"{direct_res.avg_decided_latency:.3f} | {direct_res.decided_round_advance} |")
        print(f"| 50ms mesh | {wan_res.tps_submit:.1f} | {wan_res.tps_finalized_decided:.1f} | "
              f"{wan_res.avg_decided_latency:.3f} | {wan_res.decided_round_advance} |")
        # WAN should be slower but still >10 tps
        # Also expect submit TPS under WAN may be lower due to proxy delay on submit
        print(f"[tps] direct finalized {direct_res.tps_finalized_decided:.1f} vs WAN {wan_res.tps_finalized_decided:.1f}")

        print("[test_tps_under_latency_50ms] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 6 – throughput vs latency tradeoff (optional)
# ---------------------------------------------------------------------------


@pytest.mark.tps
@pytest.mark.bench
@pytest.mark.slow
async def test_throughput_latency_tradeoff() -> None:
    """Vary batch concurrency 5/10/20, record TPS vs avg latency curve."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()
        await _wait_baseline_decided(mgr)

        rows: list[tuple[int, TpsResult]] = []
        for conc in [5, 10, 20]:
            # Small wait between runs to avoid overlapping backpressure
            if rows:
                try:
                    await wait_for_decided_round(mgr.nodes(), min_round=(rows[-1][1].final_decided or 0) + 1, timeout=30.0)
                except TimeoutError:
                    pass
            res = await benchmark_tps(
                mgr.nodes(), mgr,
                total_txs=300, batch_size=64, concurrency=conc, timeout=60.0,
            )
            _print_tps(f"tradeoff-c{conc}", res)
            rows.append((conc, res))
            print(f"[tradeoff] concurrency={conc} tps_submit={res.tps_submit:.1f} "
                  f"tps_finalized={res.tps_finalized_decided:.1f} avg_lat={res.avg_decided_latency:.3f}s")

        print("[tradeoff] TPS vs latency curve")
        print("| concurrency | tps_submit | tps_finalized | avg_lat (s) |")
        print("|---:|---:|---:|---:|")
        for conc, res in rows:
            print(f"| {conc} | {res.tps_submit:.1f} | {res.tps_finalized_decided:.1f} | {res.avg_decided_latency:.3f} |")

        # Basic sanity: none should be zero
        for conc, res in rows:
            assert res.tps_submit > 20.0, f"concurrency {conc} tps_submit too low: {res.tps_submit:.1f}"
            assert res.tps_finalized_decided > 10.0, f"concurrency {conc} tps_finalized too low: {res.tps_finalized_decided:.1f}"

        print("[test_throughput_latency_tradeoff] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:
            try:
                await mgr._mesh.stop()
            except Exception:
                pass
        mgr.cleanup()
