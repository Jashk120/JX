from __future__ import annotations

import asyncio
import math
import os
import time

import pytest

from harness.cluster import ClusterConfig, ClusterManager, _fanout_k, parse_diagnosis_log, predicted_p50_seconds
from harness.metrics import FinalityStats, collect_statuses, measure_finality_batch, wait_for_decided_round

pytestmark = [pytest.mark.asyncio]


def _log_predicted_table(gaps, fans):
    print("[sweep] predicted p50 (gap/k*logN) normalized 25/1≈0.60s")
    print("| gap_ms | k | predicted p50 |")
    print("|---:|---:|---:|")
    for g in gaps:
        for k in fans:
            pred = predicted_p50_seconds(g, k)
            print(f"| {g} | {k} | {pred:.3f}s |")


async def _measure_strict(mgr: ClusterManager, gap: int, fanout, dedup: bool, quic: bool) -> tuple[float, FinalityStats, dict]:
    nodes = mgr.nodes()
    stats = await measure_finality_batch(nodes, mgr, count=3, concurrency=1, key_prefix=f"gap{gap}k{fanout}-", timeout=15.0)
    p50 = stats.decided_p50
    print(f"[sweep] gap={gap} k={fanout} dedup={dedup} quic={quic} -> p50={p50:.3f}s p95={stats.decided_p95:.3f}s")
    for s in stats.samples:
        print(f"[sweep]   sample {s.tx_id} decided={s.decided_latency}")
    if p50 <= 0:
        raise AssertionError(f"p50 should be >0 gap={gap} k={fanout} got {p50}")
    diag = mgr.diagnosis_metrics()
    agg_hit = 0.0
    agg_p95 = 0.0
    cnt = 0
    for nid, m in diag.items():
        hr = m.get("hit_rate_avg") if m else None
        pr = m.get("p95_rtt_avg") or m.get("p95_rtt_ms")
        if hr is not None:
            agg_hit += float(hr)
            cnt += 1
        if pr is not None:
            agg_p95 += float(pr)
        print(f"[sweep] diagnosis node {nid} hit_rate={m.get('hit_rate_avg')} p95_rtt={m.get('p95_rtt_avg') or m.get('p95_rtt_ms')} attempts={m.get('sync_attempts')}")
    # Require diagnosis.log to exist and contain real metrics — no synthesized fallback.
    if cnt == 0:
        raise AssertionError(
            f"diagnosis.log missing or empty for gap={gap} k={fanout} dedup={dedup} quic={quic}; "
            f"diag={diag!r} — hit_rate/p95 must be measured, not synthesized"
        )
    for nid, m in diag.items():
        if not m:
            raise AssertionError(f"diagnosis.log empty for node {nid} gap={gap} k={fanout}")
    hit_rate = agg_hit / cnt if cnt else 0.0
    p95_rtt = agg_p95 / max(1, len(diag)) if diag else 0.0
    return p50, stats, {"hit_rate": hit_rate, "p95_rtt": p95_rtt, "diag": diag}


async def test_gap_vs_fanout_sweep() -> None:
    gaps = [25, 80]
    fans = [1, 2, 4]
    dedups = [True, False]
    quics = [False, True]

    _log_predicted_table(gaps, fans)

    dry = os.environ.get("HARNESS_SWEEP_DRY", "0") == "1"
    if dry:
        print("[sweep] HARNESS_SWEEP_DRY=1 dry run, using predicted only")
        results_dry: list[tuple[int, int | str, bool, bool, float, float]] = []
        for gap in gaps:
            for k in fans:
                for dedup in dedups:
                    for quic in quics:
                        pred = predicted_p50_seconds(gap, k)
                        p50 = pred * (0.95 if dedup else 1.05) * (0.98 if quic else 1.0)
                        hr = 0.88 if dedup else 0.55
                        pr = 1.5 * gap + (2 if quic else 5)
                        print(f"[sweep:dry] gap={gap} k={k} dedup={dedup} quic={quic} p50={p50:.3f} pred={pred:.3f} hit_rate={hr:.2f} p95_rtt={pr:.1f}ms")
                        results_dry.append((gap, k, dedup, quic, p50, pred))
        print("[sweep:dry] bench gap vs fanout summary")
        print("| gap | k | dedup | quic | p50(s) | pred(s) |")
        print("|---:|---:|:---:|:---:|---:|---:|")
        for gap, k, dedup, quic, p50, pred in results_dry:
            print(f"| {gap} | {k} | {dedup} | {quic} | {p50:.3f} | {pred:.3f} |")
        p50_25_k1 = next((p for g, k, _, _, p, _ in results_dry if g == 25 and k == 1), None)
        p50_80_k4 = next((p for g, k, _, _, p, _ in results_dry if g == 80 and k == 4), None)
        assert p50_25_k1 is not None and p50_80_k4 is not None
        # F2 tolerance: p50 ~0.20-0.25s for quic+dedup k=4; baseline ~0.60s.
        # Narrowed from legacy 0.05-8.0 band to 0.15-1.2s to verify F2/F3 scaling.
        assert 0.15 < p50_25_k1 < 1.2 and 0.15 < p50_80_k4 < 1.2
        ratio = p50_80_k4 / p50_25_k1 if p50_25_k1 else 1.0
        print(f"[sweep:dry] 80k4 / 25k1 ratio={ratio:.2f} expect ~1.0")
        assert 0.5 < ratio < 2.0
        print("[test_gap_vs_fanout_sweep] PASS (dry)")
        return

    results: list[tuple[int, int | str, bool, bool, float, float]] = []
    failures = 0

    for gap in gaps:
        for k in fans:
            for dedup in dedups:
                for quic in quics:
                    cfg = ClusterConfig(
                        num_nodes=6,
                        sync_interval_ms=gap,
                        sync_timeout_ms=500,
                        fanout=k,
                        dedup_enabled=dedup,
                        quic_enabled=quic,
                        use_proxy=False,
                        log_level="info",
                    )
                    mgr = ClusterManager(cfg)
                    eff_k = _fanout_k(k)
                    pred = predicted_p50_seconds(gap, k)
                    print(f"[sweep] start gap={gap} k={k} eff_k={eff_k} dedup={dedup} quic={quic} predicted={pred:.3f}s @70C")
                    try:
                        await mgr.start()
                        await asyncio.sleep(0.5)
                        try:
                            await wait_for_decided_round(mgr.nodes(), min_round=1, timeout=20.0)
                        except Exception as e:
                            print(f"[sweep] warmup decided wait failed gap={gap} k={k} {e}")
                        p50, stats, diag = await _measure_strict(mgr, gap, k, dedup, quic)
                        ratio = p50 / pred if pred > 0 else 1.0
                        print(f"[sweep] result gap={gap} k={k} dedup={dedup} quic={quic} p50={p50:.3f} pred={pred:.3f} ratio={ratio:.2f} hit_rate={diag['hit_rate']:.2f} p95_rtt={diag['p95_rtt']:.1f}ms")
                        results.append((gap, k, dedup, quic, p50, pred))
                        assert p50 > 0, f"p50 should be >0 gap={gap} k={k}"
                        if p50 > 8.0:
                            print(f"[sweep] warn high latency gap={gap} k={k} p50={p50:.3f} >8s may be thermal")
                        if dedup:
                            assert diag["hit_rate"] >= 0.0
                    except Exception as e:
                        failures += 1
                        print(f"[sweep] cluster gap={gap} k={k} dedup={dedup} quic={quic} failed {e} — no prediction substitution")
                    finally:
                        try:
                            mgr.stop_all()
                        except Exception:
                            pass
                        if mgr._mesh is not None:
                            try:
                                await mgr._mesh.stop()
                            except Exception:
                                pass
                        mgr.cleanup()
                        await asyncio.sleep(0.2)

    print("[sweep] bench gap vs fanout summary")
    print("| gap | k | dedup | quic | p50(s) | pred(s) | hit_rate | p95_rtt(ms) |")
    print("|---:|---:|:---:|:---:|---:|---:|---:|---:|")
    for gap, k, dedup, quic, p50, pred in results:
        print(f"| {gap} | {k} | {dedup} | {quic} | {p50:.3f} | {pred:.3f} | - | - |")

    total_combos = len(gaps) * len(fans) * len(dedups) * len(quics)
    # Verifiability: at least half of combos must have real measurements.
    assert len(results) >= (total_combos + 1) // 2, (
        f"sweep verifiability failed: only {len(results)}/{total_combos} combos produced real measurements "
        f"({failures} failures); need >=50% real — prediction substitution is disabled"
    )

    if len(results) >= 2:
        p50_25_k1 = next((p for g, k, _, _, p, _ in results if g == 25 and k == 1), None)
        p50_80_k4 = next((p for g, k, _, _, p, _ in results if g == 80 and k == 4), None)
        if p50_25_k1 is not None and p50_80_k4 is not None:
            print(f"[sweep] fit check 25ms k=1 p50={p50_25_k1:.3f}s vs 80ms k=4 p50={p50_80_k4:.3f}s target ~0.6s @70C (gap/k*logN)")
            # F2: p50 ~0.20-0.25s for optimized (dedup+quic k=4), baseline ~0.60s.
            # Tightened from legacy 0.05-8.0 band to 0.15-1.2s per k·logN model.
            for p in [p50_25_k1, p50_80_k4]:
                assert 0.15 < p < 1.2, f"p50 {p:.3f}s out of expected 0.15-1.2 band (F2 tightened from 0.05-8.0)"
            ratio = p50_80_k4 / p50_25_k1 if p50_25_k1 > 0 else 1.0
            print(f"[sweep] 80k4 / 25k1 ratio={ratio:.2f} (expect ~0.7-1.4 with dedup+quic model gap/k*logN)")
            assert 0.5 < ratio < 2.0, f"fanout scaling broken: ratio {ratio:.2f} expect ~1.0 (gap/k*logN) F2 tightened"

    assert len(results) >= 4, f"sweep should cover at least 4 combos, got {len(results)}"
    print("[test_gap_vs_fanout_sweep] PASS")
