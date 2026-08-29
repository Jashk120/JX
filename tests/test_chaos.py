"""
test_chaos.py – additional chaos scenarios for 6-node consensus.

- random latency chaos (60s with 5s randomization)
- isolate-single-node then heal
"""

from __future__ import annotations

import asyncio
import random

import pytest

from harness.cluster import ClusterConfig, ClusterManager
from harness.metrics import (
    checkpoint_roster_consistent,
    collect_statuses,
    frontiers_within_bound,
    wait_for_checkpoint,
    wait_for_decided_round,
)

pytestmark = pytest.mark.asyncio


@pytest.mark.chaos
@pytest.mark.bench
@pytest.mark.slow
async def test_random_latency_chaos() -> None:
    """60s chaos: every 5s randomize mesh latency 10..150ms and drop 0..10%."""
    mgr = ClusterManager(
        ClusterConfig(num_nodes=6, use_proxy=True, proxy_latency_ms=20.0, proxy_jitter_ms=5.0)
    )
    try:
        await mgr.start()

        # seed traffic
        for i in range(5):
            try:
                await mgr.submit_put(f"k-chaos-seed-{i}".encode(), b"v", node_id=(i % 6) + 1)
            except Exception:
                pass

        mesh = mgr._mesh  # type: ignore[attr-defined]
        assert mesh is not None

        # background chaos: randomize every 5s for 60s
        stop_chaos = asyncio.Event()

        async def _chaos_loop() -> None:
            start = asyncio.get_event_loop().time()
            while not stop_chaos.is_set() and (asyncio.get_event_loop().time() - start) < 60.0:
                mean = random.uniform(10, 150)
                jitter = random.uniform(0, min(50, mean * 0.5))
                drop = random.uniform(0, 0.10)
                mesh.set_latency(mean, jitter)
                mesh.set_drop_prob(drop)
                print(f"[chaos] latency mean={mean:.1f}ms jitter={jitter:.1f}ms drop={drop:.2%}")
                # also submit a tx during chaos
                try:
                    await mgr.submit_put(
                        f"k-chaos-{random.randint(0, 9999)}".encode(),
                        b"x" * random.randint(8, 256),
                        node_id=random.randint(1, 6),
                    )
                except Exception as e:
                    print(f"[chaos] submit failed: {e}")
                try:
                    await asyncio.wait_for(stop_chaos.wait(), timeout=5.0)
                    break
                except asyncio.TimeoutError:
                    continue

        chaos_task = asyncio.create_task(_chaos_loop())

        # wait for initial convergence before chaos fully ramps
        try:
            await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=30.0, poll_interval=0.5)
            print("[test_random_latency_chaos] initial convergence reached before/within chaos window")
        except TimeoutError as e:
            print(f"[test_random_latency_chaos] initial convergence delayed under chaos: {e}")

        # let chaos run its full 60s
        try:
            await asyncio.wait_for(chaos_task, timeout=65.0)
        except asyncio.TimeoutError:
            stop_chaos.set()
            chaos_task.cancel()
            try:
                await chaos_task
            except asyncio.CancelledError:
                pass

        print("[test_random_latency_chaos] chaos window done, stabilizing")

        # stabilize mesh to healthy params and drive final convergence
        mesh.set_latency(15.0, 5.0)
        mesh.set_drop_prob(0.0)
        await asyncio.sleep(1.0)
        for i in range(5):
            try:
                await mgr.submit_put(f"k-chaos-final-{i}".encode(), b"vf", node_id=(i % 6) + 1)
            except Exception:
                pass

        statuses = await wait_for_decided_round(mgr.nodes(), min_round=3, timeout=45.0, poll_interval=0.5)
        print(f"[test_random_latency_chaos] final decided: { {nid: s.decided_round for nid, s in statuses.items()} }")

        assert frontiers_within_bound(statuses, bound=5), f"frontier after chaos: { {nid: s.decided_round for nid, s in statuses.items()} }"
        # checkpoint may be delayed under chaos, but roster should be consistent
        assert checkpoint_roster_consistent(statuses)

        print("[test_random_latency_chaos] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


@pytest.mark.chaos
@pytest.mark.slow
async def test_isolate_single_node() -> None:
    """Isolate node 6 via mesh.isolate_node(6), ensure remaining 5 still converge, then heal."""
    mgr = ClusterManager(
        ClusterConfig(num_nodes=6, use_proxy=True, proxy_latency_ms=10.0, proxy_jitter_ms=5.0)
    )
    try:
        await mgr.start()

        # initial convergence baseline
        for i in range(3):
            await mgr.submit_put(f"k-iso-pre-{i}".encode(), b"v", node_id=(i % 6) + 1)
        baseline = await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=30.0, poll_interval=0.5)
        baseline_round = max(s.decided_round for s in baseline.values())
        print(f"[test_isolate_single_node] baseline decided={baseline_round}")

        mesh = mgr._mesh  # type: ignore[attr-defined]
        assert mesh is not None

        # isolate node 6 (ingress blocked, rest healthy)
        mesh.isolate_node(6)
        print("[test] isolated node 6")

        # submit to majority (nodes 1-5) and let them progress
        for i in range(5):
            try:
                await mgr.submit_put(f"k-iso-major-{i}".encode(), b"vmajor", node_id=1)
            except Exception as e:
                print(f"[test] submit to majority failed: {e}")

        await asyncio.sleep(3.0)

        # remaining 5 should still converge (decided advances)
        majority_nodes = [h for h in mgr.nodes() if h.node_id != 6]
        majority_statuses = await wait_for_decided_round(
            majority_nodes, min_round=baseline_round + 1, timeout=45.0, poll_interval=0.5
        )
        print(f"[test] majority decided while isolated: { {nid: s.decided_round for nid, s in majority_statuses.items()} }")
        assert frontiers_within_bound(majority_statuses, bound=3)
        assert checkpoint_roster_consistent(majority_statuses)
        # majority peers should see 4 others (within majority)
        for nid, st in majority_statuses.items():
            print(f"[test] majority node {nid} peers={len(st.peers)} decided={st.decided_round}")

        # check isolated node is indeed behind or stalled (optional, not strict)
        isolated = await collect_statuses([h for h in mgr.nodes() if h.node_id == 6], timeout=3.0)
        if isolated:
            iso_st = isolated[6]
            print(f"[test] isolated node 6 decided={iso_st.decided_round} checkpoint={iso_st.latest_checkpoint_round} peers={len(iso_st.peers)}")

        # heal
        mesh.heal()
        print("[test] healed isolation of node 6")
        # stabilize: submit after heal
        for i in range(5):
            try:
                await mgr.submit_put(f"k-iso-heal-{i}".encode(), b"vheal", node_id=(i % 6) + 1)
            except Exception:
                pass

        # all 6 should converge again
        healed = await wait_for_decided_round(mgr.nodes(), min_round=baseline_round + 2, timeout=60.0, poll_interval=0.5)
        print(f"[test] healed global decided: { {nid: s.decided_round for nid, s in healed.items()} }")

        assert frontiers_within_bound(healed, bound=4), f"frontier after heal: { {nid: s.decided_round for nid, s in healed.items()} }"
        assert checkpoint_roster_consistent(healed)

        # all nodes see peers
        for nid, st in healed.items():
            print(f"[test] node {nid} peers={len(st.peers)} decided={st.decided_round} checkpoint={st.latest_checkpoint_round}")
            assert len(st.peers) >= 4, f"node {nid} peers {len(st.peers)} <4 after heal"

        # optional checkpoint catch-up for previously isolated node
        try:
            cp = await wait_for_checkpoint(mgr.nodes(), min_round=1, timeout=30.0, poll_interval=0.5)
            print(f"[test] checkpoint after heal: { {nid: s.latest_checkpoint_round for nid, s in cp.items()} }")
        except TimeoutError:
            print("[test] checkpoint not yet advanced after heal (tolerated)")

        print("[test_isolate_single_node] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()
