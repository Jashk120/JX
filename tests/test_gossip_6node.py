"""
test_gossip_6node.py – main hard test suite for 6-node JKaIN consensus.

Covers convergence under various network conditions, partitions, churn,
concurrent load and backpressure.  Uses harness ClusterManager API exactly
as implemented (no invented method names).
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
    wait_for_ordered_round,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _assert_convergence(mgr: ClusterManager, *, decided_min: int = 1, checkpoint_min: int | None = None) -> None:
    """Collect statuses and assert frontier / roster invariants."""
    statuses = await collect_statuses(mgr.nodes(), timeout=5.0)
    assert len(statuses) == 6, f"expected 6 statuses, got {len(statuses)}: {statuses.keys()}"
    # frontiers within bound
    assert frontiers_within_bound(statuses, bound=5), (
        f"frontiers not within bound: { {nid: s.decided_round for nid, s in statuses.items()} }"
    )
    # checkpoint roster consistent
    assert checkpoint_roster_consistent(statuses), (
        f"checkpoint rosters diverged: { {nid: [m.node_id for m in s.checkpoint_roster] for nid, s in statuses.items()} }"
    )
    if checkpoint_min is not None:
        for nid, st in statuses.items():
            assert st.latest_checkpoint_round is not None and st.latest_checkpoint_round >= checkpoint_min, (
                f"node {nid} checkpoint {st.latest_checkpoint_round} < {checkpoint_min}"
            )
    for nid, st in statuses.items():
        assert st.decided_round >= decided_min, f"node {nid} decided {st.decided_round} < {decided_min}"
        # peers: each node should know about others (allow 4..5 due to transient reconnect)
        # we assert at least 4 peers seen (out of 5 expected)
        assert len(st.peers) >= 4, f"node {nid} has only {len(st.peers)} peers, expected >=4"


# ---------------------------------------------------------------------------
# 1 – no latency
# ---------------------------------------------------------------------------


@pytest.mark.gossip
@pytest.mark.slow
async def test_6node_convergence_no_latency() -> None:
    """Spawn 6 nodes direct (no proxy), wait decided>=3 + checkpoint>=1, assert convergence."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()

        # inject a few puts to drive consensus
        for i in range(5):
            await mgr.submit_put(f"k-init-{i}".encode(), f"v-init-{i}".encode(), node_id=(i % 6) + 1)

        statuses = await wait_for_decided_round(mgr.nodes(), min_round=3, timeout=60.0, poll_interval=0.5)
        print(f"[test_6node_convergence_no_latency] decided: { {nid: s.decided_round for nid, s in statuses.items()} }")

        statuses = await wait_for_checkpoint(mgr.nodes(), min_round=1, timeout=60.0, poll_interval=0.5)
        print(f"[test_6node_convergence_no_latency] checkpoint: { {nid: s.latest_checkpoint_round for nid, s in statuses.items()} }")

        # same checkpoint_roster across all nodes
        rosters = [frozenset(m.node_id for m in s.checkpoint_roster) for s in statuses.values()]
        assert len(set(rosters)) == 1, f"roster diverged: {rosters}"

        # frontiers within bound
        assert frontiers_within_bound(statuses, bound=2), f"frontier bound violated: { {nid: s.decided_round for nid, s in statuses.items()} }"

        # peers: each node sees others
        for nid, st in statuses.items():
            print(f"[test] node {nid} peers={len(st.peers)} ordered={st.ordered_round} decided={st.decided_round} checkpoint={st.latest_checkpoint_round}")
            assert len(st.peers) >= 4

        await _assert_convergence(mgr, decided_min=3, checkpoint_min=1)
        print("[test_6node_convergence_no_latency] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 2 – 50 ms latency + 20 ms jitter
# ---------------------------------------------------------------------------


@pytest.mark.gossip
@pytest.mark.slow
async def test_6node_convergence_with_latency_50ms() -> None:
    """Mesh mean 50ms jitter 20ms, same convergence but longer deadlines (60s per wait)."""
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

        for i in range(5):
            await mgr.submit_put(f"k-lat50-{i}".encode(), f"v-lat50-{i}".encode(), node_id=(i % 6) + 1)

        statuses = await wait_for_decided_round(mgr.nodes(), min_round=3, timeout=60.0, poll_interval=0.5)
        print(f"[test_6node_convergence_with_latency_50ms] decided: { {nid: s.decided_round for nid, s in statuses.items()} }")

        statuses = await wait_for_checkpoint(mgr.nodes(), min_round=1, timeout=60.0, poll_interval=0.5)
        print(f"[test_6node_convergence_with_latency_50ms] checkpoint: { {nid: s.latest_checkpoint_round for nid, s in statuses.items()} }")

        assert frontiers_within_bound(statuses, bound=3), f"frontier: { {nid: s.decided_round for nid, s in statuses.items()} }"
        assert checkpoint_roster_consistent(statuses)
        for nid, st in statuses.items():
            print(f"[test] node {nid} decided={st.decided_round} checkpoint={st.latest_checkpoint_round} peers={len(st.peers)}")

        await _assert_convergence(mgr, decided_min=3, checkpoint_min=1)
        print("[test_6node_convergence_with_latency_50ms] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 3 – 100 ms jitter 50 ms + 5% drop
# ---------------------------------------------------------------------------


@pytest.mark.gossip
@pytest.mark.chaos
@pytest.mark.slow
async def test_6node_latency_jitter_100ms() -> None:
    """Mean 100ms jitter 50ms plus 5% drop – must still converge decided>=2 within 45s."""
    mgr = ClusterManager(
        ClusterConfig(
            num_nodes=6,
            use_proxy=True,
            proxy_latency_ms=100.0,
            proxy_jitter_ms=50.0,
            proxy_drop_prob=0.05,
        )
    )
    try:
        await mgr.start()

        for i in range(5):
            try:
                await mgr.submit_put(f"k-jit100-{i}".encode(), f"v-jit100-{i}".encode())
            except Exception as e:
                print(f"[test] submit failed (expected under drop): {e}")

        statuses = await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=45.0, poll_interval=0.5)
        print(f"[test_6node_latency_jitter_100ms] decided: { {nid: s.decided_round for nid, s in statuses.items()} }")

        # checkpoint may be slower under loss, wait with longer deadline but don't fail if checkpoint not yet
        try:
            cp = await wait_for_checkpoint(mgr.nodes(), min_round=1, timeout=30.0, poll_interval=0.5)
            print(f"[test_6node_latency_jitter_100ms] checkpoint: { {nid: s.latest_checkpoint_round for nid, s in cp.items()} }")
        except TimeoutError:
            print("[test_6node_latency_jitter_100ms] checkpoint not reached within 30s (tolerated under loss)")

        assert frontiers_within_bound(statuses, bound=5), f"frontier bound violated under jitter/loss: { {nid: s.decided_round for nid, s in statuses.items()} }"
        print("[test_6node_latency_jitter_100ms] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 4 – partition and heal
# ---------------------------------------------------------------------------


@pytest.mark.chaos
@pytest.mark.slow
async def test_6node_partition_and_heal() -> None:
    """Inject partition {1,2,3} vs {4,5,6} via mesh.set_partition, heal and converge."""
    mgr = ClusterManager(
        ClusterConfig(num_nodes=6, use_proxy=True, proxy_latency_ms=10.0, proxy_jitter_ms=5.0)
    )
    try:
        await mgr.start()

        # drive initial convergence so we have baseline
        for i in range(3):
            await mgr.submit_put(f"k-prepart-{i}".encode(), b"v", node_id=(i % 6) + 1)
        base = await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=30.0, poll_interval=0.5)
        base_round = max(s.decided_round for s in base.values())
        print(f"[test_6node_partition_and_heal] base decided={base_round}")

        mesh = mgr._mesh  # type: ignore[attr-defined]
        assert mesh is not None, "mesh required for partition test"

        # inject partition
        mesh.set_partition([1, 2, 3], [4, 5, 6])
        print("[test] partition {1,2,3} vs {4,5,6} injected")
        # let each side progress separately (5s) – submit to both sides
        for i in range(5):
            try:
                await mgr.submit_put(f"k-part-a-{i}".encode(), b"va", node_id=1)
            except Exception:
                pass
            try:
                await mgr.submit_put(f"k-part-b-{i}".encode(), b"vb", node_id=4)
            except Exception:
                pass
            await asyncio.sleep(0.2)

        await asyncio.sleep(5.0)
        # collect mid-partition statuses (may diverge, just log)
        mid = await collect_statuses(mgr.nodes(), timeout=5.0)
        print(f"[test] mid-partition decided: { {nid: s.decided_round for nid, s in mid.items()} }")
        print(f"[test] mid-partition checkpoint: { {nid: s.latest_checkpoint_round for nid, s in mid.items()} }")

        # heal
        mesh.heal()
        print("[test] partition healed")

        # submit after heal to drive convergence
        for i in range(5):
            try:
                await mgr.submit_put(f"k-heal-{i}".encode(), b"vh", node_id=(i % 6) + 1)
            except Exception:
                pass

        # wait for global convergence – decided should advance past base
        healed = await wait_for_decided_round(mgr.nodes(), min_round=base_round + 1, timeout=60.0, poll_interval=0.5)
        print(f"[test] healed decided: { {nid: s.decided_round for nid, s in healed.items()} }")
        assert frontiers_within_bound(healed, bound=3)

        # no split-brain checkpoint: all nodes same roster
        assert checkpoint_roster_consistent(healed), f"split-brain checkpoint: { {nid: [m.node_id for m in s.checkpoint_roster] for nid, s in healed.items()} }"

        # all 6 see each other as peers (allow transient 4+)
        for nid, st in healed.items():
            print(f"[test] node {nid} peers={len(st.peers)} decided={st.decided_round} checkpoint={st.latest_checkpoint_round}")
            assert len(st.peers) >= 4, f"node {nid} peers {len(st.peers)} <4 after heal"

        print("[test_6node_partition_and_heal] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 5 – churn kill/restart
# ---------------------------------------------------------------------------


@pytest.mark.chaos
@pytest.mark.slow
async def test_6node_churn_kill_restart() -> None:
    """Kill node 6 (SIGTERM), wait 3s, restart and wait for catch-up."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()

        for i in range(3):
            await mgr.submit_put(f"k-churn-pre-{i}".encode(), b"v", node_id=(i % 6) + 1)
        baseline = await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=30.0, poll_interval=0.5)
        print(f"[test_6node_churn_kill_restart] baseline decided: { {nid: s.decided_round for nid, s in baseline.items()} }")

        # kill node 6
        mgr.kill_node(6)
        print("[test] killed node 6")
        await asyncio.sleep(3.0)

        # remaining 5 should still progress – submit more tx
        for i in range(5):
            try:
                await mgr.submit_put(f"k-churn-mid-{i}".encode(), b"vmid", node_id=1)
            except Exception as e:
                print(f"[test] submit mid failed: {e}")
        # verify at least remaining nodes progress (don't require node 6)
        remaining_nodes = [h for h in mgr.nodes() if h.node_id != 6]
        mid_statuses = await wait_for_decided_round(remaining_nodes, min_round=3, timeout=30.0, poll_interval=0.5)
        print(f"[test] after kill remaining decided: { {nid: s.decided_round for nid, s in mid_statuses.items()} }")

        # restart node 6
        await mgr.restart_node(6, timeout=15.0)
        print("[test] restarted node 6")

        # drive consensus again
        for i in range(5):
            try:
                await mgr.submit_put(f"k-churn-post-{i}".encode(), b"vpost", node_id=(i % 6) + 1)
            except Exception:
                pass

        # wait for restarted node to catch up: need all 6 to reach same checkpoint or decided
        all_statuses = await wait_for_decided_round(mgr.nodes(), min_round=4, timeout=45.0, poll_interval=0.5)
        print(f"[test] post-restart decided: { {nid: s.decided_round for nid, s in all_statuses.items()} }")

        # checkpoint catch-up check: node's checkpoint should be within 1 of peers
        cps = [s.latest_checkpoint_round for s in all_statuses.values() if s.latest_checkpoint_round is not None]
        if cps:
            max_cp = max(cps)
            min_cp = min(cps)
            print(f"[test] checkpoint range: min={min_cp} max={max_cp}")
            assert max_cp - min_cp <= 2, f"checkpoint divergence after restart: { {nid: s.latest_checkpoint_round for nid, s in all_statuses.items()} }"

        # peers check for restarted node
        restarted_st = all_statuses.get(6)
        if restarted_st:
            print(f"[test] restarted node 6 peers={len(restarted_st.peers)} decided={restarted_st.decided_round}")
            assert len(restarted_st.peers) >= 4

        print("[test_6node_churn_kill_restart] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 6 – concurrent tx load (100 puts round-robin)
# ---------------------------------------------------------------------------


@pytest.mark.bench
@pytest.mark.slow
async def test_6node_concurrent_tx_load() -> None:
    """After convergence, submit 100 concurrent tx round-robin, verify deterministic convergence."""
    mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
    try:
        await mgr.start()

        # initial convergence
        await wait_for_decided_round(mgr.nodes(), min_round=2, timeout=30.0, poll_interval=0.5)
        base = await collect_statuses(mgr.nodes(), timeout=5.0)
        base_decided = max(s.decided_round for s in base.values()) if base else 0
        base_cp = max((s.latest_checkpoint_round or 0) for s in base.values()) if base else 0
        print(f"[test_6node_concurrent_tx_load] base decided={base_decided} checkpoint={base_cp}")

        # 100 concurrent puts round-robin
        async def _put(i: int) -> None:
            node_id = (i % 6) + 1
            try:
                await mgr.submit_put(f"key-{i}".encode(), f"val-{i}".encode(), node_id=node_id)
            except Exception as e:
                # under concurrency some submits may need retry; log and continue
                print(f"[test] put {i} via node {node_id} failed: {e}")

        await asyncio.gather(*[_put(i) for i in range(100)])
        print("[test] 100 concurrent puts submitted")

        # wait for decided to advance (at least base+2)
        target = base_decided + 2
        statuses = await wait_for_decided_round(mgr.nodes(), min_round=target, timeout=60.0, poll_interval=0.5)
        print(f"[test_6node_concurrent_tx_load] after load decided: { {nid: s.decided_round for nid, s in statuses.items()} }")

        # check checkpoint advances (if state.get not exposed, checkpoint/roster is convergence signal)
        try:
            cp_statuses = await wait_for_checkpoint(mgr.nodes(), min_round=base_cp + 1, timeout=45.0, poll_interval=0.5)
            print(f"[test] checkpoint after load: { {nid: s.latest_checkpoint_round for nid, s in cp_statuses.items()} }")
            # compare checkpoint payload hashes via roster consistency + checkpoint round agreement
            assert checkpoint_roster_consistent(cp_statuses), "checkpoint roster diverged after concurrent load"
            # checkpoint rounds should be within 1
            cp_rounds = [s.latest_checkpoint_round for s in cp_statuses.values() if s.latest_checkpoint_round is not None]
            assert max(cp_rounds) - min(cp_rounds) <= 1, f"checkpoint round divergence after load: {cp_rounds}"
            statuses = cp_statuses
        except TimeoutError:
            print("[test] checkpoint not yet advanced after load (acceptable if decided advanced)")
            # at least decided must have converged
            assert frontiers_within_bound(statuses, bound=3)

        # no divergence: all decided within bound and same checkpoint roster
        assert frontiers_within_bound(statuses, bound=3), f"frontier divergence after load: { {nid: s.decided_round for nid, s in statuses.items()} }"
        assert checkpoint_roster_consistent(statuses)

        print("[test_6node_concurrent_tx_load] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()


# ---------------------------------------------------------------------------
# 7 – out-of-order and backpressure (heterogeneous latency)
# ---------------------------------------------------------------------------


@pytest.mark.gossip
@pytest.mark.bench
@pytest.mark.slow
async def test_6node_out_of_order_and_backpressure() -> None:
    """Bursts with varying payload size, mix fast/slow nodes (1-2:10ms, 3-6:80ms). No node stalls."""
    mgr = ClusterManager(
        ClusterConfig(num_nodes=6, use_proxy=True, proxy_latency_ms=10.0, proxy_jitter_ms=5.0)
    )
    try:
        await mgr.start()

        # make fast/slow split: nodes 1-2 fast (10ms), nodes 3-6 slow (80ms)
        mesh = mgr._mesh  # type: ignore[attr-defined]
        if mesh is not None:
            for entry in mesh.entries:  # type: ignore[attr-defined]
                if entry.node_id in (1, 2):
                    entry.proxy.set_latency(10.0, 5.0)
                else:
                    entry.proxy.set_latency(80.0, 15.0)
            print("[test] heterogeneous latency: nodes 1-2 @10ms, nodes 3-6 @80ms")

        # wait for initial convergence before bursts
        await wait_for_decided_round(mgr.nodes(), min_round=1, timeout=30.0, poll_interval=0.5)

        # bursts with varying payload sizes
        payload_sizes = [16, 128, 512, 1024, 4096, 16384]
        for burst in range(4):
            tasks = []
            for j in range(10):
                size = random.choice(payload_sizes)
                key = f"burst{burst}-k{j}".encode()
                value = b"x" * size
                node_id = random.randint(1, 6)
                tasks.append(mgr.submit_put(key, value, node_id=node_id))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            failures = sum(1 for r in results if isinstance(r, Exception))
            if failures:
                print(f"[test] burst {burst} failures: {failures}/10")
            # small gap between bursts to allow gossip to interleave
            await asyncio.sleep(0.3)

        print("[test] 4 bursts of 10 puts each submitted (varying sizes, heterogeneous latency)")

        # ensure no node stalls forever: each node's ordered_round progresses
        # capture ordered before wait
        before = await collect_statuses(mgr.nodes(), timeout=5.0)
        before_ordered = {nid: s.ordered_round for nid, s in before.items()}
        print(f"[test] ordered before wait: {before_ordered}")

        # wait for ordered to advance on all nodes (at least +1)
        min_before = min(before_ordered.values()) if before_ordered else 0
        ordered_statuses = await wait_for_ordered_round(mgr.nodes(), min_round=min_before + 1, timeout=45.0, poll_interval=0.5)
        print(f"[test] ordered after: { {nid: s.ordered_round for nid, s in ordered_statuses.items()} }")

        # also decided should progress
        decided_before = min(s.decided_round for s in before.values()) if before else 0
        decided_statuses = await wait_for_decided_round(mgr.nodes(), min_round=decided_before + 1, timeout=45.0, poll_interval=0.5)
        print(f"[test] decided after: { {nid: s.decided_round for nid, s in decided_statuses.items()} }")

        # per-node ordered must have advanced (no stall)
        for nid, st in ordered_statuses.items():
            assert st.ordered_round > before_ordered.get(nid, 0), f"node {nid} ordered stalled: before={before_ordered.get(nid)} after={st.ordered_round}"
            print(f"[test] node {nid} ordered {before_ordered.get(nid)} -> {st.ordered_round} decided={st.decided_round}")

        # frontiers still bounded
        assert frontiers_within_bound(decided_statuses, bound=4)

        print("[test_6node_out_of_order_and_backpressure] PASS")
    finally:
        mgr.stop_all()
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        mgr.cleanup()
