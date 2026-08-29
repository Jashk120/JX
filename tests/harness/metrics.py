"""
metrics.py – convergence helpers for hardening tests.

Collects StatusReport from multiple nodes in parallel and provides
wait predicates for decided_round / checkpoint progress.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Tuple

from .cluster import NodeHandle
from .control import ControlClient, StatusReport


async def collect_statuses(
    nodes: List[NodeHandle],
    timeout: float = 5.0,
) -> Dict[int, StatusReport]:
    """Fetch StatusReport from each node in parallel. Missing nodes are omitted."""
    async def _fetch(h: NodeHandle) -> Tuple[int, Optional[StatusReport]]:
        try:
            client = ControlClient(h.control_socket, timeout=timeout, retries=1)
            st = await client.status()
            return (h.node_id, st)
        except Exception:
            return (h.node_id, None)

    results = await asyncio.gather(*[_fetch(n) for n in nodes])
    return {nid: st for nid, st in results if st is not None}


async def wait_for_decided_round(
    nodes: List[NodeHandle],
    min_round: int,
    timeout: float = 30.0,
    poll_interval: float = 0.5,
    require_all: bool = True,
) -> Dict[int, StatusReport]:
    """
    Poll until every (or any, if require_all=False) node reaches decided_round >= min_round.
    Returns the last statuses dict on success; raises TimeoutError on failure.
    """
    deadline = time.monotonic() + timeout
    last: Dict[int, StatusReport] = {}
    while time.monotonic() < deadline:
        last = await collect_statuses(nodes)
        if require_all:
            if last and all(s.decided_round >= min_round for s in last.values()) and len(last) == len(nodes):
                return last
        else:
            if any(s.decided_round >= min_round for s in last.values()):
                return last
        await asyncio.sleep(poll_interval)
    raise TimeoutError(
        f"wait_for_decided_round min_round={min_round} not reached within {timeout}s; "
        f"last: { {nid: s.decided_round for nid, s in last.items()} }"
    )


async def wait_for_checkpoint(
    nodes: List[NodeHandle],
    min_round: int,
    timeout: float = 30.0,
    poll_interval: float = 0.5,
    require_all: bool = True,
) -> Dict[int, StatusReport]:
    """
    Poll until latest_checkpoint_round >= min_round.
    Nodes with latest_checkpoint_round is None are considered not ready.
    """
    deadline = time.monotonic() + timeout
    last: Dict[int, StatusReport] = {}
    while time.monotonic() < deadline:
        last = await collect_statuses(nodes)
        def _ok(s: StatusReport) -> bool:
            return s.latest_checkpoint_round is not None and s.latest_checkpoint_round >= min_round  # type: ignore

        if require_all:
            if last and all(_ok(s) for s in last.values()) and len(last) == len(nodes):
                return last
        else:
            if any(_ok(s) for s in last.values()):
                return last
        await asyncio.sleep(poll_interval)
    raise TimeoutError(
        f"wait_for_checkpoint min_round={min_round} not reached within {timeout}s; "
        f"last: { {nid: s.latest_checkpoint_round for nid, s in last.items()} }"
    )


async def wait_for_ordered_round(
    nodes: List[NodeHandle],
    min_round: int,
    timeout: float = 30.0,
    poll_interval: float = 0.5,
) -> Dict[int, StatusReport]:
    """Poll until all nodes reach ordered_round >= min_round."""
    deadline = time.monotonic() + timeout
    last: Dict[int, StatusReport] = {}
    while time.monotonic() < deadline:
        last = await collect_statuses(nodes)
        if last and all(s.ordered_round >= min_round for s in last.values()) and len(last) == len(nodes):
            return last
        await asyncio.sleep(poll_interval)
    raise TimeoutError(
        f"wait_for_ordered_round min_round={min_round} not reached within {timeout}s; "
        f"last: { {nid: s.ordered_round for nid, s in last.items()} }"
    )


async def wait_for_state_convergence(
    nodes: List[NodeHandle],
    timeout: float = 30.0,
    poll_interval: float = 0.5,
) -> Dict[int, StatusReport]:
    """
    Wait until all nodes agree on decided_round and checkpoint_roster.
    Useful as a generic "frontiers converged" check.

    Returns last statuses; raises if frontiers diverge past bound.
    """
    deadline = time.monotonic() + timeout
    last: Dict[int, StatusReport] = {}
    while time.monotonic() < deadline:
        last = await collect_statuses(nodes)
        if len(last) != len(nodes):
            await asyncio.sleep(poll_interval)
            continue
        decided = {s.decided_round for s in last.values()}
        if len(decided) == 1:
            # also check checkpoint roster divergence (stall signal)
            rosters = [tuple(sorted(m.node_id for m in s.checkpoint_roster)) for s in last.values()]
            # Empty roster on all nodes is considered converged (pre-checkpoint)
            if len(set(rosters)) == 1:
                return last
        await asyncio.sleep(poll_interval)
    raise TimeoutError(
        f"wait_for_state_convergence not reached within {timeout}s; "
        f"decided: { {nid: s.decided_round for nid, s in last.items()} }, "
        f"checkpoint: { {nid: s.latest_checkpoint_round for nid, s in last.items()} }"
    )


def frontiers_within_bound(
    statuses: Dict[int, StatusReport],
    bound: int = 2,
) -> bool:
    """
    Check that max decided_round - min decided_round <= bound.
    Returns True if within bound, False otherwise.
    """
    if not statuses:
        return False
    rounds = [s.decided_round for s in statuses.values()]
    return max(rounds) - min(rounds) <= bound


def checkpoint_roster_consistent(statuses: Dict[int, StatusReport]) -> bool:
    """
    Check that all nodes' checkpoint_roster agree (no silent stall).
    Empty rosters (no checkpoint yet) count as consistent if all empty.
    """
    if not statuses:
        return False
    rosters = [frozenset(m.node_id for m in s.checkpoint_roster) for s in statuses.values()]
    return len(set(rosters)) == 1


async def submit_until_decided(
    nodes: List[NodeHandle],
    payload: bytes,
    target_round: int,
    timeout: float = 30.0,
) -> Dict[int, StatusReport]:
    """
    Submit payload to a node, then wait for decided_round to advance.
    Convenience for liveness checks.
    """
    client = ControlClient(nodes[0].control_socket, timeout=5.0)
    await client.submit_tx(payload)
    return await wait_for_decided_round(nodes, target_round, timeout=timeout)


# ---------------------------------------------------------------------------
# Latency-to-finality & TPS measurement
# ---------------------------------------------------------------------------

import uuid as _uuid
from dataclasses import dataclass, field


@dataclass
class FinalitySample:
    """Per-transaction latency sample across three finality levels.

    Phase breakdown fields are derived from the absolute latencies / times:
      gossip_phase    = submit -> ordered   (dissemination via gossip)
      consensus_phase = ordered -> decided  (consensus ordering to finality)
      checkpoint_phase= decided -> checkpoint (checkpoint persistence)

    All phase fields are optional (None if prerequisite time is missing).
    """

    tx_id: str
    key: bytes
    submit_time: float  # monotonic
    ordered_time: Optional[float] = None
    decided_time: Optional[float] = None
    checkpoint_time: Optional[float] = None
    ordered_latency: Optional[float] = None
    decided_latency: Optional[float] = None
    checkpoint_latency: Optional[float] = None
    # --- phase breakdown (differences) ---
    gossip_phase: Optional[float] = None
    consensus_phase: Optional[float] = None
    checkpoint_phase: Optional[float] = None

    # Back-compat aliases / computed properties for phase latencies
    @property
    def gossip_latency(self) -> Optional[float]:
        """Alias for gossip_phase: submit -> ordered."""
        return self.gossip_phase

    @property
    def consensus_latency(self) -> Optional[float]:
        """Alias for consensus_phase: ordered -> decided."""
        return self.consensus_phase

    @property
    def checkpoint_phase_latency(self) -> Optional[float]:
        """Alias for checkpoint_phase: decided -> checkpoint."""
        return self.checkpoint_phase


@dataclass
class PhaseSample:
    """Explicit phase breakdown per transaction (differences)."""

    tx_id: str
    gossip_latency: Optional[float] = None  # submit -> ordered
    consensus_latency: Optional[float] = None  # ordered -> decided
    checkpoint_latency: Optional[float] = None  # decided -> checkpoint

    @classmethod
    def from_finality(cls, s: FinalitySample) -> "PhaseSample":
        return cls(
            tx_id=s.tx_id,
            gossip_latency=s.gossip_phase,
            consensus_latency=s.consensus_phase,
            checkpoint_latency=s.checkpoint_phase,
        )


def _quantile(sorted_vals: List[float], q: float) -> float:
    """Linear-interpolation quantile. sorted_vals must be sorted ascending."""
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sorted_vals[0])
    # clamp q to [0,1]
    if q <= 0:
        return float(sorted_vals[0])
    if q >= 1:
        return float(sorted_vals[-1])
    pos = (n - 1) * q
    lo = int(pos)
    hi = lo + 1
    frac = pos - lo
    if hi >= n:
        return float(sorted_vals[lo])
    return float(sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac)


def _mean(vals: List[float]) -> float:
    if not vals:
        return 0.0
    return float(sum(vals) / len(vals))


@dataclass
class PhaseStats:
    """Aggregated phase breakdown statistics (gossip/consensus/checkpoint)."""

    count: int
    gossip_p50: float
    gossip_p95: float
    gossip_p99: float
    gossip_mean: float
    consensus_p50: float
    consensus_p95: float
    consensus_p99: float
    consensus_mean: float
    checkpoint_p50: float
    checkpoint_p95: float
    checkpoint_p99: float
    checkpoint_mean: float
    # total (decided) for reference – same quantile as FinalityStats.decided_*
    total_p50: float = 0.0
    total_p95: float = 0.0
    total_p99: float = 0.0
    total_mean: float = 0.0

    @classmethod
    def from_samples(cls, samples: List[FinalitySample]) -> "PhaseStats":
        def _qs(latencies: List[float]) -> tuple[float, float, float, float]:
            if not latencies:
                return (0.0, 0.0, 0.0, 0.0)
            s = sorted(latencies)
            return (
                _quantile(s, 0.5),
                _quantile(s, 0.95),
                _quantile(s, 0.99),
                _mean(s),
            )

        gossip_vals = [s.gossip_phase for s in samples if s.gossip_phase is not None]
        consensus_vals = [s.consensus_phase for s in samples if s.consensus_phase is not None]
        checkpoint_vals = [s.checkpoint_phase for s in samples if s.checkpoint_phase is not None]
        decided_vals = [s.decided_latency for s in samples if s.decided_latency is not None]
        g_p50, g_p95, g_p99, g_mean = _qs(gossip_vals)  # type: ignore
        c_p50, c_p95, c_p99, c_mean = _qs(consensus_vals)  # type: ignore
        ck_p50, ck_p95, ck_p99, ck_mean = _qs(checkpoint_vals)  # type: ignore
        t_p50, t_p95, t_p99, t_mean = _qs(decided_vals)  # type: ignore
        return cls(
            count=len(samples),
            gossip_p50=g_p50,
            gossip_p95=g_p95,
            gossip_p99=g_p99,
            gossip_mean=g_mean,
            consensus_p50=c_p50,
            consensus_p95=c_p95,
            consensus_p99=c_p99,
            consensus_mean=c_mean,
            checkpoint_p50=ck_p50,
            checkpoint_p95=ck_p95,
            checkpoint_p99=ck_p99,
            checkpoint_mean=ck_mean,
            total_p50=t_p50,
            total_p95=t_p95,
            total_p99=t_p99,
            total_mean=t_mean,
        )


@dataclass
class FinalityStats:
    """Aggregated finality latency statistics."""

    count: int
    ordered_p50: float
    ordered_p95: float
    ordered_p99: float
    ordered_mean: float
    decided_p50: float
    decided_p95: float
    decided_p99: float
    decided_mean: float
    checkpoint_p50: float
    checkpoint_p95: float
    checkpoint_p99: float
    checkpoint_mean: float
    samples: List[FinalitySample] = field(default_factory=list)
    # --- phase breakdown (new fields, keep backward compat with defaults) ---
    gossip_p50: float = 0.0
    gossip_p95: float = 0.0
    gossip_p99: float = 0.0
    gossip_mean: float = 0.0
    consensus_p50: float = 0.0
    consensus_p95: float = 0.0
    consensus_p99: float = 0.0
    consensus_mean: float = 0.0
    checkpoint_phase_p50: float = 0.0
    checkpoint_phase_p95: float = 0.0
    checkpoint_phase_p99: float = 0.0
    checkpoint_phase_mean: float = 0.0

    @property
    def phase_stats(self) -> PhaseStats:
        """Convenience: PhaseStats view derived from samples."""
        return PhaseStats.from_samples(self.samples)

    @classmethod
    def from_samples(cls, samples: List[FinalitySample]) -> "FinalityStats":
        def _qs(latencies: List[float]) -> tuple[float, float, float, float]:
            if not latencies:
                return (0.0, 0.0, 0.0, 0.0)
            s = sorted(latencies)
            return (
                _quantile(s, 0.5),
                _quantile(s, 0.95),
                _quantile(s, 0.99),
                _mean(s),
            )

        ordered_vals = [s.ordered_latency for s in samples if s.ordered_latency is not None]
        decided_vals = [s.decided_latency for s in samples if s.decided_latency is not None]
        checkpoint_vals = [s.checkpoint_latency for s in samples if s.checkpoint_latency is not None]
        o_p50, o_p95, o_p99, o_mean = _qs(ordered_vals)  # type: ignore
        d_p50, d_p95, d_p99, d_mean = _qs(decided_vals)  # type: ignore
        c_p50, c_p95, c_p99, c_mean = _qs(checkpoint_vals)  # type: ignore

        # phase breakdown: gossip = ordered - submit (== ordered_latency)
        #                  consensus = decided - ordered
        #                  checkpoint_phase = checkpoint - decided
        gossip_vals = [s.gossip_phase for s in samples if s.gossip_phase is not None]
        consensus_vals = [s.consensus_phase for s in samples if s.consensus_phase is not None]
        checkpoint_phase_vals = [s.checkpoint_phase for s in samples if s.checkpoint_phase is not None]
        # fallback: if phase fields not populated (old samples), derive on the fly
        if not gossip_vals and ordered_vals:
            gossip_vals = ordered_vals
        if not consensus_vals:
            consensus_vals = [
                (s.decided_time - s.ordered_time)  # type: ignore
                for s in samples
                if s.decided_time is not None and s.ordered_time is not None
            ]
        if not checkpoint_phase_vals:
            checkpoint_phase_vals = [
                (s.checkpoint_time - s.decided_time)  # type: ignore
                for s in samples
                if s.checkpoint_time is not None and s.decided_time is not None
            ]

        g_p50, g_p95, g_p99, g_mean = _qs(gossip_vals)  # type: ignore
        cs_p50, cs_p95, cs_p99, cs_mean = _qs(consensus_vals)  # type: ignore
        ckp_p50, ckp_p95, ckp_p99, ckp_mean = _qs(checkpoint_phase_vals)  # type: ignore
        return cls(
            count=len(samples),
            ordered_p50=o_p50,
            ordered_p95=o_p95,
            ordered_p99=o_p99,
            ordered_mean=o_mean,
            decided_p50=d_p50,
            decided_p95=d_p95,
            decided_p99=d_p99,
            decided_mean=d_mean,
            checkpoint_p50=c_p50,
            checkpoint_p95=c_p95,
            checkpoint_p99=c_p99,
            checkpoint_mean=c_mean,
            samples=samples,
            gossip_p50=g_p50,
            gossip_p95=g_p95,
            gossip_p99=g_p99,
            gossip_mean=g_mean,
            consensus_p50=cs_p50,
            consensus_p95=cs_p95,
            consensus_p99=cs_p99,
            consensus_mean=cs_mean,
            checkpoint_phase_p50=ckp_p50,
            checkpoint_phase_p95=ckp_p95,
            checkpoint_phase_p99=ckp_p99,
            checkpoint_phase_mean=ckp_mean,
        )


# ---------------------------------------------------------------------------
# Phase breakdown helpers
# ---------------------------------------------------------------------------

def breakdown_stats(stats: FinalityStats) -> dict:
    """Return phase breakdown as a dict for programmatic consumption.

    Keys: gossip, consensus, checkpoint_phase, total.
    Each maps to dict with p50/p95/p99/mean and pct_of_total (for mean).
    """
    total_mean = stats.decided_mean if stats.decided_mean else 0.0
    # Avoid division by zero; percentages based on mean.
    def _pct(v: float) -> float:
        return (v / total_mean * 100.0) if total_mean > 0 else 0.0

    return {
        "gossip": {
            "p50": stats.gossip_p50,
            "p95": stats.gossip_p95,
            "p99": stats.gossip_p99,
            "mean": stats.gossip_mean,
            "pct_of_total_mean": _pct(stats.gossip_mean),
            "label": "submit->ordered",
        },
        "consensus": {
            "p50": stats.consensus_p50,
            "p95": stats.consensus_p95,
            "p99": stats.consensus_p99,
            "mean": stats.consensus_mean,
            "pct_of_total_mean": _pct(stats.consensus_mean),
            "label": "ordered->decided",
        },
        "checkpoint_phase": {
            "p50": stats.checkpoint_phase_p50,
            "p95": stats.checkpoint_phase_p95,
            "p99": stats.checkpoint_phase_p99,
            "mean": stats.checkpoint_phase_mean,
            "pct_of_total_mean": _pct(stats.checkpoint_phase_mean),
            "label": "decided->checkpoint",
        },
        "total": {
            "p50": stats.decided_p50,
            "p95": stats.decided_p95,
            "p99": stats.decided_p99,
            "mean": stats.decided_mean,
            "label": "submit->decided",
        },
        "checkpoint_total": {
            "p50": stats.checkpoint_p50,
            "p95": stats.checkpoint_p95,
            "p99": stats.checkpoint_p99,
            "mean": stats.checkpoint_mean,
            "label": "submit->checkpoint",
        },
    }


def print_phase_breakdown(stats: FinalityStats, tag: str = "") -> None:
    """Pretty-print phase breakdown with percentages of total decided latency.

    Output lines prefixed with ``[phase:tag]``:

    [phase:tag] gossip     (submit->ordered)      p50=... p95=... mean=... (xx.x% of total)
    [phase:tag] consensus  (ordered->decided)     p50=... ...
    [phase:tag] checkpoint (decided->checkpoint)  p50=... ...
    [phase:tag] total      (submit->decided)      p50=... ...
    """
    prefix = f"[phase:{tag}]" if tag else "[phase]"
    bd = breakdown_stats(stats)

    def _fmt(v: float) -> str:
        return f"{v:.3f}s"

    total_mean = bd["total"]["mean"]
    # For p50 percentages, also show share of decided p50 if available.
    total_p50 = bd["total"]["p50"] if bd["total"]["p50"] else 0.0

    def _pct_str(phase_mean: float, phase_p50: float) -> str:
        pct_mean = (phase_mean / total_mean * 100.0) if total_mean else 0.0
        pct_p50 = (phase_p50 / total_p50 * 100.0) if total_p50 else 0.0
        return f"{pct_mean:.1f}% mean, {pct_p50:.1f}% p50 of total"

    # gossip
    g = bd["gossip"]
    print(
        f"{prefix} gossip     (submit->ordered)      "
        f"p50={_fmt(g['p50'])} p95={_fmt(g['p95'])} p99={_fmt(g['p99'])} mean={_fmt(g['mean'])} "
        f"({ _pct_str(g['mean'], g['p50']) })"
    )
    # consensus
    cs = bd["consensus"]
    print(
        f"{prefix} consensus  (ordered->decided)     "
        f"p50={_fmt(cs['p50'])} p95={_fmt(cs['p95'])} p99={_fmt(cs['p99'])} mean={_fmt(cs['mean'])} "
        f"({ _pct_str(cs['mean'], cs['p50']) })"
    )
    # checkpoint phase
    ck = bd["checkpoint_phase"]
    print(
        f"{prefix} checkpoint (decided->checkpoint)  "
        f"p50={_fmt(ck['p50'])} p95={_fmt(ck['p95'])} p99={_fmt(ck['p99'])} mean={_fmt(ck['mean'])} "
        f"({ _pct_str(ck['mean'], ck['p50']) })"
    )
    # total
    t = bd["total"]
    print(
        f"{prefix} total      (submit->decided)      "
        f"p50={_fmt(t['p50'])} p95={_fmt(t['p95'])} p99={_fmt(t['p99'])} mean={_fmt(t['mean'])}"
    )
    # checkpoint total (submit->checkpoint) for completeness
    ct = bd["checkpoint_total"]
    if ct["mean"] > 0 or ct["p50"] > 0:
        print(
            f"{prefix} checkpoint_total (submit->checkpoint) "
            f"p50={_fmt(ct['p50'])} p95={_fmt(ct['p95'])} p99={_fmt(ct['p99'])} mean={_fmt(ct['mean'])}"
        )


async def wait_for_key_finalized(
    nodes: List[NodeHandle],
    key: bytes,  # noqa: ARG001 – kept for future state.get exposure
    timeout: float = 30.0,
    poll_interval: float = 0.05,
    require_all: bool = True,
) -> Dict[int, StatusReport]:
    """
    Wait until the given key is considered finalized.

    Currently approximated as waiting for decided_round to advance beyond
    the baseline observed at call time (control socket does not expose
    state.get). When state query becomes available this can be tightened
    to poll state.get for key visibility.
    """
    baseline = await collect_statuses(nodes)
    if baseline:
        base_decided = max(s.decided_round for s in baseline.values())
    else:
        base_decided = 0
    deadline = time.monotonic() + timeout
    last: Dict[int, StatusReport] = baseline
    while time.monotonic() < deadline:
        last = await collect_statuses(nodes)
        if require_all:
            if last and len(last) == len(nodes) and all(s.decided_round > base_decided for s in last.values()):
                return last
        else:
            if any(s.decided_round > base_decided for s in last.values()):
                return last
        await asyncio.sleep(poll_interval)
    raise TimeoutError(f"wait_for_key_finalized key={key!r} not finalized within {timeout}s; last decided: { {nid: s.decided_round for nid, s in last.items()} }")


async def measure_single_finality(
    nodes: List[NodeHandle],
    key: bytes,
    value: bytes,
    submit_node_id: Optional[int] = None,
    mgr: Optional[object] = None,
    timeout: float = 30.0,
    poll_interval: float = 0.05,
    **kwargs,
) -> FinalitySample:
    """
    Submit a single put via ControlClient/mgr.submit_put, record monotonic
    submit time, then poll collect_statuses until ordered/decided/checkpoint
    rounds advance beyond baseline on all nodes.

    Finality is approximated by round advancement because control socket does
    not expose per-key state.get. Baseline is captured before submit; each
    finality timestamp is the first poll time where all nodes satisfy
    round > baseline.

    Phase breakdown:
      gossip    = ordered_time - submit_time   (submit -> ordered, dissemination)
      consensus = decided_time - ordered_time  (ordered -> decided)
      checkpoint= checkpoint_time - decided_time (decided -> checkpoint)
    If checkpoint not reached within timeout, its fields remain None.

    Returns FinalitySample with both absolute latencies and phase fields
    (gossip_phase, consensus_phase, checkpoint_phase) populated.
    """
    # Compat: allow caller to pass node_handles as kwarg
    if "node_handles" in kwargs and kwargs["node_handles"] is not None:
        nodes = kwargs["node_handles"]  # type: ignore
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes")

    tx_id = _uuid.uuid4().hex[:8]

    # Baseline before submit
    try:
        baseline = await collect_statuses(nodes, timeout=2.0)
    except Exception:
        baseline = {}
    if baseline:
        base_ordered = max(s.ordered_round for s in baseline.values())
        base_decided = max(s.decided_round for s in baseline.values())
        # checkpoint may be None
        ck_vals = [s.latest_checkpoint_round for s in baseline.values() if s.latest_checkpoint_round is not None]
        base_checkpoint = max(ck_vals) if ck_vals else -1
    else:
        base_ordered = 0
        base_decided = 0
        base_checkpoint = -1

    submit_time = time.monotonic()

    # Submit
    if mgr is not None and hasattr(mgr, "submit_put"):
        # ClusterManager.submit_put
        try:
            await mgr.submit_put(key, value, node_id=submit_node_id)  # type: ignore[attr-defined]
        except TypeError:
            # fallback without node_id
            await mgr.submit_put(key, value)  # type: ignore[attr-defined]
    else:
        # Direct ControlClient submission
        if submit_node_id is not None:
            handle = next((h for h in nodes if h.node_id == submit_node_id), None)
            if handle is None:
                raise KeyError(f"submit_node_id {submit_node_id} not in nodes")
        else:
            handle = nodes[0] if nodes else None
            if handle is None:
                raise RuntimeError("no nodes provided for submission")
        client = ControlClient(handle.control_socket, timeout=5.0)
        await client.submit_put(key, value)

    ordered_time: Optional[float] = None
    decided_time: Optional[float] = None
    checkpoint_time: Optional[float] = None

    deadline = submit_time + timeout
    # grace for checkpoint after decided: don't block 30s if ck stalls (2s max after decided)
    decided_grace_deadline: float | None = None
    # Poll loop
    while time.monotonic() < deadline:
        # Early exit if ordered+decided captured (checkpoint is best-effort, 2s grace after decided)
        if ordered_time is not None and decided_time is not None:
            if checkpoint_time is not None:
                break
            # if we have decided, start grace for checkpoint
            if decided_grace_deadline is None:
                decided_grace_deadline = time.monotonic() + 2.0
            if time.monotonic() >= decided_grace_deadline:
                break
            # still allow checkpoint to arrive within grace, but don't wait full timeout
        statuses = await collect_statuses(nodes, timeout=2.0)
        now = time.monotonic()
        if statuses and len(statuses) == len(nodes):
            if ordered_time is None and all(s.ordered_round > base_ordered for s in statuses.values()):
                ordered_time = now
            if decided_time is None and all(s.decided_round > base_decided for s in statuses.values()):
                decided_time = now
                # start checkpoint grace now
                if decided_grace_deadline is None:
                    decided_grace_deadline = now + 2.0
            if checkpoint_time is None:
                # All nodes must have checkpoint > base_checkpoint
                if all(
                    s.latest_checkpoint_round is not None and s.latest_checkpoint_round > base_checkpoint
                    for s in statuses.values()
                ):
                    checkpoint_time = now
        # If still pending ordered/decided, sleep
        if ordered_time is None or decided_time is None:
            # Sleep but not past deadline
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(poll_interval, remaining))
        elif checkpoint_time is None and decided_grace_deadline is not None and time.monotonic() < decided_grace_deadline:
            # decided captured, waiting brief grace for checkpoint
            remaining = min(deadline, decided_grace_deadline) - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(poll_interval, remaining))
        elif checkpoint_time is None:
            # grace expired, return with ck=None (don't wait full timeout)
            break
        else:
            break

    def _lat(t: Optional[float]) -> Optional[float]:
        return (t - submit_time) if t is not None else None

    ordered_latency = _lat(ordered_time)
    decided_latency = _lat(decided_time)
    checkpoint_latency = _lat(checkpoint_time)

    # Phase breakdown
    gossip_phase = ordered_latency  # submit -> ordered
    consensus_phase: Optional[float] = None
    if ordered_time is not None and decided_time is not None:
        consensus_phase = decided_time - ordered_time
    checkpoint_phase: Optional[float] = None
    if decided_time is not None and checkpoint_time is not None:
        checkpoint_phase = checkpoint_time - decided_time

    return FinalitySample(
        tx_id=tx_id,
        key=bytes(key),
        submit_time=submit_time,
        ordered_time=ordered_time,
        decided_time=decided_time,
        checkpoint_time=checkpoint_time,
        ordered_latency=ordered_latency,
        decided_latency=decided_latency,
        checkpoint_latency=checkpoint_latency,
        gossip_phase=gossip_phase,
        consensus_phase=consensus_phase,
        checkpoint_phase=checkpoint_phase,
    )


async def measure_phased_finality(
    nodes: List[NodeHandle],
    key: bytes,
    value: bytes,
    submit_node_id: Optional[int] = None,
    mgr: Optional[object] = None,
    timeout: float = 30.0,
    poll_interval: float = 0.05,
    **kwargs,
) -> FinalitySample:
    """Alias for measure_single_finality with explicit phase documentation.

    Measures submit -> ordered (gossip), ordered -> decided (consensus),
    and decided -> checkpoint latencies separately. See measure_single_finality
    for full semantics.

    This helper exists to make the gossip vs consensus split explicit at the
    call site; it delegates directly to measure_single_finality.
    """
    return await measure_single_finality(
        nodes,
        key,
        value,
        submit_node_id=submit_node_id,
        mgr=mgr,
        timeout=timeout,
        poll_interval=poll_interval,
        **kwargs,
    )


async def measure_finality_batch(
    nodes: List[NodeHandle],
    mgr,
    count: int = 20,
    concurrency: int = 1,
    interval_ms: int = 0,
    key_prefix: str = "bench-",
    timeout: float = 30.0,
) -> FinalityStats:
    """
    Submit `count` puts with unique keys `f"{prefix}{i}-{uuid hex short}"`
    and measure each via measure_single_finality.

    concurrency==1 (default): sequential submit-one + wait for finality before
    next – gives isolated latency.

    concurrency>1: submit in parallel batches of size `concurrency` using
    asyncio.gather of measure_single_finality tasks. This overlaps execution
    but still yields per-tx latency. Tail latency is naturally captured by
    the slowest sample.

    interval_ms: optional sleep between sequential submissions.
    """
    samples: List[FinalitySample] = []

    if concurrency is not None and concurrency > 1:
        # Parallel batched measurement
        # Chunk into batches of `concurrency` to bound parallelism
        for batch_start in range(0, count, concurrency):
            batch_end = min(batch_start + concurrency, count)
            tasks: List[asyncio.Task] = []
            for i in range(batch_start, batch_end):
                k = f"{key_prefix}{i}-{_uuid.uuid4().hex[:6]}".encode()
                v = f"v-{i}-{_uuid.uuid4().hex[:4]}".encode()
                tasks.append(asyncio.create_task(measure_single_finality(nodes, k, v, mgr=mgr, timeout=timeout)))
            if tasks:
                results = await asyncio.gather(*tasks)
                samples.extend(results)  # type: ignore[arg-type]
            if interval_ms and batch_end < count:
                await asyncio.sleep(interval_ms / 1000.0)
    else:
        for i in range(count):
            k = f"{key_prefix}{i}-{_uuid.uuid4().hex[:6]}".encode()
            v = f"v-{i}-{_uuid.uuid4().hex[:4]}".encode()
            s = await measure_single_finality(nodes, k, v, mgr=mgr, timeout=timeout)
            samples.append(s)
            if interval_ms:
                await asyncio.sleep(interval_ms / 1000.0)

    return FinalityStats.from_samples(samples)


@dataclass
class TpsResult:
    """High-throughput benchmark result."""

    sent: int
    duration_sec: float
    tps_submit: float
    tps_finalized_decided: float
    tps_finalized_checkpoint: float
    avg_decided_latency: float
    # Extended details
    submit_duration_sec: float = 0.0
    decided_duration_sec: float = 0.0
    checkpoint_duration_sec: Optional[float] = None
    decided_round_advance: Optional[int] = None
    checkpoint_round_advance: Optional[int] = None
    baseline_decided: Optional[int] = None
    baseline_checkpoint: Optional[int] = None
    final_decided: Optional[int] = None
    final_checkpoint: Optional[int] = None
    # Phase breakdown averages (if available from per-tx samples; else None)
    avg_gossip_phase: Optional[float] = None
    avg_consensus_phase: Optional[float] = None
    avg_checkpoint_phase: Optional[float] = None

    @property
    def phase_avgs(self) -> dict:
        """Return available phase averages as dict."""
        return {
            "gossip": self.avg_gossip_phase,
            "consensus": self.avg_consensus_phase,
            "checkpoint": self.avg_checkpoint_phase,
        }


async def benchmark_tps(
    nodes: List[NodeHandle],
    mgr,
    total_txs: int = 500,
    batch_size: int = 64,
    target_duration_sec: Optional[float] = None,
    concurrency: int = 10,
    timeout: float = 60.0,
) -> TpsResult:
    """
    Saturate the cluster with total_txs puts as fast as possible (or paced
    over target_duration_sec if given). Uses asyncio.gather per batch with
    concurrency limiting. Records submit TPS, then waits for decided/checkpoint
    rounds to advance beyond baseline (with timeout) and reports finalized TPS.

    decided TPS = total_txs / (decided_time - submit_start)
    checkpoint TPS similarly if checkpoint advances; otherwise 0.
    avg_decided_latency approximated as decided_duration / 2 when no per-tx
    sample available (or 0 if not finalized).
    """
    if total_txs <= 0:
        raise ValueError("total_txs must be >0")
    if batch_size <= 0:
        raise ValueError("batch_size must be >0")
    if concurrency <= 0:
        concurrency = 1

    # Baseline rounds
    try:
        baseline = await collect_statuses(nodes, timeout=5.0)
    except Exception:
        baseline = {}
    if baseline:
        baseline_decided = max(s.decided_round for s in baseline.values())
        ck_vals = [s.latest_checkpoint_round for s in baseline.values() if s.latest_checkpoint_round is not None]
        baseline_checkpoint: Optional[int] = max(ck_vals) if ck_vals else None
        baseline_checkpoint_cmp = baseline_checkpoint if baseline_checkpoint is not None else -1
    else:
        baseline_decided = 0
        baseline_checkpoint = None
        baseline_checkpoint_cmp = -1

    submit_start = time.monotonic()

    # Pace control
    pace_interval: Optional[float] = None
    if target_duration_sec is not None and target_duration_sec > 0:
        pace_interval = target_duration_sec / max(total_txs, 1)

    sent = 0
    # Batch submission
    for offset in range(0, total_txs, batch_size):
        cur = min(batch_size, total_txs - offset)
        # Build keys/values for this batch
        kvs: List[tuple[bytes, bytes]] = []
        for i in range(cur):
            idx = offset + i
            k = f"tps-{idx}-{_uuid.uuid4().hex[:6]}".encode()
            v = b"x" * 32  # fixed size payload keeps throughput comparable
            kvs.append((k, v))

        # Submit batch with concurrency limiting via chunking
        for chunk_start in range(0, len(kvs), concurrency):
            chunk = kvs[chunk_start : chunk_start + concurrency]

            async def _submit_one(kv: tuple[bytes, bytes]) -> None:
                k, v = kv
                if mgr is not None and hasattr(mgr, "submit_put"):
                    try:
                        await mgr.submit_put(k, v)  # type: ignore[attr-defined]
                    except TypeError:
                        await mgr.submit_put(k, v)  # type: ignore[attr-defined]
                else:
                    h = nodes[0]
                    c = ControlClient(h.control_socket, timeout=5.0)
                    await c.submit_put(k, v)

            await asyncio.gather(*[_submit_one(kv) for kv in chunk])
            sent += len(chunk)

            if pace_interval is not None and pace_interval > 0:
                # Sleep proportional to chunk size
                await asyncio.sleep(pace_interval * len(chunk))

    submit_end = time.monotonic()
    submit_duration = submit_end - submit_start
    tps_submit = (sent / submit_duration) if submit_duration > 0 else 0.0

    # Wait for finalization
    decided_time: Optional[float] = None
    checkpoint_time: Optional[float] = None
    final_decided: Optional[int] = None
    final_checkpoint: Optional[int] = None
    decided_round_advance: Optional[int] = None
    checkpoint_round_advance: Optional[int] = None

    deadline = submit_start + timeout
    # Require at least 1 round advance for decided (ideally 2 to ensure tx included,
    # but 1 is sufficient for progress detection under variable tx-per-round).
    while time.monotonic() < deadline:
        statuses = await collect_statuses(nodes, timeout=2.0)
        now = time.monotonic()
        if statuses and len(statuses) == len(nodes):
            max_decided = max(s.decided_round for s in statuses.values())
            if decided_time is None and max_decided > baseline_decided:
                # Ensure all nodes advanced, not just max
                if all(s.decided_round > baseline_decided for s in statuses.values()):
                    decided_time = now
                    final_decided = max_decided
                    decided_round_advance = max_decided - baseline_decided
            # Checkpoint: all nodes have checkpoint > baseline
            ck_vals2 = [s.latest_checkpoint_round for s in statuses.values() if s.latest_checkpoint_round is not None]
            if checkpoint_time is None and ck_vals2 and len(ck_vals2) == len(nodes):
                max_ck = max(ck_vals2)  # type: ignore[arg-type]
                if max_ck > baseline_checkpoint_cmp and all(
                    s.latest_checkpoint_round is not None and s.latest_checkpoint_round > baseline_checkpoint_cmp
                    for s in statuses.values()
                ):
                    checkpoint_time = now
                    final_checkpoint = max_ck
                    checkpoint_round_advance = max_ck - baseline_checkpoint_cmp if baseline_checkpoint_cmp != -1 else max_ck
        if decided_time is not None and checkpoint_time is not None:
            break
        # If both not yet, continue polling, but if decided done and checkpoint
        # not advancing we may exit early after timeout anyway.
        # Short sleep to avoid busy loop; don't sleep past deadline.
        if decided_time is not None and checkpoint_time is None:
            # still wait for checkpoint but with same deadline
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(0.5, remaining))

    if decided_time is not None:
        decided_duration = decided_time - submit_start
    else:
        decided_duration = deadline - submit_start
        # No decided progress
        decided_time = None

    if checkpoint_time is not None:
        checkpoint_duration: Optional[float] = checkpoint_time - submit_start
    else:
        checkpoint_duration = None

    # Finalized TPS
    if decided_time is not None and decided_duration > 0:
        tps_decided = sent / decided_duration
    else:
        tps_decided = 0.0

    if checkpoint_time is not None and checkpoint_duration is not None and checkpoint_duration > 0:
        tps_checkpoint = sent / checkpoint_duration
    else:
        tps_checkpoint = 0.0

    # Avg latency heuristic: decided_duration / 2 if finalized else 0
    avg_lat = (decided_duration / 2.0) if decided_time is not None else 0.0
    # Use total finalized duration as `duration_sec` for backward compat with spec
    total_duration = decided_duration if decided_time is not None else submit_duration

    # Phase avg heuristic for TpsResult: without per-tx samples we cannot split
    # decided_duration into gossip vs consensus. Leave as None; caller can populate
    # by combining with FinalityStats if available. Provide estimated split based
    # on typical gossip fraction if desired – currently left None to avoid guessing.
    return TpsResult(
        sent=sent,
        duration_sec=total_duration,
        tps_submit=tps_submit,
        tps_finalized_decided=tps_decided,
        tps_finalized_checkpoint=tps_checkpoint,
        avg_decided_latency=avg_lat,
        submit_duration_sec=submit_duration,
        decided_duration_sec=decided_duration,
        checkpoint_duration_sec=checkpoint_duration,
        decided_round_advance=decided_round_advance,
        checkpoint_round_advance=checkpoint_round_advance,
        baseline_decided=baseline_decided,
        baseline_checkpoint=baseline_checkpoint,
        final_decided=final_decided,
        final_checkpoint=final_checkpoint,
        avg_gossip_phase=None,
        avg_consensus_phase=None,
        avg_checkpoint_phase=None,
    )
