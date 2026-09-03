"""
cluster.py – ClusterManager for hard-testing JKaIN consensus nodes.

Spawns N jkaind processes via `jkaind init` + `jkaind run`, optionally
fronted by LatencyMesh proxies.

Typed dataclasses: NodeHandle, ClusterInfo, ClusterConfig
"""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import math
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .control import ControlClient
from .proxy import LatencyMesh

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers: port allocation, binary discovery
# ---------------------------------------------------------------------------


def _is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _allocate_port(preferred: Optional[int] = None, host: str = "127.0.0.1") -> int:
    """Try preferred port; fall back to ephemeral (bind 0)."""
    if preferred is not None and _is_port_free(host, preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def find_jkaind_binary(
    extra_search: Optional[List[Path]] = None,
) -> Path:
    """
    Locate jkaind binary. Search order:
      1. $JKAIND_BIN env
      2. extra_search
      3. consensus-node/target/debug/jkaind
      4. consensus-node/target/release/jkaind
      5. target/debug/jkaind
      6. target/release/jkaind
      7. which jkaind
    If not found, attempts `cargo build --workspace` inside consensus-node.
    """
    candidates: List[Path] = []

    env_bin = os.environ.get("JKAIND_BIN")
    if env_bin:
        candidates.append(Path(env_bin))

    if extra_search:
        candidates.extend(extra_search)

    # Resolve repo root relative to this file: tests/harness -> tests -> repo root
    this = Path(__file__).resolve()
    repo_root = this.parents[2]  # harness -> tests -> JKaIN
    consensus_dir = repo_root / "consensus-node"

    candidates.extend([
        consensus_dir / "target" / "debug" / "jkaind",
        consensus_dir / "target" / "release" / "jkaind",
        repo_root / "target" / "debug" / "jkaind",
        repo_root / "target" / "release" / "jkaind",
        Path("/usr/local/bin/jkaind"),
    ])

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c

    which = shutil.which("jkaind")
    if which:
        return Path(which)

    # Try building
    logger.warning("jkaind binary not found, attempting cargo build --workspace in %s", consensus_dir)
    if consensus_dir.is_dir():
        try:
            subprocess.run(
                ["cargo", "build", "--workspace"],
                cwd=str(consensus_dir),
                check=True,
                timeout=300,
            )
            for c in candidates:
                if c.is_file():
                    return c
        except Exception as e:
            logger.error("cargo build failed: %s", e)

    raise FileNotFoundError(
        "jkaind binary not found. Searched: " + ", ".join(str(c) for c in candidates)
        + ". Set $JKAIND_BIN or run `cargo build --workspace` inside consensus-node/."
    )


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class NodeHandle:
    node_id: int
    gossip_addr: str  # "127.0.0.1:7000" advertised (proxy if mesh, real if direct)
    reconnect_addr: Optional[str]
    real_gossip_port: int
    real_reconnect_port: Optional[int]
    proxy_gossip_port: Optional[int] = None
    proxy_reconnect_port: Optional[int] = None
    data_dir: Path = field(default_factory=Path)
    control_socket: Path = field(default_factory=Path)
    process: Optional[subprocess.Popen] = None  # type: ignore
    pid: Optional[int] = None
    log_file: Optional[Path] = None

    @property
    def gossip_port(self) -> int:
        # advertised port (proxy if present)
        if self.proxy_gossip_port is not None:
            return self.proxy_gossip_port
        return self.real_gossip_port

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def control_client(self, timeout: float = 5.0) -> ControlClient:
        return ControlClient(self.control_socket, timeout=timeout)


@dataclass
class ClusterInfo:
    cluster_dir: Path
    cluster_toml: Path
    nodes: List[NodeHandle]
    mesh: Optional[LatencyMesh] = None


@dataclass
class ClusterConfig:
    num_nodes: int = 6
    base_dir: Optional[Path] = None  # temp dir parent; None -> mkdtemp
    jkaind_bin: Optional[Path] = None
    host: str = "127.0.0.1"
    # T10 (PLAN-2.4 Wave 6 / D1): 25ms until W1-W3 green + G6 bench pass.
    # 5ms only via ClusterConfig(num_nodes=6, sync_interval_ms=5, fanout=4)
    # after hot-peer QUIC proven, expect p50 ~0.12s if thermal allows.
    # Abort 5ms runs if k10temp > 85°C. Validated in jkaind run: 5..5000ms.
    sync_interval_ms: int = 25
    sync_timeout_ms: int = 500
    log_level: str = "info"
    log_file_mode: str = "file"  # "file" -> data/logs/jkaind.log, "-" -> stderr
    use_proxy: bool = False
    proxy_latency_ms: float = 0.0
    proxy_jitter_ms: float = 0.0
    proxy_drop_prob: float = 0.0
    # T11 gap vs fanout sweep (PLAN-2.4): gap 25/80, k 1/2/4, dedup on/off, QUIC on/off.
    # Latency≈k*gap*logN fit: 80ms k=4 should match 25ms k=1 at ~0.6s @70°C.
    # Fanout maps to --fanout (auto|1|2|4); dedup/quic map to --dedup/--quic
    # native flags on jkaind (verified via --help).
    fanout: str | int = "auto"
    dedup_enabled: bool = True
    quic_enabled: bool = False


def _fanout_k(fanout: str | int, n_peers: int = 5) -> int:
    if isinstance(fanout, int):
        return max(1, min(fanout, max(1, n_peers)))
    if isinstance(fanout, str) and fanout.isdigit():
        return max(1, min(int(fanout), max(1, n_peers)))
    if n_peers <= 1:
        return 1
    n = n_peers + 1
    if n <= 6:
        return 4 if n_peers >= 4 else n_peers
    if n >= 30:
        return 9
    return max(2, min(4, n_peers))


def predicted_p50_seconds(gap_ms: int, fanout: str | int, n_nodes: int = 6) -> float:
    k = _fanout_k(fanout, n_nodes - 1)
    log_n = math.log2(max(2, n_nodes))
    return (gap_ms / 1000.0) * log_n * 9.3 / max(1, k)


def predicted_p50_gap_k(gap_ms: int, fanout: str | int, n_nodes: int = 6) -> float:
    k = _fanout_k(fanout, n_nodes - 1)
    log_n = math.log2(max(2, n_nodes))
    base = 0.6 / (25 * log_n)
    return gap_ms * log_n * base / max(1, k) if k > 1 else gap_ms * log_n * base


def parse_diagnosis_log(path: Path) -> dict:
    if not path.is_file():
        return {}
    last: dict = {}
    hit_rates: list[float] = []
    p95s: list[float] = []
    try:
        for line in path.read_text(errors="replace").splitlines()[-200:]:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if "cache_hit_rate" in obj:
                hit_rates.append(float(obj.get("cache_hit_rate") or 0))
            if "p95_rtt_ms" in obj:
                p95s.append(float(obj.get("p95_rtt_ms") or 0))
            if "p50_rtt_ms" in obj:
                last = obj
        if hit_rates:
            last["hit_rate_avg"] = sum(hit_rates) / len(hit_rates)
            last["hit_rate_last"] = hit_rates[-1]
        if p95s:
            last["p95_rtt_avg"] = sum(p95s) / len(p95s)
            last["p95_rtt_last"] = p95s[-1]
    except Exception:
        pass
    return last


# ---------------------------------------------------------------------------
# ClusterManager
# ---------------------------------------------------------------------------


class ClusterManager:
    """
    Manages a 6-node (or N-node) jkaind cluster for tests.

    Lifecycle:
        mgr = ClusterManager(ClusterConfig(num_nodes=6, use_proxy=False))
        await mgr.start()          # init + spawn + wait health
        await mgr.submit_tx(b"hello")
        await mgr.wait_for_health(timeout=30)
        mgr.stop_node(6)
        await mgr.restart_node(6)
        await mgr.stop_all()
        mgr.cleanup()
    Can also be used as async context manager.
    """

    def __init__(self, config: Optional[ClusterConfig] = None, **kwargs) -> None:
        if config is None:
            config = ClusterConfig(**kwargs)
        else:
            # allow overriding via kwargs
            for k, v in kwargs.items():
                setattr(config, k, v)
        self.config = config
        self._tmp_dir: Optional[Path] = None
        self._owns_tmp: bool = False
        self.cluster_info: Optional[ClusterInfo] = None
        self._nodes: Dict[int, NodeHandle] = {}
        self._mesh: Optional[LatencyMesh] = None
        self._started: bool = False
        # register atexit cleanup
        atexit.register(self._atexit_cleanup)

    # -- binary ------------------------------------------------------------

    @property
    def jkaind_bin(self) -> Path:
        if self.config.jkaind_bin:
            return self.config.jkaind_bin
        return find_jkaind_binary()

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> ClusterInfo:
        """Generate cluster config, start mesh (if enabled), spawn nodes, wait for health."""
        if self._started:
            raise RuntimeError("ClusterManager already started")

        bin_path = self.jkaind_bin
        logger.info("Using jkaind binary: %s", bin_path)

        # create temp directory
        if self.config.base_dir is not None:
            base = Path(self.config.base_dir)
            base.mkdir(parents=True, exist_ok=True)
            self._tmp_dir = Path(tempfile.mkdtemp(dir=str(base), prefix="jkain-harness-"))
        else:
            self._tmp_dir = Path(tempfile.mkdtemp(prefix="jkain-harness-"))
        self._owns_tmp = True
        logger.info("Cluster temp dir: %s", self._tmp_dir)

        cluster_out = self._tmp_dir / "cluster"
        cluster_out.mkdir(parents=True, exist_ok=True)

        # allocate real ports
        host = self.config.host
        real_ports: Dict[int, Tuple[int, Optional[int]]] = {}
        # Try preferred 7000+ offsets
        for node_id in range(1, self.config.num_nodes + 1):
            gossip_pref = 7000 + (node_id - 1) * 2
            reconnect_pref = gossip_pref + 1
            gossip_real = _allocate_port(gossip_pref, host)
            # ensure reconnect distinct
            # if gossip_real == gossip_pref, try reconnect_pref, else ephemeral
            if gossip_real == gossip_pref:
                reconnect_real = _allocate_port(reconnect_pref, host)
                # if collision (gossip took reconnect pref due to race), reallocate
                if reconnect_real == gossip_real:
                    reconnect_real = _free_port(host)
            else:
                reconnect_real = _free_port(host)
                # ensure no collision across nodes
                while any(rp == gossip_real or (rp2 is not None and rp2 == gossip_real)
                          for rp, rp2 in real_ports.values()):
                    gossip_real = _free_port(host)
            real_ports[node_id] = (gossip_real, reconnect_real)
            logger.debug("Node %d real ports: gossip %d reconnect %d", node_id, gossip_real, reconnect_real)

        # allocate proxy mesh if needed
        proxy_ports: Optional[Dict[int, Tuple[int, Optional[int]]]] = None
        if self.config.use_proxy:
            self._mesh = LatencyMesh(host=host)
            await self._mesh.allocate(
                real_ports,
                mean_latency_ms=self.config.proxy_latency_ms,
                jitter_ms=self.config.proxy_jitter_ms,
                drop_prob=self.config.proxy_drop_prob,
            )
            # build advertised addrs from mesh proxies
            proxy_ports = {}
            for nid in real_ports:
                g_host, g_port = self._mesh.proxy_gossip_addr(nid)
                r_addr = self._mesh.proxy_reconnect_addr(nid)
                r_port = r_addr[1] if r_addr else None
                proxy_ports[nid] = (g_port, r_port)
            await self._mesh.start()
            logger.info("LatencyMesh started with %d entries", len(self._mesh.entries))

        # build jkaind init args
        init_args = [str(bin_path), "init"]
        for node_id in range(1, self.config.num_nodes + 1):
            real_gossip, real_reconnect = real_ports[node_id]
            if proxy_ports is not None:
                adv_gossip, adv_reconnect = proxy_ports[node_id]
            else:
                adv_gossip, adv_reconnect = real_gossip, real_reconnect
            gossip_addr = f"{host}:{adv_gossip}"
            reconnect_addr = f"{host}:{adv_reconnect}" if adv_reconnect else None
            if reconnect_addr:
                member = f"{node_id}:{gossip_addr}:{reconnect_addr}"
            else:
                member = f"{node_id}:{gossip_addr}"
            init_args.extend(["--member", member])
        init_args.extend(["--out", str(cluster_out)])

        logger.info("Running jkaind init: %s", " ".join(init_args))
        result = subprocess.run(init_args, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"jkaind init failed: {result.stderr}\n{result.stdout}")

        cluster_toml = cluster_out / "cluster.toml"
        if not cluster_toml.is_file():
            raise RuntimeError(f"cluster.toml not created at {cluster_toml}")

        # spawn nodes
        for node_id in range(1, self.config.num_nodes + 1):
            real_gossip, real_reconnect = real_ports[node_id]
            if proxy_ports is not None:
                adv_gossip, _ = proxy_ports[node_id]
                gossip_addr_str = f"{host}:{adv_gossip}"
                adv_reconnect_port = proxy_ports[node_id][1]
                reconnect_addr_str = f"{host}:{adv_reconnect_port}" if adv_reconnect_port else None
            else:
                gossip_addr_str = f"{host}:{real_gossip}"
                reconnect_addr_str = f"{host}:{real_reconnect}" if real_reconnect else None

            data_dir = self._tmp_dir / f"data-{node_id}"
            data_dir.mkdir(parents=True, exist_ok=True)
            # logs subdir handled by jkaind run
            control_socket = data_dir / "jkaind.sock"
            secret_path = cluster_out / f"secret-{node_id}.bin"
            # bls secret is co-located, jkaind run will find it via bls_path_for

            if not secret_path.is_file():
                raise FileNotFoundError(f"missing secret for node {node_id}: {secret_path}")

            # build run args
            run_args = [
                str(bin_path), "run",
                "--cluster", str(cluster_toml),
                "--node-id", str(node_id),
                "--secret", str(secret_path),
                "--data", str(data_dir),
                "--gossip-port", str(real_gossip),
                "--control-socket", str(control_socket),
                "--sync-interval", str(self.config.sync_interval_ms),
                "--sync-timeout", str(self.config.sync_timeout_ms),
                "--log-level", self.config.log_level,
            ]
            if str(self.config.fanout) != "auto":
                run_args.extend(["--fanout", str(self.config.fanout)])
            run_args.extend(["--dedup", str(self.config.dedup_enabled).lower()])
            run_args.extend(["--quic", str(self.config.quic_enabled).lower()])
            if real_reconnect is not None:
                run_args.extend(["--reconnect-port", str(real_reconnect)])
            if self.config.log_file_mode == "-":
                run_args.extend(["--log-file", "-"])
            else:
                log_path = data_dir / "logs" / "jkaind.log"
                run_args.extend(["--log-file", str(log_path)])

            # ensure log dir exists
            (data_dir / "logs").mkdir(parents=True, exist_ok=True)
            log_file_path = data_dir / "logs" / "jkaind.log" if self.config.log_file_mode != "-" else None

            logger.info("Spawning node %d: %s", node_id, " ".join(run_args))

            diag_log = open(data_dir / "logs" / "diagnosis.log", "wb")  # noqa: SIM115

            proc = subprocess.Popen(
                run_args,
                stdout=diag_log,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )

            handle = NodeHandle(
                node_id=node_id,
                gossip_addr=gossip_addr_str,
                reconnect_addr=reconnect_addr_str,
                real_gossip_port=real_gossip,
                real_reconnect_port=real_reconnect,
                proxy_gossip_port=proxy_ports[node_id][0] if proxy_ports else None,
                proxy_reconnect_port=proxy_ports[node_id][1] if proxy_ports and proxy_ports[node_id][1] else None,
                data_dir=data_dir,
                control_socket=control_socket,
                process=proc,
                pid=proc.pid,
                log_file=log_file_path,
            )
            self._nodes[node_id] = handle
            # keep diag handle to close later – attach to process via extra attr
            # store file handle on NodeHandle._diag_file for cleanup
            setattr(handle, "_diag_file", diag_log)  # type: ignore

        self.cluster_info = ClusterInfo(
            cluster_dir=cluster_out,
            cluster_toml=cluster_toml,
            nodes=list(self._nodes.values()),
            mesh=self._mesh,
        )
        self._started = True

        # wait for health
        await self.wait_for_health(timeout=30.0)

        return self.cluster_info

    async def wait_for_health(self, timeout: float = 30.0, interval: float = 0.5) -> None:
        """Poll each node's status socket until all respond or timeout."""
        deadline = time.monotonic() + timeout
        not_ready: List[int] = list(self._nodes.keys())
        last_err: Optional[str] = None
        while time.monotonic() < deadline:
            # check processes still alive
            for nid, h in list(self._nodes.items()):
                if h.process and h.process.poll() is not None:
                    raise RuntimeError(f"node {nid} exited early with code {h.process.returncode}. Logs: {self.collect_logs(nid)}")

            # probe each not-ready node's control socket
            still: List[int] = []
            for nid in not_ready:
                h = self._nodes[nid]
                if not h.control_socket.exists():
                    still.append(nid)
                    continue
                try:
                    client = ControlClient(h.control_socket, timeout=2.0, retries=1)
                    await client.status()
                    logger.debug("Node %d healthy", nid)
                except Exception as e:
                    last_err = str(e)
                    still.append(nid)
            if not still:
                logger.info("All %d nodes healthy", len(self._nodes))
                return
            not_ready = still
            await asyncio.sleep(interval)

        raise TimeoutError(f"wait_for_health timed out after {timeout}s; not ready: {not_ready}; last err: {last_err}")

    # -- tx submission -----------------------------------------------------

    async def submit_tx(self, payload: bytes, node_id: Optional[int] = None) -> Dict:
        """Submit transaction payload to a specific node or round-robin."""
        if not self._nodes:
            raise RuntimeError("cluster not started")
        if node_id is None:
            # pick first healthy node
            node_id = next(iter(self._nodes))
        handle = self._nodes.get(node_id)
        if handle is None:
            raise KeyError(f"unknown node_id {node_id}")
        client = ControlClient(handle.control_socket, timeout=5.0)
        return await client.submit_tx(payload)

    async def submit_put(self, key: bytes, value: bytes, node_id: Optional[int] = None) -> Dict:
        """Encode and submit a Put operation."""
        if not self._nodes:
            raise RuntimeError("cluster not started")
        if node_id is None:
            node_id = next(iter(self._nodes))
        handle = self._nodes[node_id]
        client = ControlClient(handle.control_socket, timeout=5.0)
        return await client.submit_put(key, value)

    # -- node lifecycle ----------------------------------------------------

    def stop_node(self, node_id: int, sig: int = signal.SIGTERM, timeout: float = 5.0) -> None:
        """Gracefully stop a node (SIGTERM)."""
        handle = self._nodes.get(node_id)
        if handle is None:
            raise KeyError(f"unknown node {node_id}")
        proc = handle.process
        if proc is None or proc.poll() is not None:
            logger.warning("stop_node %d: already stopped", node_id)
            return
        logger.info("Stopping node %d (pid %d)", node_id, proc.pid)
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), sig)
            else:
                proc.terminate()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Node %d did not exit in %ds, killing", node_id, timeout)
            self.kill_node(node_id)

    def kill_node(self, node_id: int) -> None:
        """Force-kill a node (SIGKILL)."""
        handle = self._nodes.get(node_id)
        if handle is None:
            raise KeyError(f"unknown node {node_id}")
        proc = handle.process
        if proc is None or proc.poll() is not None:
            return
        logger.info("Killing node %d (pid %d)", node_id, proc.pid)
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    async def restart_node(self, node_id: int, timeout: float = 10.0) -> NodeHandle:
        """
        Restart a previously stopped node with same ports and data dir.
        Retains data dir (restart recovery via checkpoint/log replay).
        """
        old = self._nodes.get(node_id)
        if old is None:
            raise KeyError(f"unknown node {node_id}")
        if old.process and old.process.poll() is None:
            raise RuntimeError(f"node {node_id} still running; stop it first")

        bin_path = self.jkaind_bin
        assert self.cluster_info is not None

        run_args = [
            str(bin_path), "run",
            "--cluster", str(self.cluster_info.cluster_toml),
            "--node-id", str(node_id),
            "--secret", str(self.cluster_info.cluster_dir / f"secret-{node_id}.bin"),
            "--data", str(old.data_dir),
            "--gossip-port", str(old.real_gossip_port),
            "--control-socket", str(old.control_socket),
            "--sync-interval", str(self.config.sync_interval_ms),
            "--sync-timeout", str(self.config.sync_timeout_ms),
            "--log-level", self.config.log_level,
        ]
        if str(self.config.fanout) != "auto":
            run_args.extend(["--fanout", str(self.config.fanout)])
        run_args.extend(["--dedup", str(self.config.dedup_enabled).lower()])
        run_args.extend(["--quic", str(self.config.quic_enabled).lower()])
        if old.real_reconnect_port is not None:
            run_args.extend(["--reconnect-port", str(old.real_reconnect_port)])
        if self.config.log_file_mode == "-":
            run_args.extend(["--log-file", "-"])
        else:
            run_args.extend(["--log-file", str(old.data_dir / "logs" / "jkaind.log")])

        (old.data_dir / "logs").mkdir(parents=True, exist_ok=True)
        diag_log = open(old.data_dir / "logs" / "diagnosis.log", "ab")  # noqa: SIM115
        proc = subprocess.Popen(
            run_args,
            stdout=diag_log,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )
        old.process = proc
        old.pid = proc.pid
        setattr(old, "_diag_file", diag_log)  # type: ignore
        logger.info("Restarted node %d pid %d", node_id, proc.pid)

        # wait for this node healthy
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"restarted node {node_id} exited with {proc.returncode}")
            if old.control_socket.exists():
                try:
                    client = ControlClient(old.control_socket, timeout=2.0, retries=1)
                    await client.status()
                    logger.info("Node %d restarted and healthy", node_id)
                    return old
                except Exception:
                    pass
            await asyncio.sleep(0.3)
        raise TimeoutError(f"restarted node {node_id} not healthy within {timeout}s")

    # -- logs / diagnostics ------------------------------------------------

    def collect_logs(self, node_id: Optional[int] = None, tail: int = 200) -> str:
        """Return tail of logs for one or all nodes."""
        targets = [self._nodes[node_id]] if node_id else list(self._nodes.values())
        out: List[str] = []
        for h in targets:
            for candidate in [
                h.log_file,
                h.data_dir / "logs" / "jkaind.log",
                h.data_dir / "logs" / "diagnosis.log",
            ]:
                if candidate and candidate.is_file():
                    try:
                        text = candidate.read_text(errors="replace")
                        lines = text.splitlines()
                        tail_lines = lines[-tail:]
                        out.append(f"=== node {h.node_id} {candidate} (last {len(tail_lines)} lines) ===")
                        out.extend(tail_lines)
                    except Exception as e:
                        out.append(f"=== node {h.node_id} log read error {candidate}: {e} ===")
                    break
        return "\n".join(out)

    def diagnosis_metrics(self, node_id: Optional[int] = None) -> Dict[int, dict]:
        targets = [self._nodes[node_id]] if node_id is not None else list(self._nodes.values())
        out: Dict[int, dict] = {}
        for h in targets:
            p = h.data_dir / "logs" / "diagnosis.log"
            out[h.node_id] = parse_diagnosis_log(p)
        return out

    def node_handle(self, node_id: int) -> NodeHandle:
        return self._nodes[node_id]

    def nodes(self) -> List[NodeHandle]:
        return list(self._nodes.values())

    @property
    def tmp_dir(self) -> Optional[Path]:
        return self._tmp_dir

    # -- cleanup -----------------------------------------------------------

    def stop_all(self) -> None:
        for nid in list(self._nodes.keys()):
            try:
                self.stop_node(nid)
            except Exception as e:
                logger.warning("stop_all node %d error: %s", nid, e)

    async def _stop_mesh(self) -> None:
        if self._mesh:
            try:
                await self._mesh.stop()
            except Exception as e:
                logger.warning("mesh stop error: %s", e)
            self._mesh = None

    def cleanup(self) -> None:
        """Kill all processes, close mesh, remove temp dir."""
        # kill processes
        for handle in self._nodes.values():
            proc = handle.process
            if proc and proc.poll() is None:
                try:
                    if os.name != "nt":
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass
            # close diag file
            diag = getattr(handle, "_diag_file", None)
            if diag:
                try:
                    diag.close()
                except Exception:
                    pass
        self._nodes.clear()
        # mesh – need async stop; try loop if running
        if self._mesh is not None:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # schedule but don't await; best effort
                    asyncio.ensure_future(self._mesh.stop())
                else:
                    loop.run_until_complete(self._mesh.stop())
            except Exception:
                pass
            self._mesh = None
        # remove temp dir
        if self._tmp_dir and self._owns_tmp and self._tmp_dir.exists():
            try:
                shutil.rmtree(str(self._tmp_dir), ignore_errors=True)
            except Exception as e:
                logger.warning("cleanup rmtree %s error: %s", self._tmp_dir, e)
        self._started = False
        # unregister atexit
        try:
            atexit.unregister(self._atexit_cleanup)
        except Exception:
            pass

    def _atexit_cleanup(self) -> None:
        # synchronous best-effort
        for handle in self._nodes.values():
            proc = handle.process
            if proc and proc.poll() is None:
                try:
                    if os.name != "nt":
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass
        if self._tmp_dir and self._owns_tmp and self._tmp_dir.exists():
            try:
                shutil.rmtree(str(self._tmp_dir), ignore_errors=True)
            except Exception:
                pass

    # -- context managers --------------------------------------------------

    async def __aenter__(self) -> "ClusterManager":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # graceful stop
        self.stop_all()
        if self._mesh:
            try:
                await self._mesh.stop()
            except Exception:
                pass
        self.cleanup()

    def __del__(self) -> None:
        try:
            self._atexit_cleanup()
        except Exception:
            pass
