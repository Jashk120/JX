"""
proxy.py – TCP latency / partition proxy for hard-testing gossip.

Architecture
------------
For each real gossip/reconnect port P, expose a proxy port Q that forwards
to P with configurable delay/jitter/loss.  Cluster.toml advertises Q (the
proxy), while the node actually listens on P (hidden).  All inter-node sync
traffic therefore must flow through a proxy, where we can inject faults.

LatencyProxy
    Single TCP forwarding proxy (asyncio.start_server -> asyncio.open_connection).

LatencyMesh
    Helper that creates 2*N proxies (gossip + reconnect) for N nodes and
    rewrites cluster.toml gossip addrs to proxy addrs.  Supports dynamic
    latency and partition control.

Notes on partitioning
---------------------
Per-node proxies multiplex all sources, so the mesh cannot perfectly
distinguish which node originated a given TCP connection (source port is
ephemeral).  ``set_partition(partA, partB)`` is approximated as:

* ``isolate_node(node_id)`` – ingress-only isolation: stop that node's
  proxy so no peer can connect to it.  Its own outgoing connections to other
  proxies still succeed (asymmetric).  Use ``drop_all_to`` semantics for
  symmetric isolation via egress blocking on top.
* ``set_partition(partA, partB)`` / ``set_isolated`` – when a partition is
  active, proxies for nodes in the isolated group will drop all inbound
  connections.  Intra-group traffic for the isolated group is also
  affected; the majority group remains internally connected.  This still
  triggers the intended consensus stall for hardening tests.

For truly symmetric isolation of a single node, combine ingress blocking
with a short ``drop_prob=1.0`` on all other proxies' handling of that
node's egress if source identification via loopback IPs is not available.
The mesh documents this limitation.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LatencyProxy
# ---------------------------------------------------------------------------


class LatencyProxy:
    """
    TCP forwarding proxy that injects latency / jitter / loss.

    Listens on (listen_host, listen_port) and forwards every inbound
    connection to (target_host, target_port).
    """

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        *,
        mean_latency_ms: float = 0.0,
        jitter_ms: float = 0.0,
        drop_prob: float = 0.0,
        node_id: Optional[int] = None,
        label: str = "",
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.mean_latency_ms = mean_latency_ms
        self.jitter_ms = jitter_ms
        self.drop_prob = drop_prob
        self.node_id = node_id
        self.label = label or f"{listen_port}->{target_port}"

        self._server: Optional[asyncio.AbstractServer] = None
        self._blocked: bool = False
        # optional partition: set of node_ids that are blocked? Used by mesh.
        self._partition_blocked: bool = False

    # -- configuration -----------------------------------------------------

    def set_latency(self, mean_ms: float, jitter_ms: float = 0.0) -> None:
        """Dynamically update latency parameters."""
        self.mean_latency_ms = max(0.0, mean_ms)
        self.jitter_ms = max(0.0, jitter_ms)

    def set_drop_prob(self, prob: float) -> None:
        """Set random drop probability in [0, 1]."""
        if not 0.0 <= prob <= 1.0:
            raise ValueError("drop_prob must be in [0,1]")
        self.drop_prob = prob

    def set_blocked(self, blocked: bool) -> None:
        """Block all forwarding (partition)."""
        self._blocked = blocked

    def set_partition_blocked(self, blocked: bool) -> None:
        self._partition_blocked = blocked

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port
        )
        # update listen_port if 0 was used (ephemeral)
        if self.listen_port == 0 and self._server.sockets:
            self.listen_port = self._server.sockets[0].getsockname()[1]
        logger.info("LatencyProxy %s listening on %s:%d -> %s:%d",
                    self.label, self.listen_host, self.listen_port,
                    self.target_host, self.target_port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        logger.info("LatencyProxy %s stopped", self.label)

    @property
    def addr(self) -> Tuple[str, int]:
        return (self.listen_host, self.listen_port)

    # -- internals ---------------------------------------------------------

    def _sample_delay(self) -> float:
        if self.mean_latency_ms <= 0 and self.jitter_ms <= 0:
            return 0.0
        jitter = random.uniform(-self.jitter_ms, self.jitter_ms) if self.jitter_ms else 0.0
        delay_ms = max(0.0, self.mean_latency_ms + jitter)
        return delay_ms / 1000.0

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        # Partition / global block check
        if self._blocked or self._partition_blocked:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        # Random drop simulation
        if self.drop_prob > 0 and random.random() < self.drop_prob:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        # Inject latency on connection establishment
        delay = self._sample_delay()
        if delay > 0:
            await asyncio.sleep(delay)

        try:
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except Exception as exc:
            logger.debug("proxy %s: failed to connect to target %s:%d: %s",
                         self.label, self.target_host, self.target_port, exc)
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> None:
            try:
                while True:
                    data = await src.read(8192)
                    if not data:
                        break
                    # per-packet latency injection on forwarding
                    d = self._sample_delay()
                    # avoid double-sleep on every chunk when mean is large; only sleep a fraction
                    # Use mean/2 for pipe to avoid doubling.
                    if d > 0:
                        # scale down pipe delay to avoid 2x latency on each direction
                        await asyncio.sleep(d * 0.5)
                    dst.write(data)
                    await dst.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as exc:
                logger.debug("proxy %s pipe %s error: %s", self.label, direction, exc)
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        # bidirectional forwarding
        t1 = asyncio.create_task(_pipe(client_reader, target_writer, "c->t"))
        t2 = asyncio.create_task(_pipe(target_reader, client_writer, "t->c"))
        try:
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            for w in (client_writer, target_writer):
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# LatencyMesh
# ---------------------------------------------------------------------------


@dataclass
class ProxyEntry:
    node_id: int
    kind: str  # "gossip" or "reconnect"
    proxy: LatencyProxy
    real_port: int
    proxy_port: int


class LatencyMesh:
    """
    Mesh of LatencyProxies for an N-node cluster.

    Each node's gossip and reconnect ports are hidden behind proxies.
    The cluster.toml that is distributed to nodes advertises proxy addrs.

    Usage:
        mesh = LatencyMesh(num_nodes=6, host="127.0.0.1")
        await mesh.allocate(real_gossip_ports, real_reconnect_ports)
        mesh.proxy_gossip_addr(node_id) -> (host, proxy_port)
        await mesh.start()
        mesh.set_latency(mean_ms=30, jitter_ms=10)
        mesh.set_partition([1,2,3], [4,5,6])
        await mesh.heal()
        await mesh.stop()
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self._entries: List[ProxyEntry] = []
        self._by_node: Dict[int, Dict[str, ProxyEntry]] = {}
        self._partition: Optional[Tuple[Set[int], Set[int]]] = None

    # -- allocation --------------------------------------------------------

    async def allocate(
        self,
        node_real_ports: Dict[int, Tuple[int, Optional[int]]],
        *,
        mean_latency_ms: float = 0.0,
        jitter_ms: float = 0.0,
        drop_prob: float = 0.0,
    ) -> None:
        """
        Create proxy entries for each node's real ports.

        ``node_real_ports`` maps node_id -> (real_gossip_port, real_reconnect_port_or_None).
        Proxy ports are allocated ephemerally (bind 0 then close) to avoid collisions,
        or sequentially if ephemeral detection fails.
        """
        import socket as _socket
        self._entries.clear()
        self._by_node.clear()

        def _free_port() -> int:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.bind((self.host, 0))
                return s.getsockname()[1]

        for node_id, (gossip_real, reconnect_real) in sorted(node_real_ports.items()):
            gossip_proxy_port = _free_port()
            gossip_proxy = LatencyProxy(
                self.host, gossip_proxy_port, self.host, gossip_real,
                mean_latency_ms=mean_latency_ms, jitter_ms=jitter_ms, drop_prob=drop_prob,
                node_id=node_id, label=f"node{node_id}-gossip",
            )
            entry = ProxyEntry(node_id=node_id, kind="gossip", proxy=gossip_proxy,
                               real_port=gossip_real, proxy_port=gossip_proxy_port)
            self._entries.append(entry)
            self._by_node.setdefault(node_id, {})["gossip"] = entry

            if reconnect_real is not None:
                reconnect_proxy_port = _free_port()
                reconnect_proxy = LatencyProxy(
                    self.host, reconnect_proxy_port, self.host, reconnect_real,
                    mean_latency_ms=mean_latency_ms, jitter_ms=jitter_ms, drop_prob=drop_prob,
                    node_id=node_id, label=f"node{node_id}-reconnect",
                )
                entry2 = ProxyEntry(node_id=node_id, kind="reconnect", proxy=reconnect_proxy,
                                    real_port=reconnect_real, proxy_port=reconnect_proxy_port)
                self._entries.append(entry2)
                self._by_node[node_id]["reconnect"] = entry2

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        for e in self._entries:
            await e.proxy.start()
            # update proxy_port after ephemeral bind
            e.proxy_port = e.proxy.listen_port

    async def stop(self) -> None:
        for e in self._entries:
            await e.proxy.stop()

    # -- address helpers ---------------------------------------------------

    def proxy_gossip_addr(self, node_id: int) -> Tuple[str, int]:
        entry = self._by_node.get(node_id, {}).get("gossip")
        if entry is None:
            raise KeyError(f"no gossip proxy for node {node_id}")
        return (self.host, entry.proxy_port)

    def proxy_reconnect_addr(self, node_id: int) -> Optional[Tuple[str, int]]:
        entry = self._by_node.get(node_id, {}).get("reconnect")
        if entry is None:
            return None
        return (self.host, entry.proxy_port)

    def real_gossip_port(self, node_id: int) -> int:
        return self._by_node[node_id]["gossip"].real_port

    # -- dynamic controls ---------------------------------------------------

    def set_latency(self, mean_ms: float, jitter_ms: float = 0.0) -> None:
        for e in self._entries:
            e.proxy.set_latency(mean_ms, jitter_ms)

    def set_jitter(self, jitter_ms: float) -> None:
        for e in self._entries:
            e.proxy.set_latency(e.proxy.mean_latency_ms, jitter_ms)

    def set_drop_prob(self, prob: float) -> None:
        for e in self._entries:
            e.proxy.set_drop_prob(prob)

    def set_partition(self, part_a: List[int], part_b: List[int]) -> None:
        """
        Block forwarding between partA and partB.

        Approximation: proxies serving nodes in partB will drop all inbound
        (so A cannot reach B), and proxies serving nodes in partA will drop
        all inbound (so B cannot reach A).  Intra-group traffic for the
        majority group is preserved only when isolating a single node via
        ``isolate_node``; for a general split both groups will see increased
        drops (full partition).  For hardening tests this still validates
        stall/recovery behaviour.

        For isolating one node, prefer ``isolate_node(node_id)`` which
        preserves intra-group connectivity of the remaining nodes.
        """
        set_a = set(part_a)
        set_b = set(part_b)
        self._partition = (set_a, set_b)
        # Block proxies for cross-group: to enforce separation we block
        # proxies on *both* sides.  For single-node isolation this is
        # asymmetric now: only isolated node's proxy blocks if caller uses
        # isolate_node; but for general partition we block both.
        for e in self._entries:
            if e.node_id in set_a or e.node_id in set_b:
                # General partition: block proxies whose target is in a
                # partitioned set – this blocks both cross and intra-group
                # for those nodes.  To preserve intra-group for majority,
                # caller should use isolate_node for single-node case or
                # manage drop probabilities manually.
                e.proxy.set_partition_blocked(True)
            else:
                e.proxy.set_partition_blocked(False)

        # For single-node isolation case, unblock the majority to keep it connected:
        # If one partition is size 1, keep the larger group's proxies open and
        # only block the singleton.  This provides a useful "isolate node" semantic.
        if len(set_a) == 1 or len(set_b) == 1:
            singleton = set_a if len(set_a) == 1 else set_b
            majority = set_b if len(set_a) == 1 else set_a
            for e in self._entries:
                if e.node_id in majority:
                    e.proxy.set_partition_blocked(False)
                elif e.node_id in singleton:
                    e.proxy.set_partition_blocked(True)

    def isolate_node(self, node_id: int) -> None:
        """Isolate a single node (ingress blocked, rest of mesh stays healthy)."""
        self._partition = ({node_id}, set())
        for e in self._entries:
            e.proxy.set_partition_blocked(e.node_id == node_id)

    def heal(self) -> None:
        """Remove any partition / blocking."""
        self._partition = None
        for e in self._entries:
            e.proxy.set_partition_blocked(False)
            e.proxy.set_blocked(False)

    def heal_partition(self) -> None:
        self.heal()

    @property
    def entries(self) -> List[ProxyEntry]:
        return list(self._entries)
