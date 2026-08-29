"""
JKaIN hard-testing harness.

Importable as:
    from harness.cluster import ClusterManager, ClusterConfig
    from harness.control import ControlClient
    from harness.proxy import LatencyProxy, LatencyMesh
    from harness.metrics import wait_for_decided_round, wait_for_checkpoint
"""

from .cluster import ClusterConfig, ClusterInfo, ClusterManager, NodeHandle, find_jkaind_binary
from .control import ControlClient, ControlError, StatusReport, encode_delete, encode_put
from .metrics import (
    checkpoint_roster_consistent,
    collect_statuses,
    frontiers_within_bound,
    wait_for_checkpoint,
    wait_for_decided_round,
    wait_for_ordered_round,
    wait_for_state_convergence,
)
from .proxy import LatencyMesh, LatencyProxy

__all__ = [
    "ClusterConfig",
    "ClusterInfo",
    "ClusterManager",
    "NodeHandle",
    "find_jkaind_binary",
    "ControlClient",
    "ControlError",
    "StatusReport",
    "encode_put",
    "encode_delete",
    "LatencyMesh",
    "LatencyProxy",
    "collect_statuses",
    "wait_for_decided_round",
    "wait_for_checkpoint",
    "wait_for_ordered_round",
    "wait_for_state_convergence",
    "frontiers_within_bound",
    "checkpoint_roster_consistent",
]
