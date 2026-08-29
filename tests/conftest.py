"""
conftest.py – shared pytest fixtures for JKaIN hard tests.

Provides:
  - cluster_factory : factory fixture that creates ClusterManagers and ensures cleanup
  - six_node_cluster : convenience wrapper (not auto-used)
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from harness.cluster import ClusterConfig, ClusterManager

# Ensure pytest-asyncio auto mode is available even without pytest.ini
pytest_plugins = ("pytest_asyncio",)


@pytest_asyncio.fixture
async def cluster_factory():
    """Factory that tracks created managers and cleans them up after the test."""
    managers: list[ClusterManager] = []

    def _make(config: ClusterConfig | None = None, **kwargs) -> ClusterManager:
        if config is None:
            config = ClusterConfig(**kwargs)
        else:
            for k, v in kwargs.items():
                setattr(config, k, v)
        mgr = ClusterManager(config)
        managers.append(mgr)
        return mgr

    yield _make

    # teardown – stop all clusters even on failure
    for mgr in managers:
        try:
            mgr.stop_all()
        except Exception:
            pass
        # also stop mesh if present
        if mgr._mesh is not None:  # type: ignore[attr-defined]
            try:
                import asyncio

                await mgr._mesh.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        try:
            mgr.cleanup()
        except Exception:
            pass


@pytest_asyncio.fixture
async def six_node_cluster(cluster_factory):  # type: ignore[no-untyped-def]
    """
    Convenience: pre-spawned 6-node cluster without proxy.
    Yields started ClusterManager; cleans up via cluster_factory.
    """
    mgr = cluster_factory(ClusterConfig(num_nodes=6, use_proxy=False))
    await mgr.start()
    yield mgr
