"""Pluggable per-host rate limiting.

The in-process limiter lives in http_client (single-process default). For a
distributed worker fleet, an optional Redis-backed limiter coordinates politeness
across machines so a target host never sees the combined fleet's full rate.
Selected via config; absent Redis, callers simply pass limiter=None and rely on
the in-process limiter.
"""

from __future__ import annotations

import os
import math
from typing import Optional, Protocol

from .config import SETTINGS, Settings


class Limiter(Protocol):
    async def acquire(self, host: str) -> None: ...


class RedisHostLimiter:
    """Cross-process minimum-interval per host using an atomic Redis lease.

    Best-effort politeness: each host may be hit at most once per
    `per_host_min_interval` across all workers sharing the same Redis.
    """

    def __init__(self, dsn: str | None = None, min_interval: float | None = None) -> None:
        import redis.asyncio as redis  # imported only on the scale path

        self._r = redis.from_url(dsn or os.environ.get("RECON_REDIS_DSN",
                                                        "redis://localhost:6379"))
        self._min = min_interval if min_interval is not None else SETTINGS.per_host_min_interval

    async def acquire(self, host: str) -> None:
        import asyncio

        key = f"recon:rl:{host}"
        ttl_ms = max(1, math.ceil(self._min * 1000))
        while True:
            if await self._r.set(key, "1", nx=True, px=ttl_ms):
                return
            remaining_ms = await self._r.pttl(key)
            await asyncio.sleep(max(1, remaining_ms) / 1000)

    async def aclose(self) -> None:
        await self._r.aclose()


def get_limiter(settings: Settings = SETTINGS) -> Optional[Limiter]:
    """Return a cross-process limiter if the distributed backend is configured,
    else None (the in-process limiter in http_client is used)."""
    if settings.queue_backend == "arq":
        try:
            return RedisHostLimiter(min_interval=settings.per_host_min_interval)
        except ImportError as exc:
            raise RuntimeError(
                "distributed rate limiting requires the 'distributed' extra"
            ) from exc
    return None
