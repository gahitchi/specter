"""The Connector wrapper: resilience around a raw collector function."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..http_client import RateLimitedClient, RequestBudgetExceeded
from ..keys import redact
from ..models import Finding, Query, Verdict
from . import cache

# Raw collector signature: async def collect(query, client, emit)
CollectFn = Callable[[Query, RateLimitedClient, Callable[[Finding], Awaitable[None]]], Awaitable[None]]
EmitFn = Callable[[Finding], Awaitable[None]]


@dataclass
class Connector:
    name: str
    kind: str  # Matches a typed Query field consumed by this connector.
    collect: CollectFn
    reliability_prior: float = 0.5
    requires_keys: list[str] = field(default_factory=list)
    use_cache: bool = True
    enabled: bool = True

    def applicable(self, query: Query) -> bool:
        return self.enabled and bool(getattr(query, self.kind, None))

    async def run(self, query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
        """Run with cache + circuit breaker + reliability tracking. Never raises:
        a failing source degrades gracefully and the rest of the scan proceeds."""
        self._rel = await asyncio.to_thread(
            cache.current_reliability, self.name, self.kind, self.reliability_prior
        )

        # 1) Cache: replay prior findings instead of hitting live sources.
        if self.use_cache:
            cached = await asyncio.to_thread(cache.get_cached, self.name, query)
            if cached is not None:
                for f in cached:
                    f.reasons = [*f.reasons, "(from cache)"]
                    await emit(self._tag(f))
                return

        # 2) Circuit breaker: skip dead sources during cooldown.
        if await asyncio.to_thread(cache.breaker_open, self.name, self.kind,
                                   self.reliability_prior):
            await emit(Finding(
                source=self.name, category=self.kind, label=self.name,
                verdict=Verdict.ERROR, confidence=0.0,
                reasons=["source circuit-breaker open (skipped, will retry later)"],
            ))
            return

        # 3) Run the collector, buffering findings so we can cache the result.
        buffered: list[Finding] = []

        async def capture(f: Finding) -> None:
            buffered.append(f)
            await emit(self._tag(f))

        try:
            await self.collect(query, client, capture)
        except RequestBudgetExceeded:
            raise
        except Exception as e:  # noqa: BLE001 - isolate source failures
            error = redact(str(e))
            await asyncio.to_thread(cache.record_failure, self.name, self.kind,
                                    self.reliability_prior, error)
            await emit(Finding(
                source=self.name, category=self.kind, label=self.name,
                verdict=Verdict.ERROR, reasons=[f"connector failed: {error}"],
            ))
            return

        # 4) Health bookkeeping: treat an all-ERROR result as a failure.
        non_error = [f for f in buffered if f.verdict != Verdict.ERROR]
        if buffered and not non_error:
            await asyncio.to_thread(cache.record_failure, self.name, self.kind,
                                    self.reliability_prior, "all results errored")
        else:
            await asyncio.to_thread(cache.record_success, self.name, self.kind,
                                    self.reliability_prior)
            if self.use_cache and non_error:
                await asyncio.to_thread(cache.set_cached, self.name, query, buffered)

    def _tag(self, f: Finding) -> Finding:
        """Stamp the run's reliability onto each finding for downstream
        confidence weighting."""
        f.data = {**f.data, "source_reliability": getattr(self, "_rel", self.reliability_prior)}
        return f
