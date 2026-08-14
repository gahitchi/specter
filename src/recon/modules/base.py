"""Module interface + the resilience wrapper that runs one module against one
artifact (cache replay + circuit breaker + reliability bookkeeping).

The resilience logic mirrors `connectors/base.Connector.run`, but operates on an
Artifact rather than a whole Query, and caches BOTH the findings a module emits
and the artifacts it produces — so a cache hit still drives recursion forward.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..activity import ActivityCallback, artifact_activity_id, safe_display_url
from ..config import Settings
from ..connectors import cache
from ..graph_models import Artifact, ArtifactType
from ..http_client import RateLimitedClient, RequestBudgetExceeded
from ..keys import redact
from ..models import Finding, Query, Verdict

EmitFinding = Callable[[Finding], Awaitable[None]]
EmitArtifact = Callable[[Artifact], Awaitable[bool | None]]


@dataclass
class ModuleContext:
    """What a module is handed when it runs. Modules grow the graph through
    `emit_artifact` and report evidence through `emit_finding`; the two are
    decoupled (a finding need not yield an artifact, and vice versa)."""

    client: RateLimitedClient
    query: Query                       # the original seed identifiers
    settings: Settings
    in_scope: Callable[[Artifact], bool]
    _emit_finding: EmitFinding
    _emit_artifact: EmitArtifact
    _emit_activity: ActivityCallback | None = None
    activity_parent_id: str | None = None
    activity_metrics: dict[str, Any] | None = None

    async def emit_finding(self, f: Finding) -> None:
        if self.activity_metrics is not None:
            self.activity_metrics.setdefault("verdicts", []).append(f.verdict.value)
        if self._emit_activity is not None:
            await self._emit_activity({
                "kind": "finding",
                "parent_id": self.activity_parent_id,
                "phase": "resolved",
                "status": "finished",
                "outcome": f.verdict.value.casefold(),
                "source": f.source,
                "category": f.category,
                "label": f.label,
                "url": safe_display_url(f.url or ""),
                "verdict": f.verdict.value,
                "confidence": f.confidence,
                "reason": redact(f.reasons[0]) if f.reasons else "",
            })
        await self._emit_finding(f)

    async def emit_artifact(self, a: Artifact) -> bool:
        admitted = await self._emit_artifact(a)
        if admitted is False:
            return False
        if self.activity_metrics is not None:
            self.activity_metrics["artifacts"] = self.activity_metrics.get("artifacts", 0) + 1
        if self._emit_activity is not None:
            await self._emit_activity({
                "kind": "artifact",
                "id": artifact_activity_id(a.key),
                "parent_id": self.activity_parent_id,
                "phase": "discovered",
                "status": "finished",
                "outcome": "success",
                "artifact_type": a.type.value,
                "label": a.value,
                "module": a.source_module,
                "confidence": a.confidence,
                "depth": a.depth,
                "in_scope": self.in_scope(a),
            })
        return True

    def for_dispatch(self, process_id: str) -> "ModuleContext":
        """Create an activity-isolated context for one module dispatch."""
        return ModuleContext(
            client=self.client,
            query=self.query,
            settings=self.settings,
            in_scope=self.in_scope,
            _emit_finding=self._emit_finding,
            _emit_artifact=self._emit_artifact,
            _emit_activity=self._emit_activity,
            activity_parent_id=process_id,
            activity_metrics={"verdicts": [], "artifacts": 0},
        )

    def child(self, _emit_finding: EmitFinding, _emit_artifact: EmitArtifact) -> "ModuleContext":
        """A ctx with the same wiring but redirected emitters (used to capture
        a module's output for caching before forwarding it on)."""
        return ModuleContext(
            client=self.client, query=self.query, settings=self.settings,
            in_scope=self.in_scope, _emit_finding=_emit_finding,
            _emit_artifact=_emit_artifact,
        )


ModuleFn = Callable[[Artifact, ModuleContext], Awaitable[None]]


@dataclass
class Module:
    name: str
    consumes: set[ArtifactType]
    produces: set[ArtifactType]
    run: ModuleFn
    reliability_prior: float = 0.5
    requires_keys: list[str] = field(default_factory=list)
    passive: bool = True           # active modules touch the target more directly
    use_cache: bool = True
    enabled: bool = True
    expansion: bool = False

    @property
    def kind_label(self) -> str:
        """A stable 'kind' for the Source/breaker row (first consumed type)."""
        return next((t.value for t in sorted(self.consumes, key=lambda x: x.value)), "module")

    def accepts(self, art: Artifact, *, expansion_enabled: bool = False) -> bool:
        return (
            self.enabled
            and (not self.expansion or expansion_enabled)
            and art.type in self.consumes
        )

    async def run_resilient(self, art: Artifact, ctx: ModuleContext) -> None:
        """Run with cache + breaker + reliability; never raises. A failing
        module degrades gracefully and the rest of the scan proceeds."""
        rel = await asyncio.to_thread(
            cache.current_reliability, self.name, self.kind_label, self.reliability_prior
        )
        ckey = f"{self.name}:{art.key}"

        # 1) Cache: replay prior findings + artifacts instead of hitting sources.
        if self.use_cache:
            cached = await asyncio.to_thread(cache.get_cached_key, ckey)
            if cached is not None:
                for fd in cached.get("findings", []):
                    f = Finding(**fd)
                    f.reasons = [*f.reasons, "(from cache)"]
                    f.data = {**f.data, "source_reliability": rel}
                    await ctx.emit_finding(f)
                for ad in cached.get("artifacts", []):
                    await ctx.emit_artifact(Artifact(**ad))
                return

        # 2) Circuit breaker: skip dead sources during cooldown.
        if await asyncio.to_thread(cache.breaker_open, self.name, self.kind_label,
                                   self.reliability_prior):
            await ctx.emit_finding(Finding(
                source=self.name, category=self.kind_label, label=self.name,
                verdict=Verdict.ERROR, confidence=0.0,
                reasons=["source circuit-breaker open (skipped, will retry later)"],
            ))
            return

        # 3) Run the module, buffering output so we can cache it.
        buf_f: list[Finding] = []
        buf_a: list[Artifact] = []

        async def capture_finding(f: Finding) -> None:
            f.data = {**f.data, "source_reliability": rel}
            buf_f.append(f)
            await ctx.emit_finding(f)

        async def capture_artifact(a: Artifact) -> bool:
            buf_a.append(a)
            return await ctx.emit_artifact(a)

        cctx = ctx.child(capture_finding, capture_artifact)
        try:
            await self.run(art, cctx)
        except RequestBudgetExceeded:
            raise
        except Exception as e:  # noqa: BLE001 - isolate module failures
            error = redact(str(e))
            await asyncio.to_thread(cache.record_failure, self.name, self.kind_label,
                                    self.reliability_prior, error)
            await ctx.emit_finding(Finding(
                source=self.name, category=self.kind_label, label=self.name,
                verdict=Verdict.ERROR, reasons=[f"module failed: {error}"],
            ))
            return

        # 4) Health bookkeeping: an all-ERROR result counts as a failure.
        non_error = [f for f in buf_f if f.verdict != Verdict.ERROR]
        if buf_f and not non_error:
            await asyncio.to_thread(cache.record_failure, self.name, self.kind_label,
                                    self.reliability_prior, "all results errored")
        else:
            await asyncio.to_thread(cache.record_success, self.name, self.kind_label,
                                    self.reliability_prior)
            if self.use_cache and (non_error or buf_a):
                await asyncio.to_thread(cache.set_cached_key, ckey, {
                    "findings": [f.model_dump() for f in buf_f],
                    "artifacts": [a.model_dump() for a in buf_a],
                })
