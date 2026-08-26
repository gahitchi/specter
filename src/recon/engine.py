"""The event-driven recursive scan engine.

A scan is a best-first graph traversal. Seed identifiers become depth-0
artifacts; each artifact is dispatched to every module that consumes its type;
modules emit findings (streamed live) and new artifacts (pivots) that are
deduped, scope-checked, and budget-checked before being fed back into the
frontier. This is the capability that turns single-pass collection into the
recursive, self-pivoting traversal that defines tools like SpiderFoot — kept
honest here by hard depth/artifact/request ceilings and a scope policy.

The engine preserves the event-dict contract used by the CLI, SSE server, and
persistence path while adding `activity` and `reasoning` events. Discovered
artifacts and the edges between them are exposed on the instance
(`.artifacts`, `.edges`) for persistence and graph inspection.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from .activity import ACTIVE_PROCESS_ID, artifact_activity_id
from .config import SETTINGS, Settings
from .correlate import score
from .correlate.cluster import cluster, identity_bearing
from .evidence import assess_promotion, confirmation_satisfied
from .graph_models import Artifact, ArtifactType
from .http_client import RateLimitedClient, RequestBudgetExceeded
from .keys import VAULT, redact
from .models import Finding, Query
from .modules.base import ModuleContext
from .modules.registry import applicable_modules
from .reasoning import InvestigationReasoner

# Artifact types that descend from an in-scope parent and are always safe to
# expand in strict mode (they can't broaden the investigation's subject).
_DESCENDANT_TYPES = {
    ArtifactType.IP_ADDRESS,
    ArtifactType.ASN,
    ArtifactType.NETBLOCK,
    ArtifactType.HASH,
    ArtifactType.BREACH,
    ArtifactType.ACCOUNT_PROFILE,
    ArtifactType.URL,
}
_HOST_TYPES = {
    ArtifactType.SUBDOMAIN,
    ArtifactType.HOSTNAME,
    ArtifactType.MX_HOST,
    ArtifactType.NAMESERVER,
}

# Frontier priority: when a request budget may cut a wave short, expand the
# highest-yield leads first. Identifiers that tie identities together (email,
# account profile, domain, username) are worth more than terminal/network
# breadcrumbs (an IP geo lookup rarely unlocks a new identity). Ties break on
# the artifact's own confidence, then on shallower depth (closer to the seed).
_TYPE_PRIORITY = {
    ArtifactType.EMAIL: 100,
    ArtifactType.ACCOUNT_PROFILE: 90,
    ArtifactType.DOMAIN: 80,
    ArtifactType.USERNAME: 75,
    ArtifactType.SUBDOMAIN: 60,
    ArtifactType.HOSTNAME: 55,
    ArtifactType.MX_HOST: 50,
    ArtifactType.NAMESERVER: 45,
    ArtifactType.URL: 40,
    ArtifactType.LINK: 38,
    ArtifactType.IP_ADDRESS: 35,
    ArtifactType.NETBLOCK: 30,
    ArtifactType.ASN: 28,
    ArtifactType.BREACH: 25,
    ArtifactType.HASH: 20,
    ArtifactType.PHONE: 95,
    ArtifactType.NAME: 10,
}


@dataclass
class ScopePolicy:
    """Decides whether a newly discovered artifact may be *expanded* (have
    modules run on it). Out-of-scope artifacts are still recorded as graph nodes
    — they just don't broaden the traversal. Seeds are always in scope."""

    mode: str
    seed_domains: set[str] = field(default_factory=set)
    seed_handles: set[str] = field(default_factory=set)
    seed_emails: set[str] = field(default_factory=set)

    @classmethod
    def from_query(cls, query: Query, mode: str) -> "ScopePolicy":
        from .normalize import fold_handle, norm_domain

        domains: set[str] = set()
        if query.domain:
            domains.add(query.domain)
        if query.email and "@" in query.email:
            d = norm_domain(query.email.rsplit("@", 1)[-1])
            if d:
                domains.add(d)
        handles: set[str] = set()
        if query.username:
            h = fold_handle(query.username)
            if h:
                handles.add(h)
        emails = {query.email} if query.email else set()
        return cls(
            mode=mode,
            seed_domains=domains,
            seed_handles=handles,
            seed_emails=emails,
        )

    def in_scope(self, art: Artifact) -> bool:
        if self.mode == "aggressive":
            return True
        t = art.type
        promotion = art.data.get("promotion") or {}
        corroborated_subject_bridge = bool(
            art.parent_key
            and art.data.get("subject_relation") == "same_subject"
            and art.policy.requires_corroboration
            and promotion.get("allowed", False)
            and t
            in {
                ArtifactType.EMAIL,
                ArtifactType.USERNAME,
                ArtifactType.ACCOUNT_PROFILE,
            }
        )
        if corroborated_subject_bridge:
            return True
        if t in _DESCENDANT_TYPES:
            return True
        if t in _HOST_TYPES or t == ArtifactType.DOMAIN:
            return any(
                art.normalized == d or art.normalized.endswith("." + d) for d in self.seed_domains
            )
        if t == ArtifactType.USERNAME:
            from .normalize import fold_handle

            folded = fold_handle(art.normalized)
            return bool(folded and folded in self.seed_handles)
        if t == ArtifactType.EMAIL:
            return art.normalized in self.seed_emails
        # NAME / PHONE / LINK discovered mid-traversal: record, don't expand.
        return False


@dataclass
class _Edge:
    src_key: str
    dst_key: str
    module: str
    detail: dict


class GraphScanEngine:
    def __init__(
        self, query: Query, settings: Settings = SETTINGS, intake: dict | None = None
    ) -> None:
        self.query = query.normalized()
        self.settings = settings
        self.intake = intake
        self.scope = ScopePolicy.from_query(self.query, settings.scope_mode)
        # Results exposed for persistence / inspection.
        self.artifacts: list[Artifact] = []
        self.edges: list[_Edge] = []
        self.stop_reason: Optional[str] = None
        self.reasoning: dict = {}
        self.reasoner = InvestigationReasoner()
        # Traversal state.
        self._seen: set[str] = set()
        self._artifact_by_key: dict[str, Artifact] = {}
        self._promotion_origins: dict[str, set[str]] = {}
        self._queued: set[str] = set()
        self.promotion_stats = {
            "attempted": 0,
            "duplicates_collapsed": 0,
            "blocked": 0,
            "promoted_after_corroboration": 0,
        }

    @staticmethod
    def _priority(art: Artifact) -> tuple:
        """Best-first ordering key (higher sorts first): identity-bearing types,
        then the artifact's confidence, then shallower depth."""
        return (_TYPE_PRIORITY.get(art.type, 0), art.confidence, -art.depth)

    def _admit_node(self, art: Artifact) -> bool:
        """Record an artifact as a graph node (deduped, budgeted). Returns True
        if it is newly admitted."""
        if art.key in self._seen:
            self.promotion_stats["duplicates_collapsed"] += 1
            return False
        if len(self._seen) >= self.settings.max_artifacts:
            self.stop_reason = self.stop_reason or "max_artifacts reached"
            return False
        self._seen.add(art.key)
        self.artifacts.append(art)
        self._artifact_by_key[art.key] = art
        return True

    def _should_expand(self, art: Artifact) -> bool:
        if art.depth > self.settings.max_depth:
            return False
        origins = len(self._promotion_origins.get(art.key, set()))
        assessment = assess_promotion(art.policy, origins)
        art.data["promotion"] = assessment.model_dump(mode="json")
        return assessment.allowed and self.scope.in_scope(art)

    def _register_promotion_origin(self, art: Artifact) -> None:
        origin = (
            str(
                (art.origin.independence_key if art.origin is not None else "")
                or art.data.get("independence_key")
                or art.data.get("origin")
                or art.source_module
                or "unknown"
            )
            .strip()
            .casefold()
        )
        if origin:
            self._promotion_origins.setdefault(art.key, set()).add(origin)

    def _module_enabled(self, mod) -> bool:
        if self.settings.passive_only and not mod.passive:
            return False
        if mod.requires_keys and not VAULT.has_all(mod.requires_keys):
            return False
        return True

    async def stream(self) -> AsyncIterator[dict]:
        if self.query.is_empty():
            yield {"type": "error", "message": "no identifiers provided"}
            return

        queue: asyncio.Queue[dict | None] = asyncio.Queue()
        collected: list[Finding] = []
        activity_sequence = 0
        process_sequence = 0
        activity_lock = asyncio.Lock()
        fatal_error: str | None = None

        async def emit_activity(activity: dict) -> None:
            nonlocal activity_sequence
            async with activity_lock:
                activity_sequence += 1
                payload = {
                    "sequence": activity_sequence,
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    **activity,
                }
                payload.setdefault("id", f"{payload.get('kind', 'activity')}:{activity_sequence}")
                await queue.put({"type": "activity", "activity": payload})

        async def emit_finding(f: Finding) -> None:
            collected.append(f)
            await queue.put({"type": "finding", "finding": f.model_dump()})

        # next_frontier is rebound each wave; the closure reads the current one.
        state = {"next": []}

        async def emit_artifact(a: Artifact) -> bool:
            self.promotion_stats["attempted"] += 1
            if a.parent_key:  # always record provenance, even for dup/oob nodes
                self.edges.append(
                    _Edge(a.parent_key, a.key, a.source_module, a.data.get("edge", {}))
                )
            before = len(self._promotion_origins.get(a.key, set()))
            self._register_promotion_origin(a)
            admitted = self._admit_node(a)
            stored = self._artifact_by_key.get(a.key, a)
            if not admitted:
                if (
                    a.key not in self._queued
                    and before < len(self._promotion_origins.get(a.key, set()))
                    and self._should_expand(stored)
                ):
                    state["next"].append(stored)
                    self._queued.add(a.key)
                    self.promotion_stats["promoted_after_corroboration"] += 1
                return False
            if self._should_expand(stored):
                state["next"].append(stored)
                self._queued.add(a.key)
            elif not stored.data.get("promotion", {}).get("allowed", True):
                self.promotion_stats["blocked"] += 1
            return True

        def process_outcome(metrics: dict) -> str:
            verdicts = set(metrics.get("verdicts", []))
            if "FOUND" in verdicts or metrics.get("artifacts", 0):
                return "success"
            if verdicts & {"UNCERTAIN", "UNVERIFIABLE"}:
                return "uncertain"
            if "ERROR" in verdicts:
                return "error"
            return "not_found"

        async def worker() -> None:
            nonlocal fatal_error, process_sequence
            from .ratelimit import get_limiter

            try:
                async with RateLimitedClient(
                    self.settings,
                    limiter=get_limiter(self.settings),
                    activity_callback=emit_activity,
                ) as client:
                    ctx = ModuleContext(
                        client=client,
                        query=self.query,
                        settings=self.settings,
                        in_scope=self.scope.in_scope,
                        _emit_finding=emit_finding,
                        _emit_artifact=emit_artifact,
                        _emit_activity=emit_activity,
                    )
                    # Seed the frontier (seeds are always admitted + expanded).
                    frontier: list[Artifact] = []
                    for seed in self.query.to_seed_artifacts():
                        if self._admit_node(seed):
                            self._register_promotion_origin(seed)
                            self._queued.add(seed.key)
                            frontier.append(seed)
                            await emit_activity(
                                {
                                    "kind": "artifact",
                                    "id": artifact_activity_id(seed.key),
                                    "parent_id": None,
                                    "phase": "seeded",
                                    "status": "finished",
                                    "outcome": "success",
                                    "artifact_type": seed.type.value,
                                    "label": seed.value,
                                    "module": "seed",
                                    "confidence": seed.confidence,
                                    "depth": 0,
                                    "in_scope": True,
                                }
                            )
                    frontier.sort(key=self._priority, reverse=True)

                    async def run_dispatch(art: Artifact, mod, process_id: str) -> None:
                        dispatch_ctx = ctx.for_dispatch(process_id)
                        base_activity = {
                            "kind": "process",
                            "id": process_id,
                            "parent_id": artifact_activity_id(art.key),
                            "module": mod.name,
                            "label": mod.name,
                            "artifact_id": artifact_activity_id(art.key),
                            "artifact_type": art.type.value,
                            "artifact_label": art.value,
                        }
                        await emit_activity(
                            {
                                **base_activity,
                                "phase": "started",
                                "status": "running",
                            }
                        )
                        token = ACTIVE_PROCESS_ID.set(process_id)
                        try:
                            await mod.run_resilient(art, dispatch_ctx)
                        except RequestBudgetExceeded:
                            await emit_activity(
                                {
                                    **base_activity,
                                    "phase": "stopped",
                                    "status": "finished",
                                    "outcome": "error",
                                    "error": "request budget exhausted",
                                }
                            )
                            raise
                        except Exception as exc:
                            await emit_activity(
                                {
                                    **base_activity,
                                    "phase": "failed",
                                    "status": "finished",
                                    "outcome": "error",
                                    "error": redact(str(exc))[:300],
                                }
                            )
                            raise
                        else:
                            metrics = dispatch_ctx.activity_metrics or {}
                            await emit_activity(
                                {
                                    **base_activity,
                                    "phase": "finished",
                                    "status": "finished",
                                    "outcome": process_outcome(metrics),
                                    "findings": len(metrics.get("verdicts", [])),
                                    "artifacts": metrics.get("artifacts", 0),
                                }
                            )
                        finally:
                            ACTIVE_PROCESS_ID.reset(token)

                    batch_size = max(1, self.settings.max_concurrency)
                    while frontier:
                        if client.request_count >= self.settings.max_requests:
                            self.stop_reason = self.stop_reason or "max_requests reached"
                            break
                        state["next"] = []
                        # Flatten the best-first frontier into ordered dispatches
                        # so a tight budget is spent on the strongest leads first.
                        dispatches = [
                            (art, mod)
                            for art in frontier
                            for mod in (
                                applicable_modules(art, expansion_enabled=True)
                                if self.settings.expansion_requested
                                else applicable_modules(art)
                            )
                            if self._module_enabled(mod)
                        ]
                        dispatches = self.reasoner.rank_dispatches(
                            frontier,
                            dispatches,
                            collected,
                            self.artifacts,
                            self.settings.max_requests - client.request_count,
                        )
                        findings_before = len(collected)
                        artifacts_before = len(self.artifacts)
                        requests_before = client.request_count
                        stopped = False
                        for i in range(0, len(dispatches), batch_size):
                            if client.request_count >= self.settings.max_requests:
                                self.stop_reason = self.stop_reason or "max_requests reached"
                                stopped = True
                                break
                            batch = dispatches[i : i + batch_size]
                            scheduled = []
                            for art, mod in batch:
                                process_sequence += 1
                                scheduled.append(
                                    run_dispatch(art, mod, f"process:{process_sequence}")
                                )
                            results = await asyncio.gather(*scheduled, return_exceptions=True)
                            if client.budget_exhausted or any(
                                isinstance(result, RequestBudgetExceeded) for result in results
                            ):
                                self.stop_reason = self.stop_reason or "max_requests reached"
                                stopped = True
                                break
                        if stopped:
                            break
                        self.reasoner.complete_wave(
                            new_findings=len(collected) - findings_before,
                            new_artifacts=len(self.artifacts) - artifacts_before,
                            requests_used=client.request_count - requests_before,
                        )
                        if state["next"] and self.reasoner.low_yield_waves >= 2:
                            self.stop_reason = self.stop_reason or "diminishing returns"
                            break
                        frontier = sorted(state["next"], key=self._priority, reverse=True)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - terminate the stream cleanly
                fatal_error = redact(str(exc))
                await queue.put({"type": "error", "message": fatal_error})
            finally:
                await queue.put(None)

        task = asyncio.create_task(worker())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            if not task.done():
                task.cancel()
            with suppress(asyncio.CancelledError):
                await task

        if fatal_error is not None:
            return

        confirmed = [
            finding
            for finding in collected
            if confirmation_satisfied(finding, collected, self.query)
        ]
        identities = cluster(
            [finding for finding in confirmed if identity_bearing(finding.category)],
            self.query,
        )
        summary = score.summarize(identities)
        from .profile import synthesize_profile

        summary["profile"] = synthesize_profile(
            self.query,
            collected,
            self.artifacts,
            summary,
            intake=self.intake,
            stop_reason=self.stop_reason,
        )
        yield {"type": "summary", "summary": summary}
        out_of_scope = [
            artifact
            for artifact in self.artifacts
            if artifact.depth > 0 and not self.scope.in_scope(artifact)
        ]
        self.reasoning = self.reasoner.report(
            self.query,
            collected,
            self.artifacts,
            summary,
            stop_reason=self.stop_reason,
            scope_mode=self.settings.scope_mode,
            passive_only=self.settings.passive_only,
            out_of_scope=out_of_scope,
        )
        yield {"type": "reasoning", "reasoning": self.reasoning}
        yield {
            "type": "done",
            "total": len(collected),
            "hits": len(confirmed),
            "confirmed_hits": len(confirmed),
            "observed_hits": sum(1 for finding in collected if finding.is_hit),
            "artifacts": len(self.artifacts),
            "stop_reason": self.stop_reason,
        }
