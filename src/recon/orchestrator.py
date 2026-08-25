"""Orchestrator: drive a recursive scan over one Query and stream findings.

The traversal itself lives in `engine.GraphScanEngine` (an event-driven graph:
seeds -> modules -> new artifacts -> modules -> ...). This module is the thin
layer that adapts the engine to the three consumers — the SSE server, the CLI,
and the durable `scan()` persistence path — and keeps the same event-dict
contract those consumers already depend on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator

from .activity import ActivityCallback
from .config import SETTINGS, Settings
from .engine import GraphScanEngine
from .models import Finding, Query

logger = logging.getLogger(__name__)


async def run_stream(query: Query, settings: Settings = SETTINGS,
                     intake: dict | None = None) -> AsyncIterator[dict]:
    """Yield activity, finding, summary, reasoning, done, or error event dicts.

    Each module runs through its resilient wrapper (cache + circuit breaker +
    reliability), so a dead source degrades gracefully and recursion proceeds."""
    engine = GraphScanEngine(query, settings, intake=intake)
    async for event in engine.stream():
        yield event


async def run_collect(query: Query, settings: Settings = SETTINGS,
                      intake: dict | None = None) -> dict:
    """Non-streaming convenience: run fully and return all findings + summary."""
    findings: list[Finding] = []
    summary: dict = {}
    reasoning: dict = {}
    async for ev in run_stream(query, settings, intake=intake):
        if ev["type"] == "finding":
            findings.append(Finding(**ev["finding"]))
        elif ev["type"] == "summary":
            summary = ev["summary"]
        elif ev["type"] == "reasoning":
            reasoning = ev["reasoning"]
        elif ev["type"] == "error":
            raise RuntimeError(ev["message"])
    return {"findings": findings, "summary": summary, "reasoning": reasoning}


async def scan(query: Query, *, label: str | None = None, watchlist: bool = False,
               settings: Settings = SETTINGS, owner_id: int | None = None,
               activity_callback: ActivityCallback | None = None,
               intake: dict | None = None) -> dict:
    """Durable scan: persist a Run + Observations + the discovery graph, correlate
    into the identity graph, and diff against the previous run for change detection.

    Returns {"run_id", "target_id", "findings", "summary", "changes",
             "artifacts", "edges", "stop_reason"}.
    """
    from .correlate.graph import correlate_run
    from .monitor.diff import diff_run
    from .provenance import provenance
    from .rules import evaluate, load_rules
    from .store import get_db, repo

    db = get_db()
    from .source_pack import uses_external_pack

    if settings.expansion_requested or uses_external_pack(settings):
        from .expansion import require_ready

        require_ready(db, "source_pack")
    query = query.normalized()
    if query.is_empty():
        raise ValueError("at least one identifier is required")

    # Create target + run (sync DB work off the event loop).
    def _open():
        with db.session() as s:
            target = repo.get_or_create_target(
                s, query, label=label, watchlist=watchlist, owner_id=owner_id
            )
            run = repo.create_run(s, target)
            return target.id, run.id

    target_id, run_id = await asyncio.to_thread(_open)

    from .source_pack import uses_external_pack

    if settings.expansion_requested or uses_external_pack(settings):
        from .expansion import require_ready
        from .store import get_db

        require_ready(get_db(), "source_pack")
    engine = GraphScanEngine(query, settings, intake=intake)
    findings: list[Finding] = []
    activity_reporting_failed = False

    def _mark_failed(error: str) -> None:
        from .keys import redact

        with db.session() as s:
            run = s.get(repo.m.Run, run_id)
            if run is not None:
                repo.finish_run(s, run, "error", {"error": redact(error)[:500]})

    try:
        async for ev in engine.stream():
            if ev["type"] == "finding":
                findings.append(Finding(**ev["finding"]))
            elif (
                ev["type"] == "activity"
                and activity_callback is not None
                and not activity_reporting_failed
            ):
                try:
                    await activity_callback(ev["activity"])
                except Exception:
                    activity_reporting_failed = True
                    logger.exception("live activity reporting failed for run %s", run_id)
            elif ev["type"] == "error":
                raise RuntimeError(ev["message"])

        # Declarative correlation rules fire on the discovery graph (Phase 4).
        insights = evaluate(engine.artifacts, engine.edges, load_rules())

        def _persist():
            with db.session() as s:
                run = s.get(repo.m.Run, run_id)
                for f in findings:
                    repo.add_observation(
                        s,
                        run,
                        f,
                        reliability=float(f.data.get("source_reliability", 0.5)),
                    )
                repo.persist_graph(s, run, engine.artifacts, engine.edges)
                repo.persist_rule_findings(s, run, insights)
                run.provenance = provenance(settings)
            entities = correlate_run(db, run_id)
            from .profile import synthesize_profile

            entities["profile"] = synthesize_profile(
                query,
                findings,
                engine.artifacts,
                entities,
                intake=intake,
                stop_reason=engine.stop_reason,
            )
            changes = diff_run(db, target_id, run_id)
            with db.session() as s:
                run = s.get(repo.m.Run, run_id)
                repo.finish_run(s, run, "done", {
                    "total": len(findings),
                    "hits": sum(1 for f in findings if f.is_hit),
                    "artifacts": len(engine.artifacts),
                    "insights": len(insights),
                    "stop_reason": engine.stop_reason,
                    "reasoning": engine.reasoning,
                    "intake": intake,
                    "profile": entities["profile"],
                    "quality": {
                        **engine.promotion_stats,
                        "origin_coverage": sum(f.origin is not None for f in findings),
                        "extraction_coverage": sum(bool(f.extractions) for f in findings),
                        "partial_observations": sum(
                            f.completeness.value == "partial" for f in findings
                        ),
                    },
                })
            return entities, changes

        summary, changes = await asyncio.to_thread(_persist)
    except BaseException as exc:
        try:
            await asyncio.to_thread(_mark_failed, str(exc))
        except Exception:
            logger.exception("failed to persist error status for run %s", run_id)
        raise
    return {
        "run_id": run_id,
        "target_id": target_id,
        "findings": findings,
        "summary": summary,
        "changes": changes,
        "artifacts": engine.artifacts,
        "edges": engine.edges,
        "insights": insights,
        "reasoning": engine.reasoning,
        "stop_reason": engine.stop_reason,
    }
