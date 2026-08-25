"""Confidence analytics (Phase 5d): aggregate the trust signals this project
already records — verdicts, per-finding score breakdowns, source reliability,
independence classes, and calibration history — into a few honest summaries.

The aggregation functions are pure (they take iterables of rows), so they unit-
test without a database; `compute(db)` wires them to the persisted tables and
backs `GET /api/analytics`, `specter analytics`, and the dashboard's Confidence tab.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from .trust import independent_classes

# Verdicts whose confidence is a meaningful presence estimate (ERROR /
# UNVERIFIABLE are 0.0 by definition and would just pile up at the left edge).
_SCORED = {"FOUND", "UNCERTAIN", "NOT_FOUND"}


def confidence_histogram(rows, bins: int = 10) -> list[dict]:
    out = [{"lo": i / bins, "hi": (i + 1) / bins, "count": 0} for i in range(bins)]
    for r in rows:
        if r.verdict not in _SCORED:
            continue
        idx = min(bins - 1, max(0, int((r.confidence or 0.0) * bins)))
        out[idx]["count"] += 1
    return out


def verdict_mix(rows) -> dict:
    return dict(Counter(r.verdict for r in rows))


def top_breakdown_terms(rows, limit: int = 8) -> list[dict]:
    """Which score contributions appear most, and their average signed effect —
    i.e. what actually drives confidence across a corpus of findings."""
    counts: Counter = Counter()
    totals: dict[str, float] = defaultdict(float)
    for r in rows:
        bd = getattr(r, "breakdown", None)
        if not bd:
            continue
        for c in bd.get("contributions", []):
            term = c.get("term")
            if not term:
                continue
            counts[term] += 1
            totals[term] += c.get("delta", 0.0)
    items = [{"term": t, "count": n, "mean_delta": round(totals[t] / n, 3)}
             for t, n in counts.items()]
    items.sort(key=lambda d: -d["count"])
    return items[:limit]


def independence_coverage(rows) -> dict:
    """Across FOUND findings, distinct source *names* vs independent *classes* —
    the corroboration-inflation factor the 5a shadow score corrects for."""
    found = [
        r for r in rows
        if r.verdict == "FOUND"
        and getattr(r, "temporal_status", None) != "historical"
    ]
    sources = {r.source for r in found}
    classes, redundant = independent_classes(found)
    n_names, n_classes = len(sources), len(classes)
    return {
        "found": len(found),
        "distinct_sources": n_names,
        "distinct_classes": n_classes,
        "inflation": round(n_names / n_classes, 2) if n_classes else 0.0,
        "redundant": [{"source": s, "class": c} for s, c in redundant],
    }


def source_health(sources) -> list[dict]:
    rows = [{
        "name": s.name, "kind": s.kind, "reliability": round(s.reliability or 0.0, 3),
        "successes": s.successes, "failures": s.failures,
        "breaker_state": s.breaker_state,
    } for s in sources]
    rows.sort(key=lambda d: d["reliability"])
    return rows


def calibration_drift(cal_runs) -> list[dict]:
    """Brier / ECE over successive calibration runs — is the engine staying
    calibrated as the dataset and sites change?"""
    return [{
        "id": c.id,
        "created_at": c.created_at.isoformat() if hasattr(c.created_at, "isoformat") else c.created_at,
        "n": c.n, "brier": c.brier, "ece": c.ece,
    } for c in cal_runs]


def quality_metrics(rows, runs, artifacts, contradictions) -> dict:
    """Operational evidence-quality indicators with explicit denominators."""
    total = len(rows)
    quality = [getattr(run, "stats", {}).get("quality", {}) for run in runs]
    attempted = sum(int(item.get("attempted", 0)) for item in quality)
    duplicates = sum(int(item.get("duplicates_collapsed", 0)) for item in quality)
    blocked = sum(int(item.get("blocked", 0)) for item in quality)
    parser_failures = sum(
        row.verdict == "ERROR"
        and row.source in {"phone:web", "profile:enrich"}
        for row in rows
    )
    timeouts = sum(
        row.verdict == "ERROR"
        and "timeout" in " ".join(row.reasons or []).casefold()
        for row in rows
    )
    return {
        "origin_coverage": round(
            sum(bool(getattr(row, "origin", None)) for row in rows) / total, 3
        ) if total else 0.0,
        "extraction_coverage": round(
            sum(bool(getattr(row, "extractions", None)) for row in rows) / total, 3
        ) if total else 0.0,
        "temporal_coverage": round(
            sum(bool(getattr(row, "observed_at", None)) for row in rows) / total, 3
        ) if total else 0.0,
        "partial_observations": sum(
            getattr(row, "completeness", None) == "partial" for row in rows
        ),
        "historical_observations": sum(
            getattr(row, "temporal_status", None) == "historical" for row in rows
        ),
        "contradictions": len(contradictions),
        "contradiction_rate": round(len(contradictions) / total, 3) if total else 0.0,
        "artifact_attempts": attempted,
        "duplicate_collapse_rate": round(duplicates / attempted, 3) if attempted else 0.0,
        "automatic_pivots_blocked": blocked,
        "parser_failure_rate": round(parser_failures / total, 3) if total else 0.0,
        "module_timeout_rate": round(timeouts / total, 3) if total else 0.0,
        "artifacts_recorded": len(artifacts),
    }


def compute(db) -> dict:
    from sqlalchemy import select

    from .store import models_db as m

    with db.session() as s:
        obs = list(s.execute(select(m.Observation)).scalars().all())
        sources = list(s.execute(select(m.Source)).scalars().all())
        cals = list(s.execute(
            select(m.CalibrationRun).order_by(m.CalibrationRun.id)).scalars().all())
        runs = list(s.execute(select(m.Run)).scalars().all())
        artifacts = list(s.execute(select(m.ArtifactNode)).scalars().all())
        contradictions = list(s.execute(
            select(m.ObservationContradiction)
        ).scalars().all())
    return {
        "n_observations": len(obs),
        "confidence_histogram": confidence_histogram(obs),
        "verdict_mix": verdict_mix(obs),
        "top_terms": top_breakdown_terms(obs),
        "independence_coverage": independence_coverage(obs),
        "source_health": source_health(sources),
        "calibration_drift": calibration_drift(cals),
        "quality": quality_metrics(obs, runs, artifacts, contradictions),
    }
