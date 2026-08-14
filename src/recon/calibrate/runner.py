"""Run calibration: turn ground-truth labels into (confidence, outcome) samples
via the live verify engine, then compute metrics.

The evaluator is injectable so the whole thing is offline-testable (the metrics
are pure; only the evaluator touches the network). The default evaluator runs a
single (account, site) through the real verify pipeline — the same code path a
normal scan uses — so calibration measures the engine as it actually behaves.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

from ..config import SETTINGS, Settings
from ..models import Verdict
from . import labels as labels_mod
from . import metrics
from .metrics import Sample

# (account, site, settings) -> predicted P(present), or None to skip (e.g. the
# response was UNVERIFIABLE/ERROR — not evidence either way).
Evaluator = Callable[[str, str, Settings], Awaitable[Optional[float]]]


async def _live_samples(rows: list[dict], settings: Settings) -> list[Sample]:
    from ..collectors.username import _check_site, load_sites
    from ..http_client import RateLimitedClient
    from ..verify.baseline import BaselineCache

    rules = {r.name: r for r in load_sites(settings=settings)}
    samples: list[Sample] = []
    async with RateLimitedClient(settings) as client:
        baselines = BaselineCache(client)
        for row in rows:
            rule = rules.get(row["site"])
            if rule is None:
                continue
            f = await _check_site(rule, row["account"], client, baselines)
            if f.verdict in (Verdict.UNVERIFIABLE, Verdict.ERROR):
                continue
            samples.append(Sample(f.confidence, bool(row["present"]),
                                  source=f"username:{row['site']}", category="username"))
    return samples


async def _evaluator_samples(rows: list[dict], evaluator: Evaluator,
                             settings: Settings) -> list[Sample]:
    samples: list[Sample] = []
    for row in rows:
        conf = await evaluator(row["account"], row["site"], settings)
        if conf is None:
            continue
        samples.append(Sample(conf, bool(row["present"]),
                              source=f"username:{row['site']}", category="username"))
    return samples


async def run_calibration(evaluator: Evaluator | None = None, settings: Settings = SETTINGS,
                          labels: list[dict] | None = None, n_bins: int = 10) -> dict:
    """Produce a calibration report over the labeled set. With `evaluator=None`
    the live verify engine is used; inject one for offline/deterministic runs."""
    rows = [r for r in (labels if labels is not None else labels_mod.load_labels())
            if r.get("category", "username") == "username"]
    if evaluator is None:
        samples = await _live_samples(rows, settings)
    else:
        samples = await _evaluator_samples(rows, evaluator, settings)

    report = metrics.summary(samples, settings.found_confidence,
                             settings.uncertain_confidence, n_bins)
    report["found_threshold"] = settings.found_confidence
    report["uncertain_threshold"] = settings.uncertain_confidence
    return report


def independence_impact(db) -> dict:
    """Advisory for the source-independence flip: over persisted entities, how
    many would change confidence under the independence (shadow) weighting, and by
    how much. Lets a human decide whether to set `confidence_independence`."""
    from sqlalchemy import select

    from ..store import models_db as m

    with db.session() as s:
        ents = list(s.execute(select(m.Entity)).scalars().all())
    deltas = []
    for e in ents:
        bd = e.breakdown or {}
        total, shadow = bd.get("total"), bd.get("shadow_total")
        if total is not None and shadow is not None and shadow != total:
            deltas.append(abs(round(total - shadow, 3)))
    return {
        "entities": len(ents),
        "entities_changed": len(deltas),
        "mean_abs_delta": round(sum(deltas) / len(deltas), 3) if deltas else 0.0,
        "max_abs_delta": max(deltas) if deltas else 0.0,
    }
