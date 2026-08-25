"""Confidence propagation for a resolved identity.

Confidence rises with independent corroboration (distinct sources) weighted by
each source's reliability, and falls when coherence flags contradictions.

Phase 5a makes the result a `ScoreBreakdown` (auditable term by term) and adds a
*shadow* score under source-independence weighting: the breadth bonus counted by
distinct independence *classes* rather than distinct source names, so three
RIR-derived "confirmations" don't masquerade as three independent ones. The
shadow value is displayed but not applied to the official `total` until
`Settings.confidence_independence` is flipped on (after calibration).
"""

from __future__ import annotations

from ..config import SETTINGS
from ..explain import ScoreBreakdown
from ..store import models_db as m
from ..trust import independent_classes

_BREADTH_PER = 0.08
_BREADTH_CAP = 0.25
_FLAG_PENALTY = 0.15


def _breadth(n_distinct: int) -> float:
    return min(_BREADTH_CAP, _BREADTH_PER * max(0, n_distinct - 1))


def entity_confidence(observations: list[m.Observation], flags: list[str],
                      settings=SETTINGS) -> ScoreBreakdown:
    """Auditable identity confidence. `total` is the official score; `shadow_total`
    is the independence-weighted alternative."""
    bd = ScoreBreakdown(base=0.0)
    hits = [o for o in observations if o.verdict in ("FOUND", "UNCERTAIN")]
    if not hits:
        return bd.finalize()

    # Reliability-weighted average per-observation confidence.
    num = sum(o.confidence * (o.reliability or 0.5) for o in hits)
    den = sum(o.reliability or 0.5 for o in hits)
    bd.base = round(num / den if den else 0.0, 3)
    dimension_names = (
        "match_quality", "source_reliability", "recency", "independence",
        "transformation_certainty", "completeness",
    )
    for name in dimension_names:
        values = [
            float(getattr(o, "confidence_dimensions", {})[name])
            for o in hits
            if getattr(o, "confidence_dimensions", None)
            and name in getattr(o, "confidence_dimensions", {})
        ]
        if values:
            bd.dimensions[name] = round(sum(values) / len(values), 3)

    found_observations = [o for o in hits if o.verdict == "FOUND"]
    found_sources = [o.source for o in found_observations]
    name_distinct = len(set(found_sources))
    classes, redundant = independent_classes(found_observations)

    name_breadth = _breadth(name_distinct)
    class_breadth = _breadth(len(classes))

    use_classes = settings.confidence_independence
    breadth = class_breadth if use_classes else name_breadth
    basis = (f"{len(classes)} independent source class(es)" if use_classes
             else f"{name_distinct} distinct FOUND source(s)")
    bd.add("breadth", breadth, f"corroboration breadth — {basis}", layer="entity")

    for flag in flags:
        bd.add(f"flag:{flag}", -_FLAG_PENALTY, f"coherence flag: {flag}", layer="entity")

    bd.finalize()

    # Shadow: the *other* breadth weighting (always the independence-aware one
    # when the official score is still name-based), so the UI can show the delta.
    shadow_breadth = name_breadth if use_classes else class_breadth
    shadow = max(0.0, min(1.0, bd.base + shadow_breadth - _FLAG_PENALTY * len(flags)))
    bd.shadow_total = round(shadow, 3)
    note = f"{len(classes)} independent class(es) vs {name_distinct} source name(s)"
    if redundant:
        note += "; redundant: " + ", ".join(f"{s}→{c}" for s, c in redundant)
    bd.shadow_note = note
    return bd
