"""Corroboration scoring for identity clusters.

An identity backed by several independent FOUND sources and strong shared
signals is more trustworthy than a single weak hit. This score is reported
alongside per-finding verdicts (it does not override them).
"""

from __future__ import annotations

from ..models import Verdict
from ..trust import corroboration as trust_corroboration
from ..trust import independent_classes
from .cluster import Identity


def _score(identity: Identity, by_class: bool) -> float:
    found = [f for f in identity.findings if f.verdict == Verdict.FOUND]
    uncertain = [f for f in identity.findings if f.verdict == Verdict.UNCERTAIN]
    if not found and not uncertain:
        return 0.0

    # Distinct corroboration: source names, or independent classes (shadow).
    sources = {f.source for f in found}
    n_distinct = len(independent_classes(sources)[0]) if by_class else len(sources)
    base = sum(f.confidence for f in found) + 0.3 * sum(f.confidence for f in uncertain)
    breadth = min(0.3, 0.1 * (n_distinct - 1)) if sources else 0.0
    strong_signal_bonus = min(0.2, 0.1 * len(identity.signals))

    raw = base / (len(found) + len(uncertain)) if (found or uncertain) else 0.0
    return round(min(1.0, raw + breadth + strong_signal_bonus), 3)


def score_identity(identity: Identity) -> float:
    return _score(identity, by_class=False)


def score_identity_shadow(identity: Identity) -> float:
    """Independence-weighted score (breadth counted by distinct source classes)."""
    return _score(identity, by_class=True)


def corroboration(identity: Identity) -> dict:
    """Trustworthiness of an identity's corroboration, surfaced live so an analyst
    can see whether a confident score rests on genuinely independent confirmation
    or on several sources that collapse to one independence class. Purely
    explanatory — it does not alter the official `score`. See
    `trust.corroboration` for the shared assessment."""
    found_sources = [f.source for f in identity.findings if f.verdict == Verdict.FOUND]
    return trust_corroboration(found_sources)


def summarize(identities: list[Identity]) -> dict:
    def label(identity: Identity) -> str:
        for key in ("name", "email", "username", "phone_e164", "orcid"):
            values = identity.signals.get(key)
            if values:
                return sorted(values)[0]
        return "identity"

    return {
        "identities": len(identities),
        "clusters": [
            {
                "id": idn.id,
                "label": label(idn),
                "score": score_identity(idn),
                "confidence_shadow": score_identity_shadow(idn),
                "corroboration": corroboration(idn),
                "signals": {k: sorted(v) for k, v in idn.signals.items()},
                "found": sum(1 for f in idn.findings if f.verdict == Verdict.FOUND),
                "uncertain": sum(1 for f in idn.findings if f.verdict == Verdict.UNCERTAIN),
            }
            for idn in sorted(identities, key=lambda i: -score_identity(i))
        ],
    }
