"""Corroboration scoring for identity clusters.

An identity backed by several independent FOUND sources and strong shared
signals is more trustworthy than a single weak hit. This score is reported
alongside per-finding verdicts (it does not override them).
"""

from __future__ import annotations

from ..config import SETTINGS
from ..evidence import confirmation_satisfied
from ..models import Verdict
from ..trust import corroboration as trust_corroboration
from ..trust import independent_classes
from .cluster import Identity


def _score(identity: Identity, by_class: bool) -> float:
    found = [
        finding
        for finding in identity.findings
        if confirmation_satisfied(finding, identity.findings)
    ]
    if not found:
        return 0.0

    # Distinct corroboration: source names, or independent classes (shadow).
    sources = {f.source for f in found}
    n_distinct = len(independent_classes(found)[0]) if by_class else len(sources)
    base = sum(f.confidence for f in found)
    breadth = min(0.3, 0.1 * (n_distinct - 1)) if sources else 0.0
    raw = base / len(found)
    scored = min(1.0, raw + breadth - 0.15 * len(identity.flags))
    classes = independent_classes(found)[0]
    if len(classes) < 2:
        scored = min(scored, SETTINGS.identity_single_origin_cap)
    return round(max(0.0, scored), 3)


def score_identity(identity: Identity) -> float:
    return _score(identity, by_class=SETTINGS.confidence_independence)


def score_identity_shadow(identity: Identity) -> float:
    """Independence-weighted score (breadth counted by distinct source classes)."""
    return _score(identity, by_class=not SETTINGS.confidence_independence)


def corroboration(identity: Identity) -> dict:
    """Trustworthiness of an identity's corroboration, surfaced live so an analyst
    can see whether a confident score rests on genuinely independent confirmation
    or on several sources that collapse to one independence class. Purely
    explanatory — it does not alter the official `score`. See
    `trust.corroboration` for the shared assessment."""
    found = [
        finding
        for finding in identity.findings
        if confirmation_satisfied(finding, identity.findings)
    ]
    return trust_corroboration(found)


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
                "sources": sorted({f.source for f in idn.findings}),
                "flags": list(idn.flags),
                "found": sum(
                    confirmation_satisfied(f, idn.findings) for f in idn.findings
                ),
                "uncertain": sum(1 for f in idn.findings if f.verdict == Verdict.UNCERTAIN),
            }
            for idn in sorted(identities, key=lambda i: -score_identity(i))
        ],
    }
