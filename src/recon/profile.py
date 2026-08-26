"""Evidence-backed profile synthesis over a completed investigation graph."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .evidence import confirmation_eligible, confirmation_satisfied
from .graph_models import Artifact
from .identifiers import describe_query
from .models import Finding, Query, Verdict

_DIMENSIONS = {
    "identity": {"name"},
    "accounts": {"username", "profile"},
    "contact": {"email", "phone"},
    "infrastructure": {"domain", "dns", "network", "url"},
    "exposure": {"breach", "reputation"},
}
_DETAIL_GROUPS = {
    "name": "identity",
    "company": "identity",
    "bio": "identity",
    "institutions": "identity",
    "location": "identity",
    "region": "contact",
    "carrier": "contact",
    "line_type": "contact",
    "timezones": "contact",
    "e164": "contact",
    "registrar": "infrastructure",
    "status": "infrastructure",
    "created": "infrastructure",
    "expires": "infrastructure",
    "A": "infrastructure",
    "AAAA": "infrastructure",
    "MX": "infrastructure",
    "NS": "infrastructure",
    "country": "infrastructure",
    "city": "infrastructure",
    "isp": "infrastructure",
    "org": "infrastructure",
    "asn": "infrastructure",
    "prefix": "infrastructure",
    "hostnames": "infrastructure",
    "ports": "infrastructure",
    "breaches": "exposure",
    "abuseConfidenceScore": "exposure",
    "totalReports": "exposure",
    "reputation": "exposure",
    "followers": "accounts",
    "following": "accounts",
    "public_repos": "accounts",
    "blog": "accounts",
}
_IDENTIFIER_ALIASES = {"phone_e164": "phone"}


def _identifier_type(value: str) -> str:
    return _IDENTIFIER_ALIASES.get(value, value)


def _dimension(finding: Finding) -> str:
    if finding.source.startswith("breach:"):
        return "exposure"
    for dimension, categories in _DIMENSIONS.items():
        if finding.category in categories:
            return dimension
    return "infrastructure" if finding.category in {"host", "ip"} else "identity"


def _display(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _display(item) for key, item in list(value.items())[:20]}
    if isinstance(value, (list, tuple, set)):
        return [_display(item) for item in list(value)[:20]]
    return value


def _origin_key(finding: Finding) -> str:
    if finding.origin is not None:
        return finding.origin.independence_key
    return finding.source


def synthesize_profile(
    query: Query,
    findings: list[Finding],
    artifacts: list[Artifact],
    summary: dict[str, Any],
    *,
    intake: dict[str, Any] | None = None,
    stop_reason: str | None = None,
) -> dict[str, Any]:
    """Build a restrained profile: supplied input is not treated as confirmation."""
    observed = [finding for finding in findings if finding.verdict == Verdict.FOUND]
    eligible = [finding for finding in observed if confirmation_eligible(finding)]
    confirmed = [
        finding
        for finding in eligible
        if confirmation_satisfied(finding, findings, query)
    ]
    candidates = [finding for finding in findings if finding.verdict == Verdict.UNCERTAIN]
    clusters = summary.get("clusters") or []
    primary = clusters[0] if clusters else None
    corroboration = (primary or {}).get("corroboration") or {}
    independent = int(corroboration.get("independent_classes") or 0)

    evidence_average = (
        sum(finding.confidence for finding in confirmed) / len(confirmed) if confirmed else 0.0
    )
    corroboration_factor = min(1.0, 0.65 + 0.15 * independent)
    cluster_ceiling = float(
        (primary or {}).get("score") or 1.0
    )
    confidence = round(min(cluster_ceiling, evidence_average * corroboration_factor), 2)

    query_fields = query.normalized().model_dump(exclude_none=True)
    signal_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    signal_origins: dict[tuple[str, str], set[str]] = defaultdict(set)
    signal_findings: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in eligible:
        for key, value in finding.signals.items():
            if value:
                kind = _identifier_type(key.split(":", 1)[0])
                lookup = (kind, str(value).casefold())
                signal_sources[lookup].add(finding.source)
                signal_origins[lookup].add(_origin_key(finding))
                signal_findings[lookup].append(finding)

    identifiers: dict[tuple[str, str], dict[str, Any]] = {}
    for kind, value in query_fields.items():
        identifiers[(kind, str(value).casefold())] = {
            "type": kind,
            "value": value,
            "standing": "provided",
            "confidence": 1.0,
            "sources": ["operator input"],
        }
    for lookup, supporting_findings in signal_findings.items():
        kind, _folded = lookup
        if identifiers.get(lookup, {}).get("standing") == "provided":
            continue
        origins = signal_origins[lookup]
        standing = (
            "confirmed"
            if any(
                confirmation_satisfied(finding, findings, query)
                for finding in supporting_findings
            )
            else "candidate"
        )
        best = max(supporting_findings, key=lambda finding: finding.confidence)
        value = next(
            value
            for key, value in best.signals.items()
            if _identifier_type(key.split(":", 1)[0]) == kind and str(value).casefold() == lookup[1]
        )
        identifiers[lookup] = {
            "type": kind,
            "value": value,
            "standing": standing,
            "confidence": max(finding.confidence for finding in supporting_findings),
            "sources": sorted(signal_sources[lookup]),
            "independent_origins": len(origins),
        }
    for cluster in clusters:
        for key, values in (cluster.get("signals") or {}).items():
            if key.startswith("_"):
                continue
            key = _identifier_type(key)
            for value in values if isinstance(values, list) else [values]:
                lookup = (key, str(value).casefold())
                if lookup in identifiers:
                    continue
                cluster_confirmed = (
                    int((cluster.get("corroboration") or {}).get("independent_classes", 0)) >= 2
                )
                identifiers[lookup] = {
                    "type": key,
                    "value": value,
                    "standing": "confirmed" if cluster_confirmed else "candidate",
                    "confidence": float(
                        cluster.get("score") or 0
                    ),
                    "sources": sorted(
                        signal_sources.get(lookup) or set(cluster.get("sources") or [])
                    ),
                }

    accounts: dict[str, dict[str, Any]] = {}
    for finding in [*eligible, *candidates]:
        if finding.category not in {"username", "profile"}:
            continue
        key = finding.url or f"{finding.source}:{finding.label}"
        standing = (
            "confirmed"
            if confirmation_satisfied(finding, findings, query)
            else "candidate"
        )
        existing = accounts.get(key)
        if existing is None or finding.confidence > existing["confidence"]:
            accounts[key] = {
                "label": finding.label,
                "url": finding.url,
                "source": finding.source,
                "standing": standing,
                "confidence": finding.confidence,
            }

    details: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_details: set[tuple[str, str, str]] = set()
    for finding in observed:
        for name, value in finding.data.items():
            group = _DETAIL_GROUPS.get(name)
            if group is None or value in (None, "", [], {}):
                continue
            marker = (group, name, repr(value))
            if marker in seen_details:
                continue
            seen_details.add(marker)
            details[group].append(
                {
                    "name": name,
                    "value": _display(value),
                    "source": finding.source,
                    "confidence": finding.confidence,
                    "standing": (
                        "confirmed"
                        if confirmation_satisfied(finding, findings, query)
                        else "observed"
                    ),
                }
            )

    dimension_rows = []
    for dimension in _DIMENSIONS:
        rows = [finding for finding in findings if _dimension(finding) == dimension]
        verdicts = Counter(finding.verdict.value for finding in rows)
        confirmed_count = sum(
            confirmation_satisfied(finding, findings, query) for finding in rows
        )
        observed_count = verdicts[Verdict.FOUND.value] - confirmed_count
        if confirmed_count:
            state = "confirmed"
        elif observed_count:
            state = "observed"
        elif verdicts[Verdict.UNCERTAIN.value] or verdicts[Verdict.UNVERIFIABLE.value]:
            state = "inconclusive"
        elif rows:
            state = "checked"
        else:
            state = "not_searched"
        dimension_rows.append(
            {
                "id": dimension,
                "label": dimension.title(),
                "state": state,
                "confirmed": confirmed_count,
                "observed": observed_count,
                "candidates": verdicts[Verdict.UNCERTAIN.value],
                "checks": len(rows),
            }
        )

    gaps: list[str] = []
    states = {row["id"]: row["state"] for row in dimension_rows}
    if states["identity"] != "confirmed":
        gaps.append("No unique identity link was independently corroborated.")
    if states["accounts"] != "confirmed":
        gaps.append("No public account association was corroborated.")
    if states["contact"] != "confirmed":
        gaps.append("No contact association was independently corroborated.")
    if confirmed and independent < 2:
        gaps.append("Identity-supporting evidence has fewer than two independent sources.")
    blocked = sum(finding.verdict in {Verdict.ERROR, Verdict.UNVERIFIABLE} for finding in findings)
    if blocked:
        gaps.append(f"{blocked} source check(s) failed or could not be verified.")
    if stop_reason:
        gaps.append(f"The bounded traversal stopped because {stop_reason}.")

    if confirmed and independent >= 2:
        status = "corroborated"
        assessment = "The profile contains identity evidence corroborated by independent sources."
    elif confirmed:
        status = "partial"
        assessment = (
            "The profile contains identity-supporting evidence, but important links remain uncorroborated."
        )
    else:
        status = "unresolved"
        assessment = (
            "The investigation did not establish a corroborated profile from this starting point."
        )

    title = str((primary or {}).get("label") or next(iter(query_fields.values()), "Profile"))
    primary_identity = None
    if primary:
        primary_identity = {
            "id": primary.get("id"),
            "label": primary.get("label") or title,
            "confidence": primary.get("score") or 0,
            "flags": primary.get("flags") or [],
            "corroboration": corroboration,
            "sources": primary.get("sources") or [],
        }
    from .phone_intel import summarize_phone_research

    phone_research = summarize_phone_research(query, findings)
    return {
        "version": 2,
        "title": title,
        "status": status,
        "confidence": confidence,
        "assessment": assessment,
        "intake": intake or describe_query(query),
        "primary_identity": primary_identity,
        "identifiers": sorted(
            identifiers.values(),
            key=lambda row: (row["standing"] != "confirmed", row["type"], str(row["value"])),
        ),
        "accounts": sorted(
            accounts.values(),
            key=lambda row: (row["standing"] != "confirmed", -row["confidence"], row["label"]),
        )[:50],
        "details": {key: value[:30] for key, value in details.items()},
        "coverage": dimension_rows,
        "gaps": gaps,
        "counts": {
            "confirmed_findings": len(confirmed),
            "observed_findings": len(observed) - len(confirmed),
            "found_findings": len(observed),
            "candidate_findings": len(candidates),
            "artifacts": len(artifacts),
            "identity_clusters": len(clusters),
        },
        "artifact_types": dict(
            sorted(Counter(artifact.type.value for artifact in artifacts).items())
        ),
        "phone_research": phone_research,
        "complete": False,
        "completeness_note": "A public-source profile can show evidence coverage, never prove completeness.",
    }
