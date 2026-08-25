"""Conservative synthesis for phone-number research.

The module describes what public pages say about a number without claiming that
an allocation record or a web mention identifies its current subscriber.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from .models import Finding, Query, Verdict

_LIFECYCLE_PATTERNS = {
    "disconnected": re.compile(r"\b(disconnected|not in service|no longer in service)\b", re.I),
    "former_number": re.compile(r"\b(former|previous|old)\s+(phone\s+)?number\b", re.I),
    "reassigned": re.compile(r"\b(reassigned|recycled|new owner)\b", re.I),
    "number_changed": re.compile(r"\b(number has changed|changed (?:their|the) number)\b", re.I),
}
_ROLE_PATTERNS = {
    "organization": re.compile(
        r"\b(contact us|customer service|support line|opening hours|head office|business)\b",
        re.I,
    ),
    "directory": re.compile(r"\b(phone directory|reverse lookup|telephone directory)\b", re.I),
    "person": re.compile(r"\b(mobile|personal phone|call me|text me)\b", re.I),
}


def classify_phone_mention(
    context: str,
    structured: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify only explicit page context; ``unknown`` is the safe default."""
    text = context or ""
    types = {str(value).casefold() for value in (structured or {}).get("types", [])}
    if "person" in types:
        role = "person"
    elif types & {"organization", "localbusiness", "corporation"}:
        role = "organization"
    else:
        role = next(
            (name for name, pattern in _ROLE_PATTERNS.items() if pattern.search(text)),
            "unknown",
        )
    lifecycle = [
        name for name, pattern in _LIFECYCLE_PATTERNS.items() if pattern.search(text)
    ]
    return {
        "role": role,
        "lifecycle_markers": lifecycle,
        "historical": bool(lifecycle),
    }


def summarize_phone_research(query: Query, findings: list[Finding]) -> dict[str, Any] | None:
    if not query.phone:
        return None
    metadata = next(
        (
            dict(finding.data)
            for finding in findings
            if finding.source == "phone:validate" and finding.verdict == Verdict.FOUND
        ),
        {},
    )
    checks = [finding for finding in findings if finding.source == "phone:web"]
    mentions = [finding for finding in checks if finding.verdict == Verdict.FOUND]
    unavailable = sum(
        finding.verdict in {Verdict.UNVERIFIABLE, Verdict.ERROR} for finding in checks
    )

    rows: list[dict[str, Any]] = []
    identity_origins: dict[tuple[str, str], set[str]] = defaultdict(set)
    lifecycle: set[str] = set()
    for finding in mentions:
        data = finding.data or {}
        structured = data.get("structured") or {}
        origin_key = (
            finding.origin.independence_key
            if finding.origin is not None
            else (urlsplit(finding.url or "").hostname or finding.source)
        )
        for kind in ("name", "email"):
            value = structured.get(kind)
            if value:
                identity_origins[(kind, str(value).casefold())].add(origin_key)
        lifecycle.update(data.get("lifecycle_markers") or [])
        rows.append({
            "url": finding.url,
            "title": data.get("page_title") or finding.label,
            "domain": data.get("domain") or urlsplit(finding.url or "").hostname,
            "role": data.get("mention_role") or "unknown",
            "context": data.get("context") or "",
            "temporal_status": finding.temporal.status.value,
            "confidence": finding.confidence,
            "origin": origin_key,
            "structured_identity": {
                key: structured.get(key) for key in ("name", "email", "urls")
                if structured.get(key)
            },
        })

    identities = []
    for (kind, folded), origins in identity_origins.items():
        value = next(
            str((row.get("structured_identity") or {}).get(kind))
            for row in rows
            if str((row.get("structured_identity") or {}).get(kind, "")).casefold() == folded
        )
        identities.append({
            "type": kind,
            "value": value,
            "standing": "corroborated" if len(origins) >= 2 else "candidate",
            "independent_origins": len(origins),
        })

    distinct_names = {item[1] for item in identity_origins if item[0] == "name"}
    conflicts = []
    if len(distinct_names) > 1:
        conflicts.append(
            "Different identity names appear across public mentions; number reuse or stale pages must be reviewed."
        )
    if lifecycle & {"reassigned", "former_number", "number_changed"}:
        lifecycle_state = "possible_reuse"
    elif lifecycle:
        lifecycle_state = "historical_mentions"
    elif mentions:
        lifecycle_state = "public_mentions"
    elif checks and not unavailable:
        lifecycle_state = "not_observed_in_bounded_check"
    else:
        lifecycle_state = "unresolved"

    return {
        "version": 1,
        "number": metadata.get("e164") or query.phone,
        "allocation": {
            key: metadata.get(key)
            for key in (
                "country", "region", "region_code", "carrier", "line_type", "timezones",
                "number_portability_supported",
            )
            if metadata.get(key) not in (None, "", [])
        },
        "allocation_note": (
            "Allocation metadata describes the numbering plan and may be stale after portability; "
            "it does not identify the current subscriber."
        ),
        "lifecycle": {
            "state": lifecycle_state,
            "markers": sorted(lifecycle),
            "conflicts": conflicts,
        },
        "mentions": rows,
        "identity_links": sorted(
            identities, key=lambda item: (item["standing"] != "corroborated", item["type"])
        ),
        "coverage": {
            "direct_mentions": len(mentions),
            "independent_origins": len({row["origin"] for row in rows}),
            "unavailable_checks": unavailable,
            "bounded": True,
        },
        "ownership_established": False,
        "ownership_note": (
            "A matching public page establishes a mention. Current ownership or control requires "
            "independent, authorized verification."
        ),
    }
