"""Conservative synthesis for phone-number research.

The module distinguishes a numbering-plan fact, a public mention, and a
person-level association. None of those establishes current ownership or
control of a number.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from .evidence import confirmation_eligible
from .models import Finding, Query, Verdict

_LIFECYCLE_PATTERNS = {
    "disconnected": re.compile(r"\b(disconnected|not in service|no longer in service)\b", re.I),
    "former_number": re.compile(r"\b(former|previous|old)\s+(phone\s+)?number\b", re.I),
    "reassigned": re.compile(r"\b(reassigned|recycled|new owner)\b", re.I),
    "number_changed": re.compile(r"\b(number has changed|changed (?:their|the) number)\b", re.I),
}
_DIRECTORY_PATTERN = re.compile(
    r"\b(reverse (?:phone )?lookup|phone directory|telephone directory|phonebook|"
    r"people search|caller id|who called|directory listing)\b",
    re.I,
)
_SERVICE_PATTERN = re.compile(
    r"\b(customer service|support line|help ?line|hotline|switchboard|reception|"
    r"appointments?|sales line|fax|toll[- ]?free)\b",
    re.I,
)
_ORGANIZATION_PATTERN = re.compile(
    r"\b(contact us|opening hours|head office|registered office|business enquiries|company)\b",
    re.I,
)
_PERSON_PATTERN = re.compile(r"\b(mobile|personal phone|call me|text me|reach me)\b", re.I)
_ORGANIZATION_TYPES = {
    "organization",
    "localbusiness",
    "corporation",
    "governmentorganization",
    "educationalorganization",
}


def _host(value: str | None) -> str:
    return (urlsplit(value or "").hostname or "").casefold().removeprefix("www.")


def _same_site(left: str, right: str) -> bool:
    return bool(
        left
        and right
        and (left == right or left.endswith(f".{right}") or right.endswith(f".{left}"))
    )


def classify_phone_mention(
    context: str,
    structured: dict[str, Any] | None = None,
    *,
    page_title: str = "",
    page_url: str = "",
) -> dict[str, Any]:
    """Classify explicit page context while preserving uncertainty by default."""
    text = " ".join(part for part in (page_title, context) if part)
    record = structured or {}
    types = {str(value).casefold() for value in record.get("types", [])}
    lifecycle = [name for name, pattern in _LIFECYCLE_PATTERNS.items() if pattern.search(text)]

    directory = bool(_DIRECTORY_PATTERN.search(text))
    service = bool(_SERVICE_PATTERN.search(text))
    if "person" in types or "profilepage" in types:
        role = "person"
    elif service:
        role = "service"
    elif types & _ORGANIZATION_TYPES:
        role = "organization"
    elif _ORGANIZATION_PATTERN.search(text):
        role = "organization"
    elif _PERSON_PATTERN.search(text):
        role = "person"
    else:
        role = "unknown"

    page_host = _host(page_url)
    record_hosts = {_host(value) for value in record.get("urls", []) if _host(value)}
    first_party_record = bool(
        role == "person"
        and page_host
        and (not record_hosts or any(_same_site(page_host, host) for host in record_hosts))
    )
    if directory:
        source_kind = "directory"
    elif role == "service":
        source_kind = "service"
    elif role == "organization":
        source_kind = "organization"
    elif first_party_record:
        source_kind = "person_profile"
    elif role == "person" and record:
        source_kind = "person_record"
    else:
        source_kind = "public_page"

    historical = bool(lifecycle)
    identity_record = bool(record.get("identity_record")) or bool(types & {"person", "profilepage"})
    identity_candidate = bool(
        identity_record
        and role == "person"
        and not historical
        and source_kind not in {"directory", "service", "organization"}
    )
    if historical:
        association = "historical"
    elif source_kind == "directory":
        association = "directory_listing"
    elif role == "service":
        association = "service_contact"
    elif role == "organization":
        association = "organization_contact"
    elif identity_candidate:
        association = "person_record"
    elif role == "person":
        association = "personal_mention"
    else:
        association = "unresolved_mention"

    return {
        "role": role,
        "source_kind": source_kind,
        "association": association,
        "lifecycle_markers": lifecycle,
        "historical": historical,
        "identity_candidate": identity_candidate,
        "pivot_eligible": identity_candidate,
        "independence_group": "phone-directory" if directory else None,
    }


def _origin_key(finding: Finding) -> str:
    if finding.origin is not None:
        return finding.origin.independence_key
    return _host(finding.url) or finding.source


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
    identity_values: dict[tuple[str, str], str] = {}
    observed_values: dict[str, set[str]] = defaultdict(set)
    lifecycle: set[str] = set()
    associations: defaultdict[str, int] = defaultdict(int)
    for finding in mentions:
        data = finding.data or {}
        structured = data.get("structured") or {}
        origin_key = _origin_key(finding)
        historical = bool(data.get("lifecycle_markers")) or (
            finding.temporal.status.value == "historical"
        )
        identity_candidate = bool(
            data.get("identity_candidate", False)
            or (
                data.get("mention_role") == "person"
                and {str(item).casefold() for item in structured.get("types", [])}
                & {"person", "profilepage"}
                and not historical
            )
        )
        identity_candidate = identity_candidate and confirmation_eligible(finding)
        for kind in ("name", "email"):
            value = structured.get(kind)
            if not value:
                continue
            folded = str(value).casefold()
            observed_values[kind].add(folded)
            identity_values[(kind, folded)] = str(value)
            if identity_candidate:
                identity_origins[(kind, folded)].add(origin_key)
        lifecycle.update(data.get("lifecycle_markers") or [])
        association = data.get("association") or (
            "historical" if historical else "unresolved_mention"
        )
        associations[str(association)] += 1
        rows.append(
            {
                "url": finding.url,
                "title": data.get("page_title") or finding.label,
                "domain": data.get("domain") or _host(finding.url),
                "role": data.get("mention_role") or "unknown",
                "source_kind": data.get("source_kind") or "public_page",
                "association": association,
                "context": data.get("context") or "",
                "temporal_status": finding.temporal.status.value,
                "confidence": finding.confidence,
                "origin": origin_key,
                "identity_candidate": identity_candidate,
                "structured_identity": {
                    key: structured.get(key)
                    for key in ("name", "email", "urls")
                    if structured.get(key)
                },
            }
        )

    identities = [
        {
            "type": kind,
            "value": identity_values[(kind, folded)],
            "standing": (
                "corroborated"
                if kind != "name" and len(origins) >= 2
                else "candidate"
            ),
            "independent_origins": len(origins),
        }
        for (kind, folded), origins in identity_origins.items()
    ]

    conflicts: list[str] = []
    if len(observed_values["name"]) > 1:
        conflicts.append(
            "Different names appear across public mentions; number reuse, shared use, or stale pages must be reviewed."
        )
    if len(observed_values["email"]) > 1:
        conflicts.append(
            "Different email addresses appear across public mentions; do not assume they belong to one person."
        )
    if lifecycle & {"reassigned", "former_number", "number_changed"} or conflicts:
        lifecycle_state = "possible_reuse"
    elif mentions and associations["historical"] == len(mentions):
        lifecycle_state = "historical_mentions"
    elif any(item["standing"] == "corroborated" for item in identities):
        lifecycle_state = "corroborated_person_association"
    elif identities:
        lifecycle_state = "person_association_candidate"
    elif associations["organization_contact"] or associations["service_contact"]:
        lifecycle_state = "shared_or_service_number"
    elif mentions:
        lifecycle_state = "public_mentions"
    elif checks and not unavailable:
        lifecycle_state = "not_observed_in_bounded_check"
    else:
        lifecycle_state = "unresolved"

    corroborated = [item for item in identities if item["standing"] == "corroborated"]
    if conflicts:
        decision = {
            "status": "manual_review",
            "can_expand_automatically": False,
            "recommended_action": "Review conflicting and historical mentions before following identity leads.",
        }
    elif corroborated:
        decision = {
            "status": "corroborated_identity_lead",
            "can_expand_automatically": True,
            "recommended_action": "Continue with the corroborated email or account leads under the current limits.",
        }
    elif identities:
        decision = {
            "status": "needs_corroboration",
            "can_expand_automatically": False,
            "recommended_action": "Keep the person-level values as candidates until another independent page agrees.",
        }
    elif mentions:
        decision = {
            "status": "mention_without_identity_link",
            "can_expand_automatically": False,
            "recommended_action": "Stop automatic identity expansion; retain the pages as contextual evidence only.",
        }
    elif unavailable:
        decision = {
            "status": "coverage_incomplete",
            "can_expand_automatically": False,
            "recommended_action": "Retry unavailable sources later without treating the gap as a negative result.",
        }
    else:
        decision = {
            "status": "bounded_check_complete",
            "can_expand_automatically": False,
            "recommended_action": "Stop the phone-only path unless another verified identifier is available.",
        }

    return {
        "version": 2,
        "number": metadata.get("e164") or query.phone,
        "allocation": {
            key: metadata.get(key)
            for key in (
                "country",
                "region",
                "region_code",
                "carrier",
                "line_type",
                "timezones",
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
            identities,
            key=lambda item: (item["standing"] != "corroborated", item["type"], item["value"]),
        ),
        "decision": decision,
        "coverage": {
            "direct_mentions": len(mentions),
            "independent_origins": len({row["origin"] for row in rows}),
            "unavailable_checks": unavailable,
            "association_types": dict(sorted(associations.items())),
            "bounded": True,
        },
        "ownership_established": False,
        "ownership_note": (
            "Public pages can corroborate an association. Current ownership or control requires "
            "independent, authorized verification outside this passive scan."
        ),
    }
