"""Declared source contracts and opt-in live canary checks.

Contracts are review metadata, not marketing copy: they disclose the data a
module sends and the kind of evidence it returns. Live checks consume only
operator-designated canary artifacts from an external JSON file; the package
does not ship identities that silently generate scheduled traffic.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import SETTINGS, Settings
from .graph_models import Artifact, ArtifactType
from .http_client import RateLimitedClient
from .keys import VAULT, redact
from .models import Finding, Query, Verdict
from .modules.base import ModuleContext
from .modules.registry import MODULES

Interaction = Literal[
    "offline", "dns", "public-api", "public-page", "external-tool", "mixed"
]


@dataclass(frozen=True)
class SourceContract:
    module: str
    operator: str
    interaction: Interaction
    evidence: str
    data_sent: tuple[str, ...]
    rate_policy: str
    terms_scope: str
    reviewed_on: str = "2026-08-13"

    def as_dict(self) -> dict:
        payload = dataclasses.asdict(self)
        payload["origin_identity"] = self.operator
        payload["evidence_class"] = {
            "offline": "offline",
            "external-tool": "external_tool",
            "mixed": "aggregated",
        }.get(self.interaction, "direct")
        return payload


def _c(module, operator, interaction, evidence, data_sent, rate_policy, terms_scope):
    return SourceContract(
        module=module,
        operator=operator,
        interaction=interaction,
        evidence=evidence,
        data_sent=tuple(data_sent),
        rate_policy=rate_policy,
        terms_scope=terms_scope,
    )


CONTRACTS = {
    c.module: c
    for c in [
        _c("username", "configured site operators", "public-page", "profile existence",
           ["username", "random control username"], "shared per-host limiter",
           "Each configured site's terms and robots policy apply."),
        _c("maigret", "Maigret and selected site operators", "external-tool",
           "candidate username-profile responses; never identity confirmation", ["username"],
           "disabled by default; 25 sites, four connections, eight-second site timeout, "
           "120-second process timeout; external requests are not in the Specter HTTP budget",
           "Maigret's license and each selected site's terms and robots policy apply."),
        _c("email", "Automattic and DNS operators", "mixed", "avatar and MX records",
           ["MD5 email identifier", "email domain"], "shared HTTP limiter; DNS resolver policy",
           "Gravatar public avatar protocol and DNS operator terms apply."),
        _c("phone", "none", "offline", "number structure and carrier metadata", [],
           "no network traffic", "Local libphonenumber data only."),
        _c("phone_web", "DuckDuckGo and discovered public-page operators", "public-page",
           "direct public-page phone mentions and same-record structured identity fields",
           ["exact phone-format queries", "discovered public page URLs"],
           "three sequential searches and at most six direct pages; shared per-host limiter",
           "DuckDuckGo and each discovered site's terms and robots policy apply."),
        _c("name", "ORCID and OpenAlex", "public-api", "scholarly author records", ["name"],
           "shared per-host limiter", "ORCID and OpenAlex API policies apply."),
        _c("domain", "DNS, RDAP, and crt.sh operators", "mixed",
           "DNS, registration, and certificate records", ["domain"],
           "shared HTTP limiter; DNS resolver policy", "Each upstream service policy applies."),
        _c("resolve", "configured DNS resolver", "dns", "address records", ["hostname"],
           "DNS resolver policy", "Configured resolver terms apply."),
        _c("asn", "Team Cymru and DNS operators", "dns", "ASN and reverse DNS records",
           ["IP address"], "DNS resolver policy", "Team Cymru and resolver terms apply."),
        _c("profile_links", "profile site operator", "public-page", "public outbound links",
           ["observed profile URL"], "shared per-host limiter",
           "The profile site's terms and robots policy apply."),
        _c("wayback", "Internet Archive", "public-api", "archived URL index", ["domain"],
           "shared per-host limiter", "Internet Archive CDX API terms apply."),
        _c("ripestat", "RIPE NCC", "public-api", "RIR and routing records", ["IP or ASN"],
           "shared per-host limiter", "RIPEstat Data API terms apply."),
        _c("ip_geo", "ip-api.com", "public-api", "network geolocation", ["IP address"],
           "shared per-host limiter", "ip-api.com usage terms apply; free endpoint is HTTP."),
        _c("dns_intel", "configured DNS resolver", "dns", "mail and DNS security records",
           ["domain"], "DNS resolver policy", "Configured resolver terms apply."),
        _c("commoncrawl", "Common Crawl", "public-api", "crawl index records", ["domain"],
           "shared per-host limiter", "Common Crawl index terms apply."),
        _c("github", "GitHub", "public-api", "public account and event metadata", ["username"],
           "shared per-host limiter; provider quota", "GitHub API terms apply."),
        _c("breach", "XposedOrNot or Have I Been Pwned", "public-api",
           "breach corpus membership", ["email address"],
           "shared per-host limiter; provider quota", "Selected provider API terms apply."),
        _c("permute", "Automattic", "public-api", "avatar existence for candidates",
           ["MD5 candidate-email identifier"], "shared per-host limiter",
           "Gravatar public avatar protocol applies."),
        _c("shodan", "Shodan", "public-api", "host service observations", ["IP", "API key"],
           "shared per-host limiter; provider quota", "Shodan API terms apply."),
        _c("virustotal", "VirusTotal", "public-api", "reputation observations",
           ["domain or IP", "API key"], "shared per-host limiter; provider quota",
           "VirusTotal API terms apply."),
        _c("abuseipdb", "AbuseIPDB", "public-api", "abuse reports", ["IP", "API key"],
           "shared per-host limiter; provider quota", "AbuseIPDB API terms apply."),
        _c("gitlab", "GitLab", "public-api", "public account metadata", ["username"],
           "shared per-host limiter; provider quota", "GitLab API terms apply."),
        _c("bluesky", "Bluesky", "public-api", "public profile metadata", ["actor handle"],
           "shared per-host limiter; provider quota", "Bluesky API terms apply."),
        _c("hackernews", "Y Combinator and Firebase", "public-api", "public user metadata",
           ["username"], "shared per-host limiter", "Hacker News API terms apply."),
        _c("wikidata", "Wikimedia Foundation", "public-api", "entity label candidates", ["name"],
           "shared per-host limiter; limit five", "Wikimedia API etiquette and terms apply."),
    ]
}


def validate_contracts() -> list[str]:
    module_names = {module.name for module in MODULES}
    contract_names = set(CONTRACTS)
    errors = [f"missing source contract: {name}" for name in sorted(module_names - contract_names)]
    errors.extend(f"orphan source contract: {name}" for name in sorted(contract_names - module_names))
    for name, contract in CONTRACTS.items():
        if not contract.operator or not contract.evidence or not contract.terms_scope:
            errors.append(f"incomplete source contract: {name}")
    for module in MODULES:
        execution = module.execution_contract
        if execution["version"] != 1 or module.estimated_request_cost < 1:
            errors.append(f"invalid module execution contract: {module.name}")
        if not module.consumes:
            errors.append(f"module consumes no artifact type: {module.name}")
    return errors


class CanaryArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArtifactType
    value: str = Field(min_length=1, max_length=500)


class CanaryExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_prefix: str = Field(min_length=1, max_length=120)
    verdicts: set[Verdict] = Field(default_factory=lambda: {Verdict.FOUND})
    minimum: int = Field(default=1, ge=1, le=100)


class Canary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    module: str = Field(min_length=1, max_length=120)
    artifact: CanaryArtifact
    query: Query = Field(default_factory=Query)
    expect: CanaryExpectation
    max_requests: int = Field(default=10, ge=1, le=100)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)


def load_canaries(path: str | Path) -> list[Canary]:
    candidate = Path(path).expanduser()
    if candidate.stat().st_size > 1_000_000:
        raise ValueError("canary file is too large")
    payload = json.loads(candidate.read_text(encoding="utf-8"))
    rows = payload.get("canaries") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("canary file must contain a 'canaries' list")
    canaries = [Canary.model_validate(row) for row in rows]
    names = [canary.name for canary in canaries]
    if len(names) != len(set(names)):
        raise ValueError("canary names must be unique")
    return canaries


async def _run_canary(canary: Canary, settings: Settings) -> dict:
    module = next((item for item in MODULES if item.name == canary.module), None)
    if module is None:
        return {"name": canary.name, "module": canary.module, "status": "error",
                "detail": {"error": "unknown module"}, "duration_ms": 0, "requests": 0}
    if not module.enabled:
        return {"name": canary.name, "module": canary.module, "status": "skipped",
                "detail": {"reason": "module is disabled"}, "duration_ms": 0, "requests": 0}
    if module.expansion and not settings.expansion_requested:
        return {"name": canary.name, "module": canary.module, "status": "skipped",
                "detail": {"reason": "expansion mode is disabled"},
                "duration_ms": 0, "requests": 0}
    if canary.artifact.type not in module.consumes:
        return {"name": canary.name, "module": canary.module, "status": "error",
                "detail": {"error": "artifact type is not consumed by module"},
                "duration_ms": 0, "requests": 0}
    if module.requires_keys and not VAULT.has_all(module.requires_keys):
        return {"name": canary.name, "module": canary.module, "status": "skipped",
                "detail": {"reason": "required key is not configured"},
                "duration_ms": 0, "requests": 0}

    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    artifact = Artifact.make(canary.artifact.type, canary.artifact.value)
    canary_settings = dataclasses.replace(
        settings,
        max_requests=canary.max_requests,
        max_concurrency=1,
        deterministic=True,
    )
    started = time.monotonic()
    request_count = 0
    try:
        async def emit_finding(finding: Finding) -> None:
            findings.append(finding)

        async def emit_artifact(discovered: Artifact) -> None:
            artifacts.append(discovered)

        async with RateLimitedClient(canary_settings) as client:
            context = ModuleContext(
                client=client,
                query=canary.query.normalized(),
                settings=canary_settings,
                in_scope=lambda _artifact: True,
                _emit_finding=emit_finding,
                _emit_artifact=emit_artifact,
            )
            await asyncio.wait_for(
                module.run(artifact, context), timeout=canary.timeout_seconds
            )
            request_count = client.request_count
        matches = [
            finding for finding in findings
            if finding.source.startswith(canary.expect.source_prefix)
            and finding.verdict in canary.expect.verdicts
        ]
        status = "passed" if len(matches) >= canary.expect.minimum else "failed"
        detail = {
            "matching_findings": len(matches),
            "total_findings": len(findings),
            "verdicts": sorted({finding.verdict.value for finding in findings}),
            "artifacts": len(artifacts),
        }
    except Exception as exc:  # noqa: BLE001 - health result, not scan failure
        status = "error"
        error = redact(str(exc)).replace(canary.artifact.value, "[CANARY]")
        detail = {"error": error[:500]}
    return {
        "name": canary.name,
        "module": canary.module,
        "status": status,
        "detail": detail,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "requests": request_count,
    }


async def run_canaries(
    canaries: list[Canary], settings: Settings = SETTINGS, *, persist: bool = True
) -> list[dict]:
    results = []
    for canary in canaries:
        result = await _run_canary(canary, settings)
        results.append(result)
        if persist:
            from .store import get_db, repo

            with get_db().session() as session:
                repo.save_source_health_check(session, result)
    return results
