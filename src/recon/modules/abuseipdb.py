"""AbuseIPDB module (keyed): IP_ADDRESS -> abuse-confidence score.

Requires an `abuseipdb` key in the vault; skipped entirely when absent."""

from __future__ import annotations

from ..graph_models import Artifact, ArtifactType
from ..keys import VAULT
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    key = VAULT.get("abuseipdb")
    if not key:
        return
    resp = await ctx.client.fetch(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": art.normalized, "maxAgeInDays": "90"},
        headers={"Key": key, "Accept": "application/json"})
    if resp.status_code != 200:
        await ctx.emit_finding(Finding(
            source="abuseipdb", category="reputation", label=f"AbuseIPDB {art.normalized}",
            verdict=Verdict.UNVERIFIABLE, reasons=[f"AbuseIPDB API status {resp.status_code}"]))
        return

    d = resp.json().get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    await ctx.emit_finding(Finding(
        source="abuseipdb", category="reputation", label=f"AbuseIPDB {art.normalized}",
        url=None, verdict=Verdict.FOUND, confidence=0.85,
        reasons=[f"abuse confidence {score}% over {d.get('totalReports', 0)} report(s)"],
        data={k: d.get(k) for k in ("abuseConfidenceScore", "totalReports",
                                    "countryCode", "isp", "domain", "usageType")},
    ))


MODULE = Module(
    name="abuseipdb",
    consumes={ArtifactType.IP_ADDRESS},
    produces=set(),
    run=_run,
    reliability_prior=0.85,
    requires_keys=["abuseipdb"],
)
