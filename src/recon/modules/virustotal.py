"""VirusTotal module (keyed): DOMAIN / IP_ADDRESS -> reputation + resolutions.

Requires a `virustotal` key in the vault; skipped entirely when absent."""

from __future__ import annotations

from ..graph_models import Artifact, ArtifactType
from ..keys import VAULT
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_API = "https://www.virustotal.com/api/v3"


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    key = VAULT.get("virustotal")
    if not key:
        return
    path = (f"/ip_addresses/{art.normalized}" if art.type == ArtifactType.IP_ADDRESS
            else f"/domains/{art.normalized}")
    resp = await ctx.client.fetch(
        f"{_API}{path}", headers={"x-apikey": key, "User-Agent": ctx.settings.user_agent})
    if resp.status_code != 200:
        await ctx.emit_finding(Finding(
            source="virustotal", category="reputation", label=f"VT {art.normalized}",
            verdict=Verdict.UNVERIFIABLE if resp.status_code != 404 else Verdict.NOT_FOUND,
            reasons=[f"VT API status {resp.status_code}"]))
        return

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    await ctx.emit_finding(Finding(
        source="virustotal", category="reputation", label=f"VT {art.normalized}",
        url=None, verdict=Verdict.FOUND, confidence=0.85,
        reasons=[f"{malicious} engine(s) flag malicious; reputation {attrs.get('reputation', 0)}"],
        data={"last_analysis_stats": stats, "reputation": attrs.get("reputation")},
    ))


MODULE = Module(
    name="virustotal",
    consumes={ArtifactType.DOMAIN, ArtifactType.IP_ADDRESS},
    produces=set(),
    run=_run,
    reliability_prior=0.85,
    requires_keys=["virustotal"],
)
