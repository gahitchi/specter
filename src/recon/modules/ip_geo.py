"""IP geolocation module: IP_ADDRESS -> geo/org/network finding via ip-api.com
(keyless, ~45 req/min). Terminal — emits evidence, no further artifacts."""

from __future__ import annotations

import json

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_FIELDS = "status,country,countryCode,regionName,city,isp,org,as,asname,reverse,hosting"


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    # ip-api free tier is HTTP-only.
    resp = await ctx.client.fetch(f"http://ip-api.com/json/{art.normalized}?fields={_FIELDS}")
    if resp.status_code != 200 or not resp.text.strip():
        return
    try:
        d = json.loads(resp.text)
    except json.JSONDecodeError:
        return
    if d.get("status") != "success":
        await ctx.emit_finding(Finding(
            source="ip:geo", category="network", label=f"Geo {art.normalized}",
            verdict=Verdict.NOT_FOUND, reasons=[d.get("message", "no geo data")]))
        return

    loc = ", ".join(filter(None, [d.get("city"), d.get("regionName"), d.get("country")]))
    await ctx.emit_finding(Finding(
        source="ip:geo", category="network", label=f"Geo {art.normalized}", url=None,
        verdict=Verdict.FOUND, confidence=0.7,
        reasons=[f"{loc or 'unknown location'} — {d.get('org') or d.get('isp') or '?'}"],
        data={k: d.get(k) for k in ("country", "countryCode", "city", "isp", "org",
                                    "as", "asname", "reverse", "hosting")},
    ))


MODULE = Module(
    name="ip_geo",
    consumes={ArtifactType.IP_ADDRESS},
    produces=set(),
    run=_run,
    reliability_prior=0.70,
    enabled=False,  # free endpoint is HTTP-only; retained for compatibility, not dispatched
)
