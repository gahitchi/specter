"""Wikidata entity search as a name-based candidate source."""

from __future__ import annotations

from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    response = await ctx.client.fetch(
        "https://www.wikidata.org/w/api.php",
        params={
            "action": "wbsearchentities", "format": "json", "language": "en",
            "type": "item", "limit": "5", "search": art.normalized,
        },
    )
    if response.status_code != 200:
        await ctx.emit_finding(Finding(
            source="wikidata:search", category="name", label=f"Wikidata {art.value}",
            verdict=Verdict.UNVERIFIABLE,
            reasons=[f"Wikidata API status {response.status_code}"],
        ))
        return
    results = response.json().get("search", [])[:5]
    if not results:
        await ctx.emit_finding(Finding(
            source="wikidata:search", category="name", label=f"Wikidata {art.value}",
            verdict=Verdict.NOT_FOUND, reasons=["no Wikidata label or alias match"],
        ))
        return
    for result in results:
        entity_id = str(result.get("id") or "")
        url = f"https://www.wikidata.org/wiki/{entity_id}"
        await ctx.emit_finding(Finding(
            source="wikidata:search", category="name",
            label=f"Wikidata: {result.get('label') or entity_id}",
            url=url, verdict=Verdict.UNCERTAIN, confidence=0.45,
            reasons=["name or alias candidate; not proof of identity"],
            signals={"wikidata": entity_id} if entity_id else {},
            data={"description": result.get("description"), "aliases": result.get("aliases", [])},
        ))
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.ACCOUNT_PROFILE, url, parent=art, source_module="wikidata",
            confidence=0.45,
            policy=EvidencePolicy.candidate(),
        ))


MODULE = Module(
    name="wikidata",
    consumes={ArtifactType.NAME},
    produces={ArtifactType.ACCOUNT_PROFILE},
    run=_run,
    reliability_prior=0.58,
    expansion=True,
    evidence_policy=EvidencePolicy.candidate(),
)
