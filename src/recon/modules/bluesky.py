"""Bluesky public AppView profile lookup for an exact actor handle."""

from __future__ import annotations

from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    response = await ctx.client.fetch(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
        params={"actor": art.normalized},
    )
    if response.status_code in {400, 404}:
        await ctx.emit_finding(Finding(
            source="bluesky:profile", category="username", label=f"Bluesky {art.normalized}",
            verdict=Verdict.NOT_FOUND, reasons=["actor was not resolved by Bluesky AppView"],
        ))
        return
    if response.status_code != 200:
        await ctx.emit_finding(Finding(
            source="bluesky:profile", category="username", label=f"Bluesky {art.normalized}",
            verdict=Verdict.UNVERIFIABLE,
            reasons=[f"Bluesky API status {response.status_code}"],
        ))
        return
    profile = response.json()
    handle = str(profile.get("handle") or art.normalized)
    did = str(profile.get("did") or "")
    url = f"https://bsky.app/profile/{did or handle}"
    await ctx.emit_finding(Finding(
        source="bluesky:profile", category="username", label=f"Bluesky: {handle}",
        url=url, verdict=Verdict.FOUND, confidence=0.84,
        reasons=["actor resolved by the public Bluesky AppView API"],
        signals={
            "username:bluesky": handle,
            **({"bluesky_did": did} if did else {}),
            **({"name": profile["displayName"]} if profile.get("displayName") else {}),
        },
        data={key: profile.get(key) for key in (
            "displayName", "description", "followersCount", "followsCount", "postsCount"
        )},
        policy=EvidencePolicy.corroborated(),
    ))
    await ctx.emit_artifact(Artifact.make(
        ArtifactType.ACCOUNT_PROFILE, url, parent=art, source_module="bluesky"
    ))


MODULE = Module(
    name="bluesky",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.ACCOUNT_PROFILE},
    run=_run,
    reliability_prior=0.72,
    expansion=True,
)
