"""Hacker News official Firebase API user lookup."""

from __future__ import annotations

from urllib.parse import quote

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    account = quote(art.normalized, safe="")
    response = await ctx.client.fetch(
        f"https://hacker-news.firebaseio.com/v0/user/{account}.json"
    )
    if response.status_code == 404 or (response.status_code == 200 and response.text == "null"):
        await ctx.emit_finding(Finding(
            source="hackernews:user", category="username", label=f"Hacker News {art.normalized}",
            verdict=Verdict.NOT_FOUND, reasons=["no user in the official Hacker News API"],
        ))
        return
    if response.status_code != 200:
        await ctx.emit_finding(Finding(
            source="hackernews:user", category="username", label=f"Hacker News {art.normalized}",
            verdict=Verdict.UNVERIFIABLE,
            reasons=[f"Hacker News API status {response.status_code}"],
        ))
        return
    user = response.json()
    url = f"https://news.ycombinator.com/user?id={account}"
    await ctx.emit_finding(Finding(
        source="hackernews:user", category="username", label=f"Hacker News: {user.get('id')}",
        url=url, verdict=Verdict.FOUND, confidence=0.82,
        reasons=["user returned by the official Hacker News Firebase API"],
        signals={"username:hackernews": str(user.get("id") or art.normalized)},
        data={key: user.get(key) for key in ("created", "karma", "about")},
    ))
    await ctx.emit_artifact(Artifact.make(
        ArtifactType.ACCOUNT_PROFILE, url, parent=art, source_module="hackernews"
    ))


MODULE = Module(
    name="hackernews",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.ACCOUNT_PROFILE},
    run=_run,
    reliability_prior=0.70,
    expansion=True,
)
