"""GitLab public Users API enrichment for an exact username."""

from __future__ import annotations

from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    response = await ctx.client.fetch(
        "https://gitlab.com/api/v4/users", params={"username": art.normalized}
    )
    if response.status_code != 200:
        await ctx.emit_finding(Finding(
            source="gitlab:user", category="username", label=f"GitLab {art.normalized}",
            verdict=Verdict.UNVERIFIABLE,
            reasons=[f"GitLab API status {response.status_code}"],
        ))
        return
    users = response.json()
    user = next(
        (item for item in users if str(item.get("username", "")).casefold() == art.normalized.casefold()),
        None,
    )
    if user is None:
        await ctx.emit_finding(Finding(
            source="gitlab:user", category="username", label=f"GitLab {art.normalized}",
            verdict=Verdict.NOT_FOUND, reasons=["no exact GitLab username match"],
        ))
        return
    url = user.get("web_url")
    await ctx.emit_finding(Finding(
        source="gitlab:user", category="username", label=f"GitLab: {user.get('username')}",
        url=url, verdict=Verdict.FOUND, confidence=0.84,
        reasons=["exact username returned by the public GitLab Users API"],
        signals={
            "username:gitlab": art.normalized,
            **({"name": user["name"]} if user.get("name") else {}),
        },
        data={key: user.get(key) for key in ("id", "name", "state", "avatar_url")},
        policy=EvidencePolicy.corroborated(),
    ))
    if url:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.ACCOUNT_PROFILE, url, parent=art, source_module="gitlab"
        ))


MODULE = Module(
    name="gitlab",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.ACCOUNT_PROFILE},
    run=_run,
    reliability_prior=0.72,
    expansion=True,
)
