"""USERNAME module: site fanout through the false-positive verify engine, then
pivot every FOUND profile into an ACCOUNT_PROFILE artifact for enrichment.

Delegates verification to the existing `collectors.username.collect` — behavior
of the verdict pipeline is unchanged; this only wraps it in the module envelope
and emits the artifacts that make recursion possible."""

from __future__ import annotations

from ..collectors import username as _username
from ..evidence import confirmation_eligible
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Query, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    q = Query(username=art.normalized)

    async def emit(f: Finding) -> None:
        await ctx.emit_finding(f)
        if f.verdict == Verdict.FOUND and f.url and confirmation_eligible(f):
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.ACCOUNT_PROFILE, f.url, parent=art,
                source_module="username", site=f.label,
            ))

    await _username.collect(q, ctx.client, emit)


MODULE = Module(
    name="username",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.ACCOUNT_PROFILE},
    run=_run,
    reliability_prior=0.75,
)
