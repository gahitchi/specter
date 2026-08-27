"""EMAIL module: gravatar/MX existence signals (via the existing collector), then
pivot into a gravatar HASH, a candidate USERNAME (local-part), and the email's
DOMAIN so the domain/DNS modules can take over."""

from __future__ import annotations

from ..collectors import email as _email
from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Query
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    q = Query(email=art.normalized)
    email = art.normalized
    local, _, domain = email.partition("@")

    async def emit(f: Finding) -> None:
        await ctx.emit_finding(f)
        if f.signals.get("gravatar_hash"):
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.HASH, f.signals["gravatar_hash"], parent=art,
                source_module="email", kind="gravatar_md5",
            ))
        cand = f.data.get("candidate_username")
        if cand:
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.USERNAME, cand, parent=art, source_module="email",
                confidence=0.4,
                policy=EvidencePolicy.candidate(),
            ))

    await _email.collect(q, ctx.client, emit)

    # Pivot the email's domain into the DNS/subdomain modules.
    if domain:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.DOMAIN, domain, parent=art, source_module="email",
        ))


MODULE = Module(
    name="email",
    consumes={ArtifactType.EMAIL},
    produces={ArtifactType.HASH, ArtifactType.USERNAME, ArtifactType.DOMAIN},
    run=_run,
    reliability_prior=0.85,
)
