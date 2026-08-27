"""NAME module: ORCID + OpenAlex structured author records (via the existing
collector). Terminal — emits evidence but no further artifacts."""

from __future__ import annotations

from ..collectors import name as _name
from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Query
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    await _name.collect(Query(name=art.normalized), ctx.client, ctx.emit_finding)


MODULE = Module(
    name="name",
    consumes={ArtifactType.NAME},
    produces=set(),
    run=_run,
    reliability_prior=0.60,
    evidence_policy=EvidencePolicy.candidate(),
)
