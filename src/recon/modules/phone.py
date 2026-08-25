"""PHONE module: deterministic, offline numbering-plan metadata."""

from __future__ import annotations

from ..collectors import phone as _phone
from ..graph_models import Artifact, ArtifactType
from ..models import Query
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    await _phone.collect(
        Query(phone=art.value),
        ctx.client,
        ctx.emit_finding,
        default_region=ctx.settings.phone_default_region,
    )


MODULE = Module(
    name="phone",
    consumes={ArtifactType.PHONE},
    produces=set(),
    run=_run,
    reliability_prior=0.95,
)
