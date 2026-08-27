"""Optional Maigret pilot: username observations remain candidate leads."""

from __future__ import annotations

from ..adapters.maigret import (
    AdapterInputError,
    AdapterUnavailableError,
    run_maigret,
)
from ..adapters.process import ExternalProcessError
from ..config import SETTINGS
from ..evidence import Completeness, EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    if not ctx.settings.maigret_enabled:
        return
    try:
        result = await run_maigret(art.value, ctx.settings.maigret_executable)
    except AdapterInputError as exc:
        await ctx.emit_finding(Finding(
            source="external:maigret",
            category="username",
            label="Maigret profile candidates",
            verdict=Verdict.UNVERIFIABLE,
            confidence=0.0,
            reasons=[str(exc), "No account-existence conclusion was made."],
        ))
        return
    except AdapterUnavailableError as exc:
        await ctx.emit_finding(Finding(
            source="external:maigret",
            category="username",
            label="Maigret adapter",
            verdict=Verdict.ERROR,
            confidence=0.0,
            reasons=[str(exc)],
        ))
        return
    except ExternalProcessError as exc:
        await ctx.emit_finding(Finding(
            source="external:maigret",
            category="username",
            label="Maigret adapter",
            verdict=Verdict.ERROR,
            confidence=0.0,
            reasons=[f"The bounded external check failed: {exc}"],
        ))
        return

    if not result.observations:
        await ctx.emit_finding(Finding(
            source="external:maigret",
            category="username",
            label="Maigret profile candidates",
            verdict=Verdict.NOT_FOUND,
            confidence=0.0,
            reasons=[
                "Maigret returned no claimed profiles in the bounded 25-site check.",
                "This is not proof that the username has no accounts elsewhere.",
            ],
            data={
                "adapter_contract": "1.0",
                "candidate_only": True,
                "tool_version": result.tool_version,
                "external_requests_counted_by_specter": False,
            },
            completeness=Completeness.PARTIAL,
            policy=EvidencePolicy.candidate(),
        ))
        return

    for observation in result.observations:
        site = str(observation.attributes.get("site") or "Unknown site")
        await ctx.emit_finding(Finding(
            source=f"external:maigret:{site}",
            category="username",
            label=observation.label,
            url=observation.url,
            verdict=Verdict.UNCERTAIN,
            confidence=observation.confidence,
            reasons=observation.reasons,
            signals={"username": art.normalized},
            data={
                "external_observation": observation.model_dump(mode="json"),
                "candidate_only": True,
                "external_requests_counted_by_specter": False,
            },
            origin=observation.provenance.as_origin("maigret"),
            extractions=(
                [observation.provenance.extraction]
                if observation.provenance.extraction is not None else []
            ),
            completeness=observation.completeness,
            policy=observation.policy,
        ))
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.URL,
            observation.value,
            parent=art,
            source_module="maigret",
            confidence=observation.confidence,
            origin=observation.provenance.as_origin("maigret"),
            policy=observation.policy,
            candidate_only=True,
            adapter_contract=observation.schema_version,
            site=site,
        ))


MODULE = Module(
    name="maigret",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.URL},
    run=_run,
    reliability_prior=0.45,
    use_cache=False,
    enabled=SETTINGS.maigret_enabled,
    capabilities={"username-candidate-discovery", "external-tool"},
    evidence_policy=EvidencePolicy.candidate(),
)
