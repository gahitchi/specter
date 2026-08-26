"""Extract direct contact and profile links from an observed public profile."""

from __future__ import annotations

from ..evidence import (
    Completeness,
    EvidenceClass,
    EvidencePolicy,
    ExtractionProvenance,
    TemporalEvidence,
    TemporalStatus,
    infer_origin,
    utc_now,
)
from ..graph_models import Artifact, ArtifactType
from ..http_client import RequestBudgetExceeded
from ..models import Finding, Verdict
from ..verify.defenses import detect as detect_defense
from ..web_document import (
    extract_email_values,
    extract_social_profile_values,
    parse_web_document,
    response_final_url,
)
from .base import Module, ModuleContext

_ALLOWED_CONTENT_TYPES = ("text/html", "text/plain", "application/xhtml+xml")


async def _unverifiable(
    art: Artifact,
    ctx: ModuleContext,
    reason: str,
    *,
    status_code: int | None = None,
) -> None:
    data = {"status_code": status_code} if status_code is not None else {}
    await ctx.emit_finding(Finding(
        source="profile:enrich",
        category="profile",
        label="Profile contact links",
        url=art.value,
        verdict=Verdict.UNVERIFIABLE,
        confidence=0.0,
        reasons=[reason, "No absence conclusion was made."],
        data=data,
    ))


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    try:
        response = await ctx.client.fetch(art.value)
    except RequestBudgetExceeded:
        raise
    except Exception as exc:  # noqa: BLE001 - the failed retrieval is evidence state
        await ctx.emit_finding(Finding(
            source="profile:enrich",
            category="profile",
            label="Profile contact links",
            url=art.value,
            verdict=Verdict.ERROR,
            confidence=0.0,
            reasons=[f"The profile could not be retrieved: {exc}"],
        ))
        return

    defense = detect_defense(response.status_code, response.headers, response.text)
    if defense:
        await _unverifiable(
            art,
            ctx,
            f"The profile returned a challenge or blocking response ({defense}).",
            status_code=response.status_code,
        )
        return
    if not 200 <= response.status_code < 300:
        await _unverifiable(
            art,
            ctx,
            f"The profile returned HTTP {response.status_code}.",
            status_code=response.status_code,
        )
        return

    content_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
    if content_type and not any(
        content_type.startswith(allowed) for allowed in _ALLOWED_CONTENT_TYPES
    ):
        await _unverifiable(
            art,
            ctx,
            f"The profile returned unsupported content type {content_type}.",
            status_code=response.status_code,
        )
        return

    final_url = response_final_url(response, art.value)
    document = parse_web_document(response.text, final_url)
    email_values = extract_email_values(document, limit=10)
    profile_values = extract_social_profile_values(document, limit=25)
    emails = [item.value for item in email_values]
    profiles = [item[0] for item in profile_values]
    handles = {profile.username: profile.host for profile in profiles}
    incomplete = (
        response.headers.get("x-recon-body-truncated") == "1"
        or document.parser_limited
    )
    observed_at = utc_now()
    origin = infer_origin(
        "profile:enrich",
        final_url,
        collector="profile_links",
        evidence_class=EvidenceClass.DIRECT,
    )
    extractions = [
        ExtractionProvenance(
            input_artifact_key=art.key,
            method="bounded-html-parser",
            location=item.location,
            document_url=final_url,
            original_url=art.value,
            final_url=final_url,
            context=item.context or None,
            extracted_value=item.value,
            retrieved_at=observed_at,
            transformation_chain=["HTML parse", "value normalization"],
            transformation_certainty=0.9,
        )
        for item in email_values
    ]
    extractions.extend(
        ExtractionProvenance(
            input_artifact_key=art.key,
            method="bounded-html-parser",
            location=item.location,
            document_url=final_url,
            original_url=art.value,
            final_url=final_url,
            context=item.context or None,
            extracted_value=profile.url,
            retrieved_at=observed_at,
            transformation_chain=["HTML parse", "public URL validation", "profile normalization"],
            transformation_certainty=0.85,
        )
        for profile, item in profile_values
    )
    if not extractions:
        extractions.append(ExtractionProvenance(
            input_artifact_key=art.key,
            method="bounded-html-parser",
            location="retrieved-document",
            document_url=final_url,
            original_url=art.value,
            final_url=final_url,
            retrieved_at=observed_at,
            extracted_value="no supported contact link",
            transformation_certainty=1.0 if not incomplete else 0.5,
        ))

    if emails or profiles:
        verdict = Verdict.FOUND
        confidence = 0.40
        reasons = [
            f"The fetched profile directly linked {len(emails)} email address(es) "
            f"and {len(profiles)} social profile(s).",
            "Linked values are leads; they do not by themselves prove common ownership.",
        ]
    elif incomplete:
        verdict = Verdict.UNVERIFIABLE
        confidence = 0.0
        reasons = [
            "No contact links were found before the configured response-size limit.",
            "The truncated document cannot support an absence conclusion.",
        ]
    else:
        verdict = Verdict.NOT_FOUND
        confidence = 0.0
        reasons = [
            "The fetched profile contained no supported contact or social-profile links.",
            "This result applies only to the retrieved public document.",
        ]

    lead_policy = EvidencePolicy.corroborated()
    signals = {
        **{f"email:{index}": email for index, email in enumerate(emails)},
        **{
            f"username:{profile.host}": profile.username
            for profile in profiles
        },
    }
    await ctx.emit_finding(Finding(
        source="profile:enrich",
        category="profile",
        label=f"Profile contact links: {art.data.get('site', document.title or art.value)}",
        url=art.value,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        signals=signals,
        data={
            "emails": emails,
            "handles": handles,
            "profiles": [
                {"host": profile.host, "username": profile.username, "url": profile.url}
                for profile in profiles
            ],
            "document_truncated": incomplete,
        },
        origin=origin,
        extractions=extractions,
        temporal=TemporalEvidence(
            observed_at=observed_at,
            status=(
                TemporalStatus.CURRENT
                if verdict in {Verdict.FOUND, Verdict.NOT_FOUND}
                else TemporalStatus.UNKNOWN
            ),
        ),
        completeness=Completeness.PARTIAL if incomplete else Completeness.COMPLETE,
        policy=lead_policy,
    ))

    for email in emails:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.EMAIL,
            email,
            parent=art,
            source_module="profile_links",
            confidence=0.40,
            policy=lead_policy,
            origin=origin,
        ))
    for profile in profiles:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.USERNAME,
            profile.username,
            parent=art,
            source_module="profile_links",
            confidence=0.40,
            policy=lead_policy,
            origin=origin,
            site=profile.host,
            profile_url=profile.url,
        ))
    for link in document.links[:25]:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.LINK,
            link.url,
            parent=art,
            source_module="profile_links",
            confidence=0.35,
            policy=lead_policy,
            origin=origin,
        ))


MODULE = Module(
    name="profile_links",
    consumes={ArtifactType.ACCOUNT_PROFILE},
    produces={ArtifactType.EMAIL, ArtifactType.USERNAME, ArtifactType.LINK},
    run=_run,
    reliability_prior=0.40,
    capabilities={"direct-profile-retrieval", "contact-link-extraction"},
)
