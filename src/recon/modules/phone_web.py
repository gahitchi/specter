"""Bounded public-web discovery and direct verification for phone numbers.

Search results are leads, never evidence. A page becomes evidence only after
Specter fetches it directly and finds the normalized number in page content or
in one structured-data record. The workflow is sequential and intentionally
small so it behaves like a careful scraper, not an API fan-out.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import phonenumbers

from ..graph_models import Artifact, ArtifactType
from ..config import SETTINGS
from ..evidence import (
    Completeness,
    EvidenceClass,
    EvidenceOrigin,
    EvidencePolicy,
    ExtractionProvenance,
    TemporalEvidence,
    TemporalStatus,
    infer_origin,
    utc_now,
)
from ..http_client import RequestBudgetExceeded
from ..models import Finding, Verdict
from ..verify.defenses import detect as detect_defense
from ..web_document import (
    WebDocument,
    collapse_text,
    find_structured_phone_match,
    matching_phone_span,
    parse_web_document,
    phone_context,
    public_http_url,
    response_final_url,
)
from .base import Module, ModuleContext

_SEARCH_URL = "https://html.duckduckgo.com/html/"
_ALLOWED_CONTENT_TYPES = ("text/html", "text/plain", "application/xhtml+xml")


@dataclass(frozen=True)
class SearchCandidate:
    url: str
    title: str = ""


@dataclass(frozen=True)
class DiscoveryResult:
    candidates: list[SearchCandidate]
    successful_queries: int
    unavailable_queries: int


class _SearchResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "a":
            return
        values = {key.casefold(): value or "" for key, value in attrs}
        classes = set(values.get("class", "").split())
        if "result__a" in classes or "result-link" in classes:
            self._href = values.get("href") or None
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            self.results.append((self._href, collapse_text(" ".join(self._text))))
            self._href = None
            self._text = []


def _parse_target(raw: str, default_region: str | None) -> tuple[Any, str, str | None] | None:
    try:
        number = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(number):
        return None
    return (
        number,
        phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        phonenumbers.region_code_for_number(number),
    )


def _search_queries(number: Any) -> list[str]:
    values = [
        phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
    ]
    queries: list[str] = []
    for value in values:
        query = f'"{value}"'
        if query not in queries:
            queries.append(query)
    return queries


def _unwrap_search_url(href: str) -> str | None:
    resolved = urljoin(_SEARCH_URL, href)
    parts = urlsplit(resolved)
    host = (parts.hostname or "").casefold()
    if host == "duckduckgo.com" or host.endswith(".duckduckgo.com"):
        try:
            target = (parse_qs(parts.query, max_num_fields=20).get("uddg") or [""])[0]
        except ValueError:
            return None
        if not target:
            return None
        resolved = target
    result = public_http_url(resolved, _SEARCH_URL)
    if not result:
        return None
    result_host = (urlsplit(result).hostname or "").casefold()
    if result_host == "duckduckgo.com" or result_host.endswith(".duckduckgo.com"):
        return None
    return result


def _parse_search_results(body: str) -> list[SearchCandidate]:
    parser = _SearchResultParser()
    parser.feed(body)
    results: list[SearchCandidate] = []
    seen: set[str] = set()
    for href, title in parser.results:
        url = _unwrap_search_url(href)
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(SearchCandidate(url=url, title=title[:160]))
    return results


async def _discover(number: Any, ctx: ModuleContext) -> DiscoveryResult:
    candidates: list[SearchCandidate] = []
    seen: set[str] = set()
    successful = 0
    unavailable = 0
    queries = _search_queries(number)[:ctx.settings.phone_web_max_queries]
    for query in queries:
        try:
            response = await ctx.client.fetch(_SEARCH_URL, params={"q": query, "kl": "wt-wt"})
        except RequestBudgetExceeded:
            raise
        except Exception:  # noqa: BLE001 - a search outage is an evidence state
            unavailable += 1
            continue
        defense = detect_defense(response.status_code, response.headers, response.text)
        if response.status_code != 200 or defense:
            unavailable += 1
            continue
        successful += 1
        for candidate in _parse_search_results(response.text):
            if candidate.url in seen:
                continue
            seen.add(candidate.url)
            candidates.append(candidate)
            if len(candidates) >= ctx.settings.phone_web_max_pages:
                break
    return DiscoveryResult(
        candidates=candidates[:ctx.settings.phone_web_max_pages],
        successful_queries=successful,
        unavailable_queries=unavailable,
    )


async def _emit_match(
    art: Artifact,
    ctx: ModuleContext,
    candidate: SearchCandidate,
    document: WebDocument,
    target_e164: str,
    region: str | None,
    final_url: str,
) -> bool:
    visible_span = matching_phone_span(document.visible_text, target_e164, region)
    tel_match = any(
        matching_phone_span(value, target_e164, region)
        for value in document.telephone_links
    )
    structured_match = find_structured_phone_match(document, target_e164, region)
    if not visible_span and not tel_match and not structured_match:
        return False

    structured = structured_match.as_dict() if structured_match else None
    identity_record = bool(structured_match and structured_match.identity_record)
    confidence = 0.82 if identity_record else 0.78
    title = document.title or candidate.title or (
        urlsplit(candidate.url).hostname or "Public page"
    )
    context = phone_context(document.visible_text, visible_span)
    reasons = [
        "The page was fetched directly and contains the same normalized phone number.",
        "This confirms a public mention, not current ownership or control of the number.",
    ]
    if context:
        reasons.append(f"Page context: {context}")
    elif tel_match:
        reasons.append("The matching number appears in a telephone link.")
    if identity_record:
        reasons.append("Identity fields come from the same structured record as the phone number.")

    signals = {"phone_e164": target_e164}
    if identity_record and structured and structured.get("email"):
        signals["email"] = structured["email"]
    observed_at = utc_now()
    origin = infer_origin(
        "phone:web",
        final_url,
        collector="phone_web",
        evidence_class=EvidenceClass.DIRECT,
    )
    if structured_match:
        location = "json-ld.telephone"
    elif tel_match:
        location = "anchor[href^=tel]"
    else:
        location = "visible-text"
    incomplete = document.parser_limited
    await ctx.emit_finding(Finding(
        source="phone:web",
        category="phone",
        label=f"Public phone mention: {title[:120]}",
        url=candidate.url,
        verdict=Verdict.FOUND,
        confidence=confidence,
        reasons=reasons,
        signals=signals,
        data={
            "phone_e164": target_e164,
            "page_title": title,
            "context": context,
            "structured": structured,
            "discovery_source": "DuckDuckGo HTML search",
            "verified_directly": True,
        },
        origin=origin,
        extractions=[ExtractionProvenance(
            input_artifact_key=art.key,
            method="normalized-phone-match",
            location=location,
            document_url=final_url,
            original_url=candidate.url,
            final_url=final_url,
            context=context,
            extracted_value=target_e164,
            retrieved_at=observed_at,
            transformation_chain=["HTML parse", "phone normalization", "E.164 comparison"],
            transformation_certainty=0.95,
        )],
        temporal=TemporalEvidence(
            observed_at=observed_at,
            status=TemporalStatus.CURRENT,
        ),
        completeness=Completeness.PARTIAL if incomplete else Completeness.COMPLETE,
    ))
    await ctx.emit_artifact(Artifact.make(
        ArtifactType.URL,
        candidate.url,
        parent=art,
        source_module="phone_web",
        confidence=confidence,
        origin=origin,
    ))

    if not identity_record or not structured:
        return True
    lead_policy = EvidencePolicy(
        requires_corroboration=True,
        minimum_independent_origins=2,
    )
    if structured.get("name"):
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.NAME,
            structured["name"],
            parent=art,
            source_module="phone_web",
            confidence=confidence,
            policy=lead_policy,
            origin=origin,
        ))
    if structured.get("email"):
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.EMAIL,
            structured["email"],
            parent=art,
            source_module="phone_web",
            confidence=confidence,
            policy=lead_policy,
            origin=origin,
        ))
    for url in structured.get("urls", []):
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.ACCOUNT_PROFILE,
            url,
            parent=art,
            source_module="phone_web",
            confidence=0.80,
            policy=lead_policy,
            origin=origin,
        ))
    return True


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    if not ctx.settings.phone_web_enabled:
        return
    parsed_target = _parse_target(art.value, ctx.settings.phone_default_region)
    if not parsed_target:
        return  # The offline phone module reports the actionable parse error.
    number, target_e164, region = parsed_target
    discovery = await _discover(number, ctx)
    if not discovery.successful_queries:
        observed_at = utc_now()
        await ctx.emit_finding(Finding(
            source="phone:web",
            category="phone",
            label="Public phone mentions",
            verdict=Verdict.UNVERIFIABLE,
            confidence=0.0,
            reasons=[
                "Public-page discovery was unavailable or blocked; no absence conclusion was made."
            ],
            signals={"phone_e164": target_e164},
            origin=infer_origin(
                "phone:web",
                _SEARCH_URL,
                collector="phone_web",
                evidence_class=EvidenceClass.DIRECT,
                independence_key="search:duckduckgo",
            ),
            extractions=[ExtractionProvenance(
                input_artifact_key=art.key,
                method="bounded-exact-format-search",
                location="search-response",
                document_url=_SEARCH_URL,
                retrieved_at=observed_at,
                direct=False,
                transformation_chain=["exact format query", "availability check"],
                transformation_certainty=0.5,
            )],
            temporal=TemporalEvidence(observed_at=observed_at),
            completeness=Completeness.PARTIAL,
        ))
        return

    matched_pages = 0
    unavailable_pages = 0
    checked_pages = 0
    checked_extractions: list[ExtractionProvenance] = []
    for candidate in discovery.candidates:
        try:
            response = await ctx.client.fetch(candidate.url)
        except RequestBudgetExceeded:
            raise
        except Exception:  # noqa: BLE001 - individual pages degrade independently
            unavailable_pages += 1
            continue
        defense = detect_defense(response.status_code, response.headers, response.text)
        if defense or response.status_code in {401, 403, 407, 409, 423, 425, 429}:
            unavailable_pages += 1
            continue
        if response.status_code in {404, 410}:
            checked_pages += 1
            continue
        if not 200 <= response.status_code < 300:
            unavailable_pages += 1
            continue
        content_type = response.headers.get("content-type", "").split(";", 1)[0].casefold()
        if content_type and not any(content_type.startswith(item) for item in _ALLOWED_CONTENT_TYPES):
            unavailable_pages += 1
            continue
        if response.headers.get("x-recon-body-truncated") == "1":
            unavailable_pages += 1
        final_url = response_final_url(response, candidate.url)
        document = parse_web_document(response.text, final_url)
        if document.parser_limited:
            unavailable_pages += 1
        checked_pages += 1
        checked_extractions.append(ExtractionProvenance(
            input_artifact_key=art.key,
            method="normalized-phone-match",
            location="retrieved-document",
            document_url=final_url,
            original_url=candidate.url,
            final_url=final_url,
            extracted_value="no matching phone observed",
            retrieved_at=utc_now(),
            transformation_chain=["HTML parse", "phone normalization", "E.164 comparison"],
            transformation_certainty=0.8 if document.parser_limited else 1.0,
        ))
        if await _emit_match(
            art, ctx, candidate, document, target_e164, region, final_url
        ):
            matched_pages += 1

    if matched_pages:
        return

    incomplete = bool(discovery.unavailable_queries or unavailable_pages)
    verdict = Verdict.UNVERIFIABLE if incomplete else Verdict.NOT_FOUND
    if incomplete:
        reason = (
            f"No direct match was confirmed; {unavailable_pages} discovered page(s) and "
            f"{discovery.unavailable_queries} search request(s) could not be verified."
        )
    elif discovery.candidates:
        reason = f"Checked {checked_pages} discovered public page(s) without an exact phone match."
    else:
        reason = "The bounded search discovered no public pages for the exact phone formats."
    observed_at = utc_now()
    await ctx.emit_finding(Finding(
        source="phone:web",
        category="phone",
        label="Public phone mentions",
        verdict=verdict,
        confidence=0.0,
        reasons=[reason, "A bounded public-web check is not proof that no mention exists."],
        signals={"phone_e164": target_e164},
        data={
            "queries_attempted": min(
                len(_search_queries(number)), ctx.settings.phone_web_max_queries
            ),
            "candidate_pages": len(discovery.candidates),
            "checked_pages": checked_pages,
            "unavailable_pages": unavailable_pages,
        },
        origin=EvidenceOrigin(
            collector="phone_web",
            operator="DuckDuckGo and directly retrieved public pages",
            origin="bounded-phone-web-check",
            evidence_class=EvidenceClass.AGGREGATED,
            independence_key="public_web",
        ),
        extractions=checked_extractions or [ExtractionProvenance(
            input_artifact_key=art.key,
            method="bounded-exact-format-search",
            location="search-results",
            document_url=_SEARCH_URL,
            extracted_value="no candidate public page",
            retrieved_at=observed_at,
            direct=False,
            transformation_chain=["exact format query", "candidate URL validation"],
            transformation_certainty=1.0 if not incomplete else 0.5,
        )],
        temporal=TemporalEvidence(
            observed_at=observed_at,
            status=(
                TemporalStatus.UNKNOWN if incomplete else TemporalStatus.CURRENT
            ),
        ),
        completeness=Completeness.PARTIAL if incomplete else Completeness.COMPLETE,
    ))


MODULE = Module(
    name="phone_web",
    consumes={ArtifactType.PHONE},
    produces={ArtifactType.URL, ArtifactType.ACCOUNT_PROFILE, ArtifactType.NAME, ArtifactType.EMAIL},
    run=_run,
    reliability_prior=0.62,
    use_cache=False,
    enabled=SETTINGS.phone_web_enabled,
    capabilities={"phone-page-discovery", "direct-phone-verification", "structured-data"},
)
