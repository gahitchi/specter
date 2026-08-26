import dataclasses
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest

from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.models import Query, Verdict
from recon.modules import phone_web
from recon.modules.base import ModuleContext

_PHONE = "+14155552671"
_PAGE = "https://directory.example/alice"
_FIXTURES = Path(__file__).parent / "fixtures" / "web"


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def _search_html(*urls: str) -> str:
    links = []
    for index, url in enumerate(urls):
        redirect = f"//duckduckgo.com/l/?{urlencode({'uddg': url})}"
        links.append(f'<a class="result__a" href="{redirect}">Result {index}</a>')
    return "<html><body>" + "".join(links) + "</body></html>"


class FakeClient:
    def __init__(self, search: list[httpx.Response], pages: dict[str, httpx.Response]) -> None:
        self.search = list(search)
        self.pages = pages
        self.calls: list[tuple[str, dict | None]] = []

    async def fetch(self, url: str, *, params=None):
        self.calls.append((url, params))
        if url == phone_web._SEARCH_URL:
            return self.search.pop(0)
        return self.pages[url]


async def _run(
    client: FakeClient,
    *,
    settings=None,
    value: str = _PHONE,
):
    findings, artifacts = [], []

    async def emit_finding(item):
        findings.append(item)

    async def emit_artifact(item):
        artifacts.append(item)

    context = ModuleContext(
        client=client,
        query=Query(phone=value),
        settings=settings
        or dataclasses.replace(
            SETTINGS,
            phone_web_enabled=True,
            phone_web_max_queries=2,
            phone_web_max_pages=6,
        ),
        in_scope=lambda _item: True,
        _emit_finding=emit_finding,
        _emit_artifact=emit_artifact,
    )
    await phone_web.MODULE.run(Artifact.make(ArtifactType.PHONE, value), context)
    return findings, artifacts


def test_search_queries_cover_exact_international_and_national_formats():
    parsed = phone_web._parse_target(_PHONE, None)
    assert parsed is not None
    queries = phone_web._search_queries(parsed[0])
    assert queries == [
        '"+14155552671"',
        '"+1 415-555-2671"',
        '"(415) 555-2671"',
    ]


def test_search_results_are_unwrapped_deduplicated_and_public_only():
    body = _search_html(
        _PAGE,
        _PAGE,
        "http://127.0.0.1/private",
        "https://example.org/second#section",
    )
    results = phone_web._parse_search_results(body)
    assert [item.url for item in results] == [
        _PAGE,
        "https://example.org/second",
    ]


def test_candidate_priority_checks_direct_looking_pages_before_directories():
    direct = phone_web.SearchCandidate("https://profile.example/alice", "Alice contact")
    directory = phone_web.SearchCandidate(
        "https://lookup.example/alice", "Reverse phone lookup directory"
    )

    assert phone_web._candidate_priority(direct) < phone_web._candidate_priority(directory)


@pytest.mark.asyncio
async def test_direct_page_match_is_evidence_and_duplicate_results_are_fetched_once():
    search = httpx.Response(200, text=_search_html(_PAGE))
    page = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="<html><title>Alice contact</title><p>Call +1 (415) 555-2671 for Alice.</p></html>",
    )
    client = FakeClient([search, search], {_PAGE: page})

    findings, artifacts = await _run(client)

    assert len(findings) == 1
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].url == _PAGE
    assert "not current ownership" in findings[0].reasons[1]
    assert [item.type for item in artifacts] == [ArtifactType.URL]
    assert [url for url, _params in client.calls].count(_PAGE) == 1


@pytest.mark.asyncio
async def test_unrelated_phone_on_candidate_page_is_not_a_match():
    search = httpx.Response(200, text=_search_html(_PAGE))
    page = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="<p>Reception: +1 212-555-0199</p>",
    )
    findings, artifacts = await _run(FakeClient([search, search], {_PAGE: page}))

    assert findings[-1].verdict == Verdict.NOT_FOUND
    assert artifacts == []


@pytest.mark.asyncio
async def test_same_person_json_ld_can_create_guarded_identity_pivots():
    search = httpx.Response(200, text=_search_html(_PAGE))
    page = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="""
            <html><title>Alice</title><script type="application/ld+json">
            {
              "@type": "Person",
              "name": "Alice Example",
              "telephone": "+1 415 555 2671",
              "email": "alice@example.com",
              "url": "https://alice.example/about",
              "sameAs": ["https://github.com/alice"]
            }
            </script></html>
        """,
    )
    findings, artifacts = await _run(FakeClient([search, search], {_PAGE: page}))

    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].confidence == 0.82
    assert findings[0].signals["email"] == "alice@example.com"
    assert {item.type for item in artifacts} == {
        ArtifactType.URL,
        ArtifactType.NAME,
        ArtifactType.EMAIL,
        ArtifactType.ACCOUNT_PROFILE,
    }
    profile_values = {item.value for item in artifacts if item.type == ArtifactType.ACCOUNT_PROFILE}
    assert profile_values == {
        "https://alice.example/about",
        "https://github.com/alice",
    }
    assert all(
        item.data.get("subject_relation") == "same_subject"
        for item in artifacts
        if item.type
        in {
            ArtifactType.NAME,
            ArtifactType.EMAIL,
            ArtifactType.ACCOUNT_PROFILE,
        }
    )


@pytest.mark.asyncio
async def test_copied_directory_pages_collapse_and_never_create_identity_pivots():
    pages = {
        "https://one.example/lookup": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=_fixture("phone_directory_copy.html"),
        ),
        "https://two.example/lookup": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=_fixture("phone_directory_copy.html"),
        ),
    }
    search = httpx.Response(200, text=_search_html(*pages))

    findings, artifacts = await _run(FakeClient([search, search], pages))

    assert {finding.data["association"] for finding in findings} == {"directory_listing"}
    assert {finding.origin.independence_key for finding in findings} == {"phone-directory"}
    assert all(finding.policy.confirmation_allowed is False for finding in findings)
    assert {artifact.type for artifact in artifacts} == {ArtifactType.URL}


@pytest.mark.asyncio
async def test_exact_third_party_person_copies_share_one_claim_lineage():
    pages = {
        "https://one.example/profile": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=_fixture("phone_person_profile.html"),
        ),
        "https://two.example/profile": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=_fixture("phone_person_profile.html"),
        ),
    }
    search = httpx.Response(200, text=_search_html(*pages))

    findings, artifacts = await _run(FakeClient([search, search], pages))

    assert len(findings) == 2
    assert len({finding.origin.independence_key for finding in findings}) == 1
    assert all(finding.origin.independence_key.startswith("phone-record:") for finding in findings)
    identity_artifacts = [artifact for artifact in artifacts if artifact.type != ArtifactType.URL]
    assert identity_artifacts
    assert len({artifact.origin.independence_key for artifact in identity_artifacts}) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fixture_name", "association", "temporal_status"),
    [
        ("phone_service_number.html", "service_contact", "unknown"),
        ("phone_reassigned.html", "historical", "historical"),
    ],
)
async def test_shared_and_historical_numbers_remain_context_only(
    fixture_name: str,
    association: str,
    temporal_status: str,
):
    search = httpx.Response(200, text=_search_html(_PAGE))
    page = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text=_fixture(fixture_name),
    )

    findings, artifacts = await _run(FakeClient([search, search], {_PAGE: page}))

    assert findings[0].data["association"] == association
    assert findings[0].temporal.status.value == temporal_status
    assert findings[0].policy.confirmation_allowed is False
    assert {artifact.type for artifact in artifacts} == {ArtifactType.URL}


@pytest.mark.asyncio
async def test_confirmed_mention_does_not_hide_incomplete_coverage():
    blocked_page = "https://blocked.example/contact"
    search = httpx.Response(200, text=_search_html(_PAGE, blocked_page))
    pages = {
        _PAGE: httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=_fixture("phone_person_profile.html"),
        ),
        blocked_page: httpx.Response(429, text="rate limited"),
    }

    findings, _artifacts = await _run(FakeClient([search, search], pages))

    assert [finding.verdict for finding in findings] == [
        Verdict.FOUND,
        Verdict.UNVERIFIABLE,
    ]
    assert "coverage incomplete" in findings[-1].reasons[-1]


@pytest.mark.asyncio
async def test_search_block_is_unverifiable_instead_of_not_found():
    blocked = httpx.Response(202, text="Automated search challenge")
    findings, artifacts = await _run(FakeClient([blocked, blocked], {}))

    assert findings[0].verdict == Verdict.UNVERIFIABLE
    assert "no absence conclusion" in findings[0].reasons[0]
    assert artifacts == []


@pytest.mark.asyncio
async def test_phone_web_can_be_disabled_without_network_activity():
    client = FakeClient([], {})
    settings = dataclasses.replace(SETTINGS, phone_web_enabled=False)
    findings, artifacts = await _run(client, settings=settings)

    assert findings == []
    assert artifacts == []
    assert client.calls == []


def test_phone_web_limits_and_default_region_are_validated():
    with pytest.raises(ValueError, match="positive"):
        dataclasses.replace(SETTINGS, phone_web_max_pages=0)
    with pytest.raises(ValueError, match="supported ISO"):
        dataclasses.replace(SETTINGS, phone_default_region="ZZ")
    with pytest.raises(ValueError, match="capped"):
        dataclasses.replace(SETTINGS, phone_web_max_queries=4)
    with pytest.raises(ValueError, match="capped"):
        dataclasses.replace(SETTINGS, phone_web_max_pages=7)
