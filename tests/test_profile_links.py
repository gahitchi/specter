import dataclasses

import httpx
import pytest

from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.models import Query, Verdict
from recon.modules import profile_links
from recon.modules.base import ModuleContext

_PROFILE = "https://profiles.example/alice"


class FakeClient:
    def __init__(self, response: httpx.Response) -> None:
        self.response = response

    async def fetch(self, _url):
        return self.response


async def _run(response: httpx.Response):
    findings, artifacts = [], []

    async def emit_finding(item):
        findings.append(item)

    async def emit_artifact(item):
        artifacts.append(item)

    context = ModuleContext(
        client=FakeClient(response),
        query=Query(username="alice"),
        settings=dataclasses.replace(SETTINGS),
        in_scope=lambda _item: True,
        _emit_finding=emit_finding,
        _emit_artifact=emit_artifact,
    )
    artifact = Artifact.make(ArtifactType.ACCOUNT_PROFILE, _PROFILE, site="Example")
    await profile_links.MODULE.run(artifact, context)
    return findings, artifacts


@pytest.mark.asyncio
async def test_profile_links_use_direct_visible_and_structured_links_only():
    response = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="""
            <title>Alice</title>
            <p>Reach <a href="mailto:Alice@Example.com">Alice</a></p>
            <a href="/projects#featured">Projects</a>
            <script>const decoy = 'decoy@example.net';</script>
            <script type="application/ld+json">
              {"@type":"Person","sameAs":"https://github.com/Alice"}
            </script>
        """,
    )

    findings, artifacts = await _run(response)

    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].data["emails"] == ["alice@example.com"]
    assert findings[0].data["handles"] == {"alice": "github.com"}
    assert "decoy@example.net" not in findings[0].data["emails"]
    assert {(item.type, item.value) for item in artifacts} == {
        (ArtifactType.EMAIL, "alice@example.com"),
        (ArtifactType.USERNAME, "alice"),
        (ArtifactType.LINK, "https://profiles.example/projects"),
    }
    username = next(item for item in artifacts if item.type == ArtifactType.USERNAME)
    assert username.data == {
        "site": "github.com",
        "profile_url": "https://github.com/Alice",
    }


@pytest.mark.asyncio
async def test_profile_challenge_is_unverifiable():
    findings, artifacts = await _run(httpx.Response(
        403,
        headers={"server": "cloudflare", "content-type": "text/html"},
        text="Attention Required! Cloudflare Ray ID",
    ))

    assert findings[0].verdict == Verdict.UNVERIFIABLE
    assert artifacts == []


@pytest.mark.asyncio
async def test_truncated_empty_profile_does_not_claim_absence():
    findings, artifacts = await _run(httpx.Response(
        200,
        headers={"content-type": "text/html", "x-recon-body-truncated": "1"},
        text="<p>No links in the retrieved prefix</p>",
    ))

    assert findings[0].verdict == Verdict.UNVERIFIABLE
    assert artifacts == []
