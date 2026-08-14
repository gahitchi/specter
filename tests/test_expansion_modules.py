import dataclasses

import httpx
import pytest

from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.models import Query, Verdict
from recon.modules import bluesky, gitlab, hackernews, wikidata
from recon.modules.base import ModuleContext


class FakeClient:
    def __init__(self, response):
        self.response = response

    async def fetch(self, *_args, **_kwargs):
        return self.response


async def _run(module, artifact, response):
    findings, artifacts = [], []

    async def finding(item):
        findings.append(item)

    async def discovered(item):
        artifacts.append(item)

    context = ModuleContext(
        client=FakeClient(response),
        query=Query(),
        settings=dataclasses.replace(SETTINGS, expansion_requested=True),
        in_scope=lambda _item: True,
        _emit_finding=finding,
        _emit_artifact=discovered,
    )
    await module.run(artifact, context)
    return findings, artifacts


@pytest.mark.asyncio
async def test_gitlab_exact_public_user():
    findings, artifacts = await _run(
        gitlab.MODULE,
        Artifact.make(ArtifactType.USERNAME, "alice"),
        httpx.Response(200, json=[{"id": 7, "username": "alice", "name": "Alice",
                                  "state": "active", "web_url": "https://gitlab.com/alice"}]),
    )
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].signals == {"username:gitlab": "alice"}
    assert artifacts[0].type == ArtifactType.ACCOUNT_PROFILE


@pytest.mark.asyncio
async def test_bluesky_profile_is_did_backed():
    findings, _ = await _run(
        bluesky.MODULE,
        Artifact.make(ArtifactType.USERNAME, "alice.example"),
        httpx.Response(200, json={"handle": "alice.example", "did": "did:plc:123",
                                  "followersCount": 10}),
    )
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].signals["bluesky_did"] == "did:plc:123"


@pytest.mark.asyncio
async def test_hackernews_null_is_not_found():
    findings, _ = await _run(
        hackernews.MODULE,
        Artifact.make(ArtifactType.USERNAME, "missing"),
        httpx.Response(200, text="null"),
    )
    assert findings[0].verdict == Verdict.NOT_FOUND


@pytest.mark.asyncio
async def test_wikidata_name_match_remains_uncertain():
    findings, artifacts = await _run(
        wikidata.MODULE,
        Artifact.make(ArtifactType.NAME, "Ada Lovelace"),
        httpx.Response(200, json={"search": [{"id": "Q7259", "label": "Ada Lovelace",
                                               "description": "English mathematician"}]}),
    )
    assert findings[0].verdict == Verdict.UNCERTAIN
    assert findings[0].confidence < SETTINGS.found_confidence
    assert artifacts[0].confidence == findings[0].confidence
