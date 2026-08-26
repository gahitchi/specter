"""Phase-2 keyless modules: HTTP mocked with respx, DNS monkeypatched."""

import dataclasses

import httpx
import pytest
import respx

from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.http_client import RateLimitedClient
from recon.models import Query, Verdict
from recon.modules import breach, dns_intel, github, ripestat
from recon.modules.base import ModuleContext

# robots.txt fetching would need its own mock; disable it for unit tests.
_NO_ROBOTS = dataclasses.replace(SETTINGS, respect_robots=False, per_host_min_interval=0.0)


async def _run_module(mod, art):
    findings, artifacts = [], []

    async def ef(f):
        findings.append(f)

    async def ea(a):
        artifacts.append(a)

    async with RateLimitedClient(_NO_ROBOTS) as client:
        ctx = ModuleContext(client=client, query=Query(), settings=SETTINGS,
                            in_scope=lambda a: True, _emit_finding=ef, _emit_artifact=ea)
        await mod.run(art, ctx)
    return findings, artifacts


@respx.mock
@pytest.mark.asyncio
async def test_ripestat_asn_emits_netblocks():
    respx.get(url__startswith="https://stat.ripe.net/data/announced-prefixes").mock(
        return_value=httpx.Response(200, json={"data": {"prefixes": [
            {"prefix": "104.20.16.0/20"}, {"prefix": "172.66.0.0/16"}]}}))

    findings, artifacts = await _run_module(ripestat.MODULE,
                                            Artifact.make(ArtifactType.ASN, "13335"))
    blocks = {a.value for a in artifacts if a.type == ArtifactType.NETBLOCK}
    assert blocks == {"104.20.16.0/20", "172.66.0.0/16"}
    assert findings[0].verdict == Verdict.FOUND


@pytest.mark.asyncio
async def test_dns_intel_parses_spf_into_artifacts(monkeypatch):
    # Monkeypatch the DNS helpers (offline) rather than mock a resolver.
    def fake_txt(name):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"]
        return ["v=spf1 include:_spf.google.com ip4:198.51.100.0/24 ip4:203.0.113.7 -all"]

    monkeypatch.setattr(dns_intel, "_txt", fake_txt)
    monkeypatch.setattr(dns_intel, "_records", lambda name, rtype: [])

    findings, artifacts = await _run_module(dns_intel.MODULE,
                                            Artifact.make(ArtifactType.DOMAIN, "example.com"))
    domains = {a.value for a in artifacts if a.type == ArtifactType.DOMAIN}
    ips = {a.value for a in artifacts if a.type == ArtifactType.IP_ADDRESS}
    blocks = {a.value for a in artifacts if a.type == ArtifactType.NETBLOCK}
    assert "_spf.google.com" in domains
    assert "203.0.113.7" in ips
    assert "198.51.100.0/24" in blocks
    assert any("DMARC policy p=reject" in r for f in findings for r in f.reasons)


@respx.mock
@pytest.mark.asyncio
async def test_github_harvests_commit_email():
    respx.get("https://api.github.com/users/octocat").mock(
        return_value=httpx.Response(200, json={
            "login": "octocat", "html_url": "https://github.com/octocat",
            "email": None, "blog": "", "public_repos": 8, "followers": 3}))
    respx.get("https://api.github.com/users/octocat/events/public").mock(
        return_value=httpx.Response(200, json=[
            {"payload": {"commits": [{"author": {"email": "dev@example.com"}},
                                     {"author": {"email": "1+x@users.noreply.github.com"}}]}}]))

    findings, artifacts = await _run_module(github.MODULE,
                                            Artifact.make(ArtifactType.USERNAME, "octocat"))
    emails = {a.value for a in artifacts if a.type == ArtifactType.EMAIL}
    assert "dev@example.com" in emails
    assert all("noreply.github.com" not in e for e in emails)  # noreply filtered
    observed = next(item for item in artifacts if item.value == "dev@example.com")
    assert observed.policy.candidate_only is True
    commit_finding = next(item for item in findings if item.source == "github:commits")
    assert commit_finding.policy.candidate_only is True
    assert "other people" in commit_finding.reasons[1]
    assert any(a.type == ArtifactType.ACCOUNT_PROFILE for a in artifacts)


@respx.mock
@pytest.mark.asyncio
async def test_breach_emits_breach_artifacts():
    respx.get(url__startswith="https://api.xposedornot.com/v1/check-email").mock(
        return_value=httpx.Response(200, json={"breaches": [["Adobe", "LinkedIn"]]}))

    findings, artifacts = await _run_module(breach.MODULE,
                                            Artifact.make(ArtifactType.EMAIL, "a@b.com"))
    breaches = {a.value for a in artifacts if a.type == ArtifactType.BREACH}
    assert breaches == {"Adobe", "LinkedIn"}
    assert findings[0].verdict == Verdict.FOUND
