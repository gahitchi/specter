"""Phase 6a: efficient traversal.

Covers (1) the honest request budget — measured in real outbound requests
counted by the client, not module dispatches — and (2) the priority frontier
that expands high-yield leads before low-value breadcrumbs when the budget is
tight.
"""

import dataclasses

import httpx
import pytest
import respx

from recon import engine as engine_mod
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.http_client import RateLimitedClient, RequestBudgetExceeded
from recon.models import Query
from recon.modules.base import Module

_FAST = dataclasses.replace(SETTINGS, respect_robots=False, per_host_min_interval=0.0)


# --------------------------------------------------------------- priority key

def test_priority_orders_identity_types_above_breadcrumbs():
    p = GraphScanEngine._priority
    email = Artifact.make(ArtifactType.EMAIL, "a@b.com")
    ip = Artifact.make(ArtifactType.IP_ADDRESS, "1.1.1.1")
    name = Artifact.make(ArtifactType.NAME, "Jane Doe")
    # EMAIL (identity-bearing) outranks an IP, which outranks a bare NAME.
    assert p(email) > p(ip) > p(name)


def test_priority_breaks_ties_on_confidence_then_depth():
    p = GraphScanEngine._priority
    seed = Artifact.make(ArtifactType.DOMAIN, "example.com")
    hi = Artifact.make(ArtifactType.SUBDOMAIN, "a.example.com", parent=seed, confidence=0.9)
    lo = Artifact.make(ArtifactType.SUBDOMAIN, "b.example.com", parent=seed, confidence=0.3)
    assert p(hi) > p(lo)  # same type + depth -> higher confidence wins


# ---------------------------------------------------------- real-request count

@respx.mock
@pytest.mark.asyncio
async def test_client_counts_real_requests():
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    async with RateLimitedClient(_FAST) as client:
        assert client.request_count == 0
        await client.fetch("https://example.com/a")
        await client.fetch("https://example.com/b")
        assert client.request_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_client_enforces_hard_budget_without_overshoot():
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    settings = dataclasses.replace(_FAST, max_requests=2)
    async with RateLimitedClient(settings) as client:
        await client.fetch("https://example.com/a")
        await client.fetch("https://example.com/b")
        with pytest.raises(RequestBudgetExceeded):
            await client.fetch("https://example.com/c")
        assert client.request_count == 2
        assert client.budget_exhausted is True


@respx.mock
@pytest.mark.asyncio
async def test_robots_and_redirects_count_as_outbound_requests():
    settings = dataclasses.replace(
        _FAST, respect_robots=True, max_requests=4, max_redirects=2
    )
    respx.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nAllow: /")
    )
    respx.get("https://example.com/start").mock(
        return_value=httpx.Response(302, headers={"Location": "/final"})
    )
    respx.get("https://example.com/final").mock(
        return_value=httpx.Response(200, text="done")
    )
    async with RateLimitedClient(settings) as client:
        response = await client.fetch("https://example.com/start")
        assert response.text == "done"
        assert len(response.history) == 1
        assert client.request_count == 3


@respx.mock
@pytest.mark.asyncio
async def test_client_caps_response_body_while_streaming():
    respx.get("https://example.com/large").mock(
        return_value=httpx.Response(200, text="x" * 100)
    )
    settings = dataclasses.replace(_FAST, max_body_bytes=16)
    async with RateLimitedClient(settings) as client:
        response = await client.fetch("https://example.com/large")
        assert response.text == "x" * 16
        assert response.headers["x-recon-body-truncated"] == "1"


@respx.mock
@pytest.mark.parametrize(
    "target",
    ["https://elsewhere.example/final", "http://api.example/final"],
)
@pytest.mark.asyncio
async def test_cross_origin_redirect_does_not_forward_caller_headers(target):
    start = respx.get("https://api.example/start").mock(
        return_value=httpx.Response(302, headers={"Location": target})
    )
    final = respx.get(target).mock(
        return_value=httpx.Response(200, text="done")
    )
    async with RateLimitedClient(_FAST) as client:
        response = await client.fetch(
            "https://api.example/start", headers={"Authorization": "Bearer secret"}
        )

    assert response.text == "done"
    assert start.calls[0].request.headers["Authorization"] == "Bearer secret"
    assert "Authorization" not in final.calls[0].request.headers


@pytest.mark.asyncio
async def test_client_rejects_unsafe_urls_before_network():
    async with RateLimitedClient(_FAST) as client:
        with pytest.raises(ValueError):
            await client.fetch("file:///etc/passwd")
        with pytest.raises(ValueError):
            await client.fetch("https://user:pass@example.com/")
        with pytest.raises(ValueError):
            await client.fetch("https://127.0.0.1/private")
        with pytest.raises(ValueError):
            await client.fetch("https://metadata.local/private")
        assert client.request_count == 0


# ----------------------------------------------------- budget halts expansion

@respx.mock
@pytest.mark.asyncio
async def test_request_budget_counts_fetches_and_halts_next_wave(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    calls = {"resolve": []}

    async def domain_run(art, ctx):
        # Three *real* requests in a single module dispatch.
        for i in range(3):
            await ctx.client.fetch(f"https://h{i}.example.com/")
        await ctx.emit_artifact(Artifact.make(ArtifactType.SUBDOMAIN, "a.example.com",
                                              parent=art, source_module="domain"))

    async def resolve_run(art, ctx):
        calls["resolve"].append(art.normalized)

    mods = [
        Module("domain", {ArtifactType.DOMAIN}, {ArtifactType.SUBDOMAIN}, domain_run, use_cache=False),
        Module("resolve", {ArtifactType.SUBDOMAIN}, set(), resolve_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])

    # Budget of 2 real requests: the third request is rejected before transport,
    # so the resolve wave never starts and the ceiling is never exceeded.
    settings = dataclasses.replace(_FAST, max_requests=2)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    [ev async for ev in eng.stream()]

    assert calls["resolve"] == []                       # next wave halted
    assert eng.stop_reason == "max_requests reached"


@respx.mock
@pytest.mark.asyncio
async def test_high_priority_lead_expands_before_low_when_budget_tight(monkeypatch):
    """Within one wave, a tight budget must spend itself on the EMAIL lead
    (high priority) and skip the IP breadcrumb (low priority)."""
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    expanded = []

    async def seed_run(art, ctx):
        # Emit one low-value and one high-value lead in the same wave.
        await ctx.emit_artifact(Artifact.make(ArtifactType.IP_ADDRESS, "9.9.9.9",
                                              parent=art, source_module="seed_mod"))
        await ctx.emit_artifact(Artifact.make(ArtifactType.EMAIL, "found@example.com",
                                              parent=art, source_module="seed_mod"))

    async def ip_run(art, ctx):
        expanded.append("ip")
        await ctx.client.fetch("https://ip.example.com/")

    async def email_run(art, ctx):
        expanded.append("email")
        await ctx.client.fetch("https://email.example.com/")

    mods = [
        Module("seed_mod", {ArtifactType.DOMAIN}, set(), seed_run, use_cache=False),
        Module("ip_mod", {ArtifactType.IP_ADDRESS}, set(), ip_run, use_cache=False),
        Module("email_mod", {ArtifactType.EMAIL}, set(), email_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])

    # The seed module makes no request, so the second wave starts with budget
    # fully intact. max_concurrency=1 -> one dispatch per batch; max_requests=1
    # leaves room for exactly one of the two leads. Priority must spend it on
    # the EMAIL and skip the IP.
    settings = dataclasses.replace(_FAST, max_requests=1, max_concurrency=1)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    [ev async for ev in eng.stream()]

    assert expanded == ["email"]                        # high-yield lead won the budget
    assert eng.stop_reason == "max_requests reached"
