"""The recursive engine: a seed cascades into deeper artifacts, and the frontier
dedups so the same artifact is never processed twice."""

import pytest

from recon import engine as engine_mod
from recon.engine import GraphScanEngine, ScanCancelled
from recon.graph_models import Artifact, ArtifactType
from recon.models import Finding, Query, Verdict
from recon.modules.base import Module


def _fake_registry(monkeypatch, calls):
    async def domain_run(art, ctx):
        for sub in ("a.example.com", "b.example.com"):
            await ctx.emit_artifact(Artifact.make(ArtifactType.SUBDOMAIN, sub,
                                                   parent=art, source_module="domain"))

    async def resolve_run(art, ctx):
        calls.setdefault("resolve", []).append(art.normalized)
        # Both subdomains resolve to the SAME ip -> the engine must dedup it.
        await ctx.emit_artifact(Artifact.make(ArtifactType.IP_ADDRESS, "1.1.1.1",
                                              parent=art, source_module="resolve"))

    async def asn_run(art, ctx):
        calls.setdefault("asn", []).append(art.normalized)
        await ctx.emit_finding(Finding(source="asn:fake", category="network",
                                        label="AS1", verdict=Verdict.FOUND, confidence=0.9))
        await ctx.emit_artifact(Artifact.make(ArtifactType.ASN, "1", parent=art,
                                              source_module="asn"))

    mods = [
        Module("domain", {ArtifactType.DOMAIN}, {ArtifactType.SUBDOMAIN}, domain_run, use_cache=False),
        Module("resolve", {ArtifactType.SUBDOMAIN}, {ArtifactType.IP_ADDRESS}, resolve_run, use_cache=False),
        Module("asn", {ArtifactType.IP_ADDRESS}, {ArtifactType.ASN}, asn_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])


async def _run(query, settings=None):
    eng = GraphScanEngine(query) if settings is None else GraphScanEngine(query, settings)
    events = [ev async for ev in eng.stream()]
    return eng, events


@pytest.mark.asyncio
async def test_engine_honors_durable_job_cancellation_before_collection():
    async def cancelled() -> bool:
        return True

    engine = GraphScanEngine(
        Query(username="alice"), cancellation_requested=cancelled
    )
    with pytest.raises(ScanCancelled, match="cancelled by user"):
        [event async for event in engine.stream()]
    assert engine.stop_reason == "cancelled by user"


@pytest.mark.asyncio
async def test_recursion_cascades_domain_to_asn(monkeypatch):
    calls = {}
    _fake_registry(monkeypatch, calls)
    eng, events = await _run(Query(domain="example.com"))

    types = {a.type for a in eng.artifacts}
    assert ArtifactType.SUBDOMAIN in types
    assert ArtifactType.IP_ADDRESS in types
    assert ArtifactType.ASN in types

    # The shared IP (1.1.1.1) reached from two subdomains is processed once.
    assert calls["asn"] == ["1.1.1.1"]
    # ...even though two subdomains both produced it.
    assert sorted(calls["resolve"]) == ["a.example.com", "b.example.com"]

    done = [e for e in events if e["type"] == "done"][0]
    assert done["artifacts"] == len(eng.artifacts)
    summary = next(e["summary"] for e in events if e["type"] == "summary")
    assert summary["profile"]["counts"]["artifacts"] == len(eng.artifacts)


@pytest.mark.asyncio
async def test_depths_increase_with_pivots(monkeypatch):
    calls = {}
    _fake_registry(monkeypatch, calls)
    eng, _ = await _run(Query(domain="example.com"))
    by_type = {a.type: a.depth for a in eng.artifacts}
    assert by_type[ArtifactType.DOMAIN] == 0
    assert by_type[ArtifactType.SUBDOMAIN] == 1
    assert by_type[ArtifactType.IP_ADDRESS] == 2
    assert by_type[ArtifactType.ASN] == 3
