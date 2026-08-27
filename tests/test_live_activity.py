"""Regression coverage for the live investigation activity stream."""

import asyncio
import dataclasses
import hashlib

import httpx
import pytest
import respx

from recon import engine as engine_mod
from recon.activity import ACTIVE_PROCESS_ID, safe_display_url
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import ArtifactType
from recon.http_client import RateLimitedClient
from recon.models import Finding, Query, Verdict
from recon.modules.base import Module

_FAST = dataclasses.replace(
    SETTINGS,
    respect_robots=False,
    per_host_min_interval=0.0,
    max_concurrency=1,
)


def test_display_url_redacts_credentials_and_drops_fragments() -> None:
    url = safe_display_url(
        "https://api.example/search?token=first&visible=yes#private",
        {"api_key": "second", "q": "alice"},
    )

    assert url.startswith("https://api.example/search?")
    assert "first" not in url
    assert "second" not in url
    assert "visible=yes" in url
    assert "q=alice" in url
    assert "private" not in url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "outcome"),
    [(200, "success"), (302, "success"), (403, "uncertain"),
     (404, "not_found"), (500, "error")],
)
@respx.mock
async def test_client_reports_request_lifecycle(status_code: int, outcome: str) -> None:
    events = []

    async def capture(activity: dict) -> None:
        events.append(activity)

    respx.get("https://api.example/search").mock(
        return_value=httpx.Response(status_code, text="result")
    )
    process_token = ACTIVE_PROCESS_ID.set("process:7")
    try:
        async with RateLimitedClient(_FAST, activity_callback=capture) as client:
            await client.fetch(
                "https://api.example/search",
                params={"api_key": "do-not-display", "q": "alice"},
            )
    finally:
        ACTIVE_PROCESS_ID.reset(process_token)

    assert [event["phase"] for event in events] == ["started", "finished"]
    assert events[0]["id"] == events[1]["id"] == "request:1"
    assert events[0]["parent_id"] == "process:7"
    assert events[1]["outcome"] == outcome
    assert events[1]["status_code"] == status_code
    assert "do-not-display" not in events[0]["url"]
    assert "q=alice" in events[0]["url"]
    receipt = client.latest_evidence("process:7")
    assert receipt["content_sha256"] == hashlib.sha256(b"result").hexdigest()
    assert receipt["content_bytes"] == len(b"result")
    assert receipt["final_url"].startswith("https://api.example/search?")
    assert "do-not-display" not in receipt["final_url"]
    assert "q=alice" in receipt["final_url"]


@pytest.mark.asyncio
@respx.mock
async def test_engine_streams_a_causal_execution_graph(monkeypatch) -> None:
    async def lookup(artifact, ctx) -> None:
        response = await ctx.client.fetch("https://profiles.example/alice")
        assert response.status_code == 404
        await ctx.emit_finding(Finding(
            source="profiles",
            category="username",
            label=artifact.value,
            url="https://profiles.example/alice",
            verdict=Verdict.NOT_FOUND,
            confidence=0.98,
            reasons=["profile absent"],
        ))

    module = Module(
        "profiles",
        {ArtifactType.USERNAME},
        set(),
        lookup,
        use_cache=False,
    )
    monkeypatch.setattr(
        engine_mod,
        "applicable_modules",
        lambda artifact: [module] if module.accepts(artifact) else [],
    )
    respx.get("https://profiles.example/alice").mock(
        return_value=httpx.Response(404, text="missing")
    )

    events = [
        event async for event in GraphScanEngine(
            Query(username="alice"), _FAST
        ).stream()
    ]
    activities = [event["activity"] for event in events if event["type"] == "activity"]

    assert [activity["sequence"] for activity in activities] == list(
        range(1, len(activities) + 1)
    )
    seed = next(activity for activity in activities if activity["phase"] == "seeded")
    process_started = next(
        activity for activity in activities
        if activity["kind"] == "process" and activity["phase"] == "started"
    )
    request_finished = next(
        activity for activity in activities
        if activity["kind"] == "request" and activity["phase"] == "finished"
    )
    finding = next(activity for activity in activities if activity["kind"] == "finding")
    process_finished = next(
        activity for activity in activities
        if activity["kind"] == "process" and activity["phase"] == "finished"
    )

    assert process_started["parent_id"] == seed["id"]
    assert request_finished["parent_id"] == process_started["id"]
    assert finding["parent_id"] == process_started["id"]
    assert request_finished["outcome"] == "not_found"
    assert finding["outcome"] == "not_found"
    assert process_finished["id"] == process_started["id"]
    assert process_finished["outcome"] == "not_found"
    assert events[-1]["type"] == "done"


@pytest.mark.asyncio
async def test_worker_failure_terminates_the_stream(monkeypatch) -> None:
    def broken_registry(_artifact):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(engine_mod, "applicable_modules", broken_registry)

    async def collect() -> list[dict]:
        return [
            event async for event in GraphScanEngine(
                Query(username="alice"), _FAST
            ).stream()
        ]

    events = await asyncio.wait_for(collect(), timeout=2)

    assert any(
        event["type"] == "error" and "registry unavailable" in event["message"]
        for event in events
    )
    assert events[-1]["type"] == "error"
    assert not any(event["type"] == "done" for event in events)
