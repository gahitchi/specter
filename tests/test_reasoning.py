from types import SimpleNamespace

import pytest

from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.models import Finding, Query, Verdict
from recon.reasoning import InvestigationReasoner


def _finding(verdict: Verdict, source: str = "source:test", confidence: float = 0.8) -> Finding:
    return Finding(
        source=source,
        category="username",
        label=source,
        verdict=verdict,
        confidence=confidence,
    )


def _report(
    findings: list[Finding],
    *,
    independent_classes: int = 0,
    stop_reason: str | None = None,
    out_of_scope: list[Artifact] | None = None,
) -> dict:
    summary = {
        "clusters": [
            {"id": 0, "flags": [], "corroboration": {"independent_classes": independent_classes}}
        ] if findings else []
    }
    return InvestigationReasoner().report(
        Query(username="known-handle"),
        findings,
        [Artifact.make(ArtifactType.USERNAME, "known-handle")],
        summary,
        stop_reason=stop_reason,
        scope_mode="strict",
        passive_only=True,
        out_of_scope=out_of_scope or [],
    )


def test_reasoning_requests_better_input_and_source_recovery() -> None:
    report = _report([_finding(Verdict.ERROR)])
    actions = {action["id"]: action for action in report["next_actions"]}

    assert report["objective"] == "Recover evidence coverage"
    assert {"refine-identifiers", "retry-degraded-sources"} <= set(actions)
    assert actions["retry-degraded-sources"]["status"] == "blocked"
    assert "Only passive collection was allowed." in report["guardrails"]


def test_reasoning_seeks_corroboration_for_single_class_evidence() -> None:
    report = _report([_finding(Verdict.FOUND)], independent_classes=1)
    actions = {action["id"]: action for action in report["next_actions"]}

    assert report["assessment"].endswith("corroboration is still limited.")
    assert actions["corroborate-findings"]["execution"] == "automatic"
    assert actions["corroborate-findings"]["status"] == "blocked"
    assert "monitor-confirmed-evidence" not in actions


def test_reasoning_recommends_monitoring_only_after_corroboration() -> None:
    report = _report(
        [_finding(Verdict.FOUND, "source:a"), _finding(Verdict.FOUND, "source:b")],
        independent_classes=2,
    )
    actions = {action["id"]: action for action in report["next_actions"]}

    assert report["confidence"] > 0.5
    assert "monitor-confirmed-evidence" in actions
    assert "corroborate-findings" not in actions


def test_reasoning_never_expands_scope_or_budget_silently() -> None:
    external = Artifact.make(ArtifactType.DOMAIN, "external.example")
    report = _report(
        [_finding(Verdict.FOUND)],
        independent_classes=1,
        stop_reason="max_requests reached",
        out_of_scope=[external],
    )
    actions = {action["id"]: action for action in report["next_actions"]}

    assert actions["continue-bounded-scan"]["execution"] == "approval"
    assert actions["review-scope-pivots"]["execution"] == "approval"


def test_dispatch_ranking_prefers_novel_reliable_identity_evidence() -> None:
    reasoner = InvestigationReasoner()
    artifact = Artifact.make(ArtifactType.USERNAME, "known-handle")
    low_value = SimpleNamespace(
        name="low-value", reliability_prior=0.2, produces=set()
    )
    identity = SimpleNamespace(
        name="identity", reliability_prior=0.9, produces={ArtifactType.EMAIL}
    )

    ranked = reasoner.rank_dispatches(
        [artifact],
        [(artifact, low_value), (artifact, identity)],
        [],
        [artifact],
        50,
    )

    assert ranked[0][1].name == "identity"
    assert reasoner.decisions[0]["prioritized"][0]["module"] == "identity"


@pytest.mark.asyncio
async def test_engine_stream_emits_reasoning_before_done(monkeypatch) -> None:
    from recon.modules import registry

    monkeypatch.setattr(registry, "MODULES", [])
    engine = GraphScanEngine(Query(username="known-handle"), SETTINGS)

    events = [event async for event in engine.stream()]
    types = [event["type"] for event in events]

    assert types[-3:] == ["summary", "reasoning", "done"]
    report = next(event["reasoning"] for event in events if event["type"] == "reasoning")
    assert report["next_actions"][0]["id"] == "refine-identifiers"
