"""Evidence-backed profile synthesis keeps input, facts, and gaps distinct."""

import pytest

from recon import engine as engine_mod
from recon.evidence import EvidencePolicy
from recon.graph_models import Artifact, ArtifactType
from recon.identifiers import classify_input
from recon.models import Finding, Query, Verdict
from recon.profile import synthesize_profile
from recon.store import get_db
from recon.store import models_db as m


def test_profile_synthesizes_confirmed_identity_accounts_and_coverage() -> None:
    query = Query(username="alice")
    findings = [
        Finding(
            source="github:user",
            category="username",
            label="GitHub: alice",
            url="https://github.com/alice",
            verdict=Verdict.FOUND,
            confidence=0.9,
            signals={"username:github": "alice", "email": "alice@example.com"},
            data={"name": "Alice Example", "company": "Example Org", "followers": 12},
        ),
        Finding(
            source="email:gravatar",
            category="email",
            label="Gravatar",
            verdict=Verdict.FOUND,
            confidence=0.85,
            signals={"email": "alice@example.com", "gravatar_hash": "abc"},
        ),
    ]
    summary = {
        "identities": 1,
        "clusters": [
            {
                "id": 7,
                "label": "Alice Example",
                "score": 0.91,
                "confidence_shadow": 0.88,
                "signals": {
                    "username": ["alice"],
                    "email": ["alice@example.com"],
                    "gravatar_hash": ["abc"],
                },
                "flags": [],
                "sources": ["github:user", "email:gravatar"],
                "corroboration": {"independent_classes": 2, "label": "corroborated"},
            }
        ],
    }
    artifacts = [
        Artifact.make(ArtifactType.USERNAME, "alice"),
        Artifact.make(ArtifactType.EMAIL, "alice@example.com"),
    ]

    profile = synthesize_profile(query, findings, artifacts, summary)

    assert profile["status"] == "corroborated"
    assert profile["primary_identity"]["id"] == 7
    assert any(
        row["type"] == "email" and row["standing"] == "confirmed" for row in profile["identifiers"]
    )
    assert profile["accounts"][0]["url"] == "https://github.com/alice"
    assert any(row["name"] == "company" for row in profile["details"]["identity"])
    assert {row["id"]: row["state"] for row in profile["coverage"]}["accounts"] == "confirmed"
    assert profile["complete"] is False


def test_empty_evidence_returns_unresolved_profile_not_a_false_negative() -> None:
    profile = synthesize_profile(Query(username="unknown"), [], [], {"clusters": []})

    assert profile["status"] == "unresolved"
    assert profile["confidence"] == 0
    assert profile["identifiers"][0]["standing"] == "provided"
    assert "did not establish" in profile["assessment"]
    assert profile["gaps"]


def test_phone_allocation_metadata_is_context_not_identity_confirmation() -> None:
    metadata = Finding(
        source="phone:validate",
        category="phone",
        label="Phone metadata",
        verdict=Verdict.FOUND,
        confidence=0.85,
        signals={"phone_e164": "+14155552671"},
        data={"e164": "+14155552671", "region_code": "US", "line_type": "mobile"},
        policy=EvidencePolicy(confirmation_allowed=False, pivot_allowed=False),
    )

    profile = synthesize_profile(
        Query(phone="+14155552671"),
        [metadata],
        [Artifact.make(ArtifactType.PHONE, "+14155552671")],
        {"clusters": []},
    )

    contact = next(item for item in profile["coverage"] if item["id"] == "contact")
    assert profile["status"] == "unresolved"
    assert profile["counts"]["confirmed_findings"] == 0
    assert contact["state"] == "observed"
    assert profile["phone_research"]["decision"]["status"] == "bounded_check_complete"


@pytest.mark.asyncio
async def test_durable_scan_persists_the_same_intake_and_profile(monkeypatch) -> None:
    from recon.orchestrator import scan

    monkeypatch.setattr(engine_mod, "applicable_modules", lambda _artifact: [])
    intake = classify_input("@Alice").model_dump(mode="json")

    result = await scan(Query(username="alice"), intake=intake)

    assert result["summary"]["profile"]["intake"] == intake
    with get_db().session() as session:
        run = session.get(m.Run, result["run_id"])
        assert run.status == "done"
        assert run.stats["profile"] == result["summary"]["profile"]
        assert run.stats["intake"] == intake
        assert "summary" not in run.stats
