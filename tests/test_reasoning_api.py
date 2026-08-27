from fastapi.testclient import TestClient

from recon.models import Query
from recon.server import app
from recon.store import get_db, repo

client = TestClient(app)


def test_run_reasoning_endpoint_returns_persisted_plan() -> None:
    report = {
        "version": 1,
        "objective": "Corroborate confirmed evidence",
        "assessment": "One source confirmed the lead.",
        "confidence": 0.7,
        "evidence_state": {"findings": 1},
        "uncertainties": ["Independent corroboration is missing."],
        "next_actions": [],
        "decisions": [],
        "guardrails": ["Scope remained strict."],
    }
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="known-handle"))
        run = repo.create_run(session, target)
        repo.finish_run(session, run, "done", {"reasoning": report})
        run_id = run.id

    response = client.get(f"/api/runs/{run_id}/reasoning")

    assert response.status_code == 200
    assert response.json() == {"run_id": run_id, "reasoning": report}


def test_run_reasoning_endpoint_supports_older_runs() -> None:
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(domain="older.example"))
        run = repo.create_run(session, target)
        run_id = run.id

    assert client.get(f"/api/runs/{run_id}/reasoning").json() == {
        "run_id": run_id,
        "reasoning": None,
    }


def test_run_profile_endpoint_returns_persisted_synthesis() -> None:
    profile = {"version": 1, "status": "partial", "title": "known-handle"}
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="profile-subject"))
        run = repo.create_run(session, target)
        repo.finish_run(session, run, "done", {"profile": profile})
        run_id = run.id

    assert client.get(f"/api/runs/{run_id}/profile").json() == {
        "run_id": run_id,
        "profile": profile,
    }
