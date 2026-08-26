import datetime as dt
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from recon import governance
from recon.governance import (
    apply_retention,
    purge_target,
    review_observation,
    reviewed_calibration_labels,
    target_export,
)
from recon.models import Finding, Query, Verdict
from recon.server import app
from recon.store import get_db, repo
from recon.store import models_db as m

client = TestClient(app)


def _observation(session, username="review-subject"):
    target = repo.get_or_create_target(session, Query(username=username))
    run = repo.create_run(session, target)
    observation = repo.add_observation(
        session,
        run,
        Finding(
            source="username:GitHub",
            category="username",
            label=f"GitHub profile {username}",
            url=f"https://github.com/{username}",
            verdict=Verdict.UNCERTAIN,
            confidence=0.62,
            reasons=[f"candidate {username}"],
            signals={"username:github": username},
        ),
    )
    session.flush()
    return target, run, observation


def test_review_history_and_calibration_export_are_separate_from_verdict():
    with get_db().session() as session:
        _target, _run, observation = _observation(session)
        first = review_observation(session, observation.id, "unresolved", note="check")
        latest = review_observation(session, observation.id, "accepted", note="verified")
        observation_id = observation.id

    with get_db().session() as session:
        stored = session.get(m.Observation, observation_id)
        assert stored.verdict == "UNCERTAIN"
        assert [review.id for review in stored.reviews] == [first.id, latest.id]
        labels = reviewed_calibration_labels(session)
    assert labels[0]["present"] is True
    assert labels[0]["account"] == "review-subject"
    assert labels[0]["site"] == "GitHub"


def test_review_invalidates_the_pre_review_profile_snapshot():
    with get_db().session() as session:
        _target, run, observation = _observation(session, "profile-review")
        run.stats = {
            "profile": {
                "status": "corroborated",
                "confidence": 0.98,
                "assessment": "Old interpretation",
                "primary_identity": {"name": "Wrong Person"},
                "identifiers": [
                    {"type": "username", "value": "profile-review", "standing": "provided"},
                    {"type": "email", "value": "wrong@example.com", "standing": "confirmed"},
                ],
                "accounts": [{"label": "Wrong account"}],
            }
        }
        review_observation(session, observation.id, "rejected")
        run_id = run.id

    with get_db().session() as session:
        stored = session.get(m.Run, run_id)
        profile = stored.stats["profile"]
        assert stored.stats["interpretation_stale_after_review"] is True
        assert profile["status"] == "unresolved"
        assert profile["confidence"] == 0.0
        assert profile["accounts"] == []
        assert [item["standing"] for item in profile["identifiers"]] == ["provided"]


def test_review_api_roundtrip_and_missing_observation():
    with get_db().session() as session:
        _target, run, observation = _observation(session)
        run_id, observation_id = run.id, observation.id

    response = client.post(
        f"/api/observations/{observation_id}/review",
        json={"decision": "rejected", "note": "controlled absent", "reviewer": "analyst"},
    )
    assert response.status_code == 200
    body = client.get(f"/api/runs/{run_id}/observations").json()
    assert body["observations"][0]["review"]["decision"] == "rejected"
    missing = client.post(
        "/api/observations/999999/review",
        json={"decision": "accepted"},
    )
    assert missing.status_code == 404
    assert missing.json() == {"error": "observation not found"}


def test_governance_errors_do_not_expose_exception_details(monkeypatch):
    pair = client.post(
        "/api/pair-reviews",
        json={
            "left_observation_id": 999998,
            "right_observation_id": 999999,
            "same_identity": False,
            "verification_method": "manual review",
        },
    )
    assert pair.status_code == 400
    assert pair.json() == {"error": "invalid pair review"}

    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="error-test"))
        target_id = target.id

    original_export = governance.target_export

    def reject_export(*_args, **_kwargs):
        raise LookupError("sensitive export backend detail")

    monkeypatch.setattr(governance, "target_export", reject_export)
    exported = client.post(
        f"/api/targets/{target_id}/export",
        json={"redacted": True},
    )
    assert exported.status_code == 404
    assert exported.json() == {"error": "target not found"}
    assert "sensitive" not in exported.text

    monkeypatch.setattr(governance, "target_export", original_export)

    def reject_purge(*_args, **_kwargs):
        raise LookupError("sensitive purge backend detail")

    monkeypatch.setattr(governance, "purge_target", reject_purge)
    deleted = client.request(
        "DELETE",
        f"/api/targets/{target_id}",
        json={"confirm": True},
    )
    assert deleted.status_code == 404
    assert deleted.json() == {"error": "target not found"}
    assert "sensitive" not in deleted.text


def test_redacted_export_omits_investigation_content():
    with get_db().session() as session:
        target, _run, observation = _observation(session, "private-handle")
        review_observation(session, observation.id, "accepted", note="private note")
        payload = target_export(session, target.id, redacted=True)

    encoded = json.dumps(payload)
    assert "private-handle" not in encoded
    assert "private note" not in encoded
    assert payload["target"]["query"] == {"username": "[REDACTED]"}
    assert "signals" not in payload["observations"][0]


def test_export_api_is_post_only_and_audited():
    with get_db().session() as session:
        target, _run, _observation_row = _observation(session, "api-private")
        target_id = target.id
    assert client.get(f"/api/targets/{target_id}/export").status_code == 405
    response = client.post(
        f"/api/targets/{target_id}/export",
        json={"redacted": True, "actor": "exporter"},
    )
    assert response.status_code == 200
    assert "api-private" not in response.text
    audit = client.get("/api/audit").json()
    assert audit[0]["action"] == "target.exported"
    assert audit[0]["actor"] == "exporter"


def test_purge_removes_subject_graph_and_keeps_count_only_audit():
    with get_db().session() as session:
        target, _run, observation = _observation(session)
        review_observation(session, observation.id, "rejected")
        target_id = target.id
        deleted = purge_target(session, target_id, actor="privacy-officer")
        assert deleted["targets"] == 1

    with get_db().session() as session:
        assert session.get(m.Target, target_id) is None
        assert session.execute(select(m.Observation)).scalars().all() == []
        audit = session.execute(select(m.AuditEvent)).scalars().all()
        assert [event.action for event in audit] == ["target.purged"]
        assert "query" not in audit[0].detail


def test_retention_previews_then_deletes_inactive_targets():
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=120)
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="old-subject"))
        target.created_at = old
        target_id = target.id

    with get_db().session() as session:
        preview = apply_retention(session, 90, dry_run=True)
    assert preview["target_ids"] == [target_id]

    with get_db().session() as session:
        applied = apply_retention(session, 90, dry_run=False)
    assert applied["target_ids"] == [target_id]
    with get_db().session() as session:
        assert session.get(m.Target, target_id) is None


def test_delete_api_requires_explicit_confirmation():
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="delete-me"))
        target_id = target.id
    assert client.request("DELETE",
        f"/api/targets/{target_id}", json={"confirm": False}
    ).status_code == 400
    assert client.request("DELETE",
        f"/api/targets/{target_id}", json={"confirm": True}
    ).status_code == 200
