import csv
from datetime import date

import pytest
from fastapi.testclient import TestClient

from recon.evaluation import EvaluationDataset, evaluate_dataset
from recon.evaluation_corpus import (
    capture_run,
    create_kit,
    finalize_kit,
    load_kit,
    review_sheet,
)
from recon.models import Finding, Query, Verdict
from recon.server import app
from recon.store import get_db, repo


def _completed_run() -> int:
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="review-subject"))
        run = repo.create_run(session, target)
        repo.add_observation(session, run, Finding(
            source="username:Example",
            category="username",
            label="Example profile",
            url="https://example.test/review-subject",
            verdict=Verdict.FOUND,
            confidence=0.91,
            reasons=["The profile was directly verified."],
            signals={"username": "review-subject"},
        ))
        repo.finish_run(session, run, "done", {})
        return run.id


def _complete_review(sheet, *, independent: bool = True) -> None:
    with sheet.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
        fields = list(rows[0])
    for row in rows:
        row.update({
            "expected_verdict": "FOUND",
            "expected_profile_status": "partial",
            "required_actions": "corroborate-findings",
            "expected_stop_code": "authorized_frontier_exhausted",
            "ground_truth_method": "Verified directly with the controlled account owner.",
            "verified_at": date.today().isoformat(),
            "reviewer_id": "external-reviewer-01" if independent else "operator",
            "reviewer_independent": "true" if independent else "false",
        })
    with sheet.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_private_review_kit_hides_specter_decisions_and_finalizes(tmp_path) -> None:
    kit_path = tmp_path / "private-kit.json"
    sheet_path = tmp_path / "blind-review.csv"
    dataset_path = tmp_path / "reviewed-dataset.json"
    create_kit(kit_path, "Independent review")
    captured = capture_run(
        kit_path,
        run_id=_completed_run(),
        case_id="username-positive-01",
        subject_group="subject-01",
        category="username",
        authorization_basis="controlled_test_asset",
    )

    assert len(captured.review_claims) == 1
    review_sheet(kit_path, sheet_path)
    sheet_text = sheet_path.read_text(encoding="utf-8")
    assert "The profile was directly verified" not in sheet_text
    assert ",FOUND," not in sheet_text
    assert "0.91" not in sheet_text

    _complete_review(sheet_path)
    dataset = finalize_kit(kit_path, sheet_path, dataset_path)
    report = evaluate_dataset(dataset)

    assert dataset.provenance == "externally_verified"
    assert dataset.cases[0].blind_review is True
    assert dataset.cases[0].reviewer_independent is True
    assert dataset.cases[0].subject_group == "subject-01"
    assert report["metrics"]["precision"] == 1.0
    assert report["dataset"]["evaluation_mode"] == "frozen_snapshot"
    assert load_kit(kit_path).cases[0].source_run_id == captured.source_run_id


def test_finalization_rejects_a_non_independent_review(tmp_path) -> None:
    kit_path = tmp_path / "private-kit.json"
    sheet_path = tmp_path / "blind-review.csv"
    create_kit(kit_path, "Independent review")
    capture_run(
        kit_path,
        run_id=_completed_run(),
        case_id="username-positive-01",
        subject_group="subject-01",
        category="username",
        authorization_basis="controlled_test_asset",
    )
    review_sheet(kit_path, sheet_path)
    _complete_review(sheet_path)
    text = sheet_path.read_text(encoding="utf-8").replace(
        "external-reviewer-01,true", "external-reviewer-01,false"
    )
    sheet_path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="independent"):
        finalize_kit(kit_path, sheet_path, tmp_path / "dataset.json")


def test_external_dataset_cannot_self_assert_review_metadata() -> None:
    with pytest.raises(ValueError, match="independent blind review"):
        EvaluationDataset.model_validate({
            "name": "Invalid external dataset",
            "provenance": "externally_verified",
            "cases": [{
                "id": "case-1",
                "subject_group": "subject-01",
                "category": "username",
                "query": {"username": "example"},
                "observed_findings": [],
                "expected_claims": [],
                "expected_profile_status": "unresolved",
                "ground_truth_method": "Copied from the tool output",
                "verified_at": date.today().isoformat(),
                "authorization_basis": "self_owned",
                "reviewer_id": "operator",
            }],
        })


def test_local_api_builds_and_records_an_independent_review_set(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "specter-data"))
    client = TestClient(app)
    run_id = _completed_run()

    created = client.post("/api/evaluation-kit", json={
        "name": "API review set",
        "description": "Authorized controlled cases",
        "review_mode": "independent",
    })
    assert created.status_code == 201
    captured = client.post("/api/evaluation-kit/cases", json={
        "run_id": run_id,
        "case_id": "username-positive-01",
        "subject_group": "subject-01",
        "category": "username",
        "authorization_basis": "controlled_test_asset",
    })
    assert captured.status_code == 201
    assert captured.json()["claims"] == 1

    sheet_response = client.get("/api/evaluation-kit/review-sheet")
    assert sheet_response.status_code == 200
    assert ",FOUND," not in sheet_response.text
    sheet = tmp_path / "review.csv"
    sheet.write_text(sheet_response.text, encoding="utf-8")
    _complete_review(sheet)

    finalized = client.post("/api/evaluation-kit/finalize", json={
        "review_csv": sheet.read_text(encoding="utf-8"),
    })
    assert finalized.status_code == 200
    assert finalized.json()["dataset"]["provenance"] == "externally_verified"
    assert finalized.json()["gate"]["status"] == "NEEDS_EVIDENCE"


def test_operator_pilot_groups_related_clues_and_cannot_unlock_readiness(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "specter-data"))
    client = TestClient(app)

    created = client.post("/api/evaluation-kit", json={
        "name": "My private self-check",
        "review_mode": "operator_pilot",
    })
    assert created.status_code == 201
    assert created.json()["review_mode"] == "operator_pilot"
    captured = client.post("/api/evaluation-kit/cases", json={
        "run_id": _completed_run(),
        "case_id": "username-check-01",
        "subject_group": "me",
        "category": "username",
        "authorization_basis": "self_owned",
    })
    assert captured.status_code == 201
    assert captured.json()["subjects"] == 1

    sheet_response = client.get("/api/evaluation-kit/review-sheet")
    assert sheet_response.status_code == 200
    assert "reviewer_independent" in sheet_response.text
    sheet = tmp_path / "self-check.csv"
    sheet.write_text(sheet_response.text, encoding="utf-8")
    _complete_review(sheet, independent=False)

    finalized = client.post("/api/evaluation-kit/finalize", json={
        "review_csv": sheet.read_text(encoding="utf-8"),
    })
    assert finalized.status_code == 200
    body = finalized.json()
    assert body["dataset"]["provenance"] == "operator_pilot"
    assert body["gate"]["status"] == "NEEDS_EVIDENCE"
    assert body["gate"]["sample_actual"]["subjects"] == 1
    assert any("not independent" in reason for reason in body["gate"]["reasons"])
