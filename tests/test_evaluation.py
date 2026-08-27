import json

import pytest
from fastapi.testclient import TestClient

from recon.evaluation import EvaluationDataset, evaluate_dataset, load_dataset, run_evaluation
from recon.models import Verdict
from recon.store import get_db, repo
from recon.server import app


def test_packaged_evaluation_is_functional_but_not_accuracy_evidence() -> None:
    report = run_evaluation()

    assert report["version"] == 2
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["gate"]["status"] == "NEEDS_EVIDENCE"
    assert any("functional fixture" in reason for reason in report["gate"]["reasons"])
    assert report["dataset"]["sha256"]


def test_externally_verified_dataset_requires_audit_metadata() -> None:
    fixture, _digest = load_dataset()
    payload = fixture.model_dump(mode="json")
    payload["provenance"] = "externally_verified"

    with pytest.raises(ValueError, match="subject group"):
        EvaluationDataset.model_validate(payload)


def test_operator_pilot_is_never_release_evidence() -> None:
    fixture, _digest = load_dataset()
    case = fixture.cases[0].model_copy(update={
        "subject_group": "operator-01",
        "ground_truth_method": "Checked against my own controlled account.",
        "verified_at": "2026-08-20",
        "authorization_basis": "self_owned",
        "reviewer_id": "operator",
        "reviewer_independent": False,
        "blind_review": False,
    })
    dataset = EvaluationDataset(
        name="Private operator pilot",
        provenance="operator_pilot",
        cases=[case],
    )

    report = evaluate_dataset(dataset)

    assert report["gate"]["status"] == "NEEDS_EVIDENCE"
    assert report["gate"]["sample_actual"]["subjects"] == 1
    assert any("not independent" in reason for reason in report["gate"]["reasons"])


def test_evaluation_detects_a_false_positive() -> None:
    dataset, _digest = load_dataset()
    case = dataset.cases[1].model_copy(deep=True)
    case.observed_findings[0].verdict = Verdict.FOUND
    reduced = dataset.model_copy(update={"cases": [case]})

    report = evaluate_dataset(reduced)

    assert report["metrics"]["false_positive_rate"] == 1.0
    assert report["metrics"]["precision"] == 0.0


def test_evaluation_penalizes_unexpected_positive_claims() -> None:
    dataset, _digest = load_dataset()
    case = dataset.cases[0].model_copy(deep=True)
    case.observed_findings.append(case.observed_findings[0].model_copy(update={
        "source": "unexpected:source",
        "label": "Unsupported identity",
    }))

    report = evaluate_dataset(dataset.model_copy(update={"cases": [case]}))

    assert report["metrics"]["precision"] == 0.5
    assert report["metrics"]["confusion"]["fp"] == 1
    assert report["sources"]["unexpected:source"]["precision"] == 0.0


def test_indeterminate_negative_does_not_count_as_a_true_negative() -> None:
    dataset, _digest = load_dataset()
    case = dataset.cases[1].model_copy(deep=True)
    case.observed_findings[0].verdict = Verdict.UNVERIFIABLE

    report = evaluate_dataset(dataset.model_copy(update={"cases": [case]}))

    assert report["metrics"]["negatives"] == 1
    assert report["metrics"]["confusion"]["tn"] == 0
    assert report["metrics"]["confusion"]["indeterminate"] == 1
    assert report["metrics"]["decision_coverage"] == 0.0


def test_evaluation_history_is_persisted() -> None:
    report = run_evaluation()
    with get_db().session() as session:
        saved = repo.save_evaluation(session, report)
        saved_id = saved.id

    with get_db().session() as session:
        rows = repo.list_evaluations(session)
        assert rows[0].id == saved_id
        assert rows[0].gate_status == "NEEDS_EVIDENCE"
        json.dumps(rows[0].report)

    response = TestClient(app).get("/api/evaluation")
    assert response.status_code == 200
    assert response.json()["latest"]["dataset"]["provenance"] == "functional_fixture"
