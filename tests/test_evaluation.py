import json

import pytest
from fastapi.testclient import TestClient

from recon.evaluation import EvaluationDataset, evaluate_dataset, load_dataset, run_evaluation
from recon.models import Verdict
from recon.store import get_db, repo
from recon.server import app


def test_packaged_evaluation_is_functional_but_not_accuracy_evidence() -> None:
    report = run_evaluation()

    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["gate"]["status"] == "NEEDS_EVIDENCE"
    assert any("functional fixture" in reason for reason in report["gate"]["reasons"])
    assert report["dataset"]["sha256"]


def test_externally_verified_dataset_requires_audit_metadata() -> None:
    fixture, _digest = load_dataset()
    payload = fixture.model_dump(mode="json")
    payload["provenance"] = "externally_verified"

    with pytest.raises(ValueError, match="ground_truth_method"):
        EvaluationDataset.model_validate(payload)


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
