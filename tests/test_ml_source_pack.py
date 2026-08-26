import json

import pytest

from recon.ml_identity import FEATURE_NAMES, load_model, pair_features, review_pair, train
from recon.models import Finding, Query, Verdict
from recon.source_pack import validate
from recon.store import get_db, repo
from recon.store import models_db as m


def _model_payload():
    return {
        "schema": 1,
        "kind": "review-assist-logistic-regression",
        "features": list(FEATURE_NAMES),
        "decision_threshold": 0.8,
        "scaler": {"mean": [0.0] * len(FEATURE_NAMES), "scale": [1.0] * len(FEATURE_NAMES)},
        "model": {"intercept": -2.0, "coefficients": [1.0] + [0.0] * (len(FEATURE_NAMES) - 1)},
        "metrics": {"precision": 1.0, "false_positive_rate": 0.0, "ece": 0.05},
        "activation_eligible": True,
    }


def test_identity_model_is_json_and_explains_prediction(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(_model_payload()), encoding="utf-8")
    model = load_model(path)
    result = model.predict({"heuristic_weight": 5.0})
    assert result["probability"] > 0.8
    assert result["suggest_same_identity"] is True
    assert result["top_contributions"][0]["feature"] == "heuristic_weight"


def test_identity_model_rejects_ineligible_artifact(tmp_path):
    payload = _model_payload()
    payload["activation_eligible"] = False
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="activation thresholds"):
        load_model(path)


@pytest.mark.parametrize(
    ("metric", "value"),
    [("precision", 0.98), ("false_positive_rate", 0.02), ("ece", 0.11)],
)
def test_identity_model_rechecks_current_activation_policy(tmp_path, metric, value):
    payload = _model_payload()
    payload["metrics"][metric] = value
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="activation thresholds"):
        load_model(path)


def test_pair_review_captures_features_and_independent_method():
    db = get_db()
    with db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        run = repo.create_run(session, target)
        left = repo.add_observation(session, run, Finding(
            source="one", category="username", label="alice", verdict=Verdict.FOUND,
            confidence=0.8, signals={"username:one": "alice"},
        ))
        right = repo.add_observation(session, run, Finding(
            source="two", category="username", label="alice", verdict=Verdict.FOUND,
            confidence=0.9, signals={"username:two": "alice"},
        ))
        session.flush()
        features = pair_features(left, right)
        assert features["shared_username"] == 1.0
        row = review_pair(
            session, left.id, right.id, True, reviewer="reviewer",
            verification_method="verified against independent account records",
        )
        assert row.features["shared_username"] == 1.0
        with pytest.raises(ValueError, match="verification method"):
            review_pair(
                session, left.id, right.id, True, reviewer="reviewer",
                verification_method="web",
            )


def test_source_pack_accepts_https_and_reports_insecure_entries():
    sites = [
        {"name": f"Site {index}", "uri_check": f"https://s{index}.example/u/{{account}}",
         "error_type": "status_code", "error_code": 404}
        for index in range(25)
    ]
    sites.append({"name": "Insecure", "uri_check": "http://bad.example/{account}",
                  "error_type": "status_code", "error_code": 404})
    sites.append({"name": "Private", "uri_check": "https://127.0.0.1/{account}",
                  "error_type": "status_code", "error_code": 404})
    sanitized, manifest = validate(json.dumps({"sites": sites}).encode())
    assert len(sanitized["sites"]) == 25
    assert manifest["accepted"] == 25
    assert manifest["rejected"] == 2
    reasons = " ".join(item["reason"] for item in manifest["rejections"])
    assert "HTTPS" in reasons
    assert "non-public IP" in reasons


def test_training_uses_latest_reviewed_pairs_and_writes_portable_json(tmp_path):
    db = get_db()
    with db.session() as session:
        target = repo.get_or_create_target(session, Query(username="training-fixture"))
        run = repo.create_run(session, target)
        observations = []
        for index in range(101):
            observation = repo.add_observation(session, run, Finding(
                source=f"fixture:{index}", category="username", label=f"account-{index}",
                verdict=Verdict.FOUND, confidence=0.8, signals={},
            ))
            observations.append(observation)
        session.flush()
        for index in range(100):
            same = index < 50
            features = {name: 0.0 for name in FEATURE_NAMES}
            features.update({
                "heuristic_weight": 8.0 if same else -5.0,
                "shared_strong": 1.0 if same else 0.0,
                "conflicting_strong": 0.0 if same else 1.0,
                "confidence_mean": 0.8,
                "reliability_mean": 0.7,
            })
            session.add(m.EntityPairReview(
                left_observation_id=observations[index].id,
                right_observation_id=observations[index + 1].id,
                same_identity=same,
                reviewer="fixture",
                verification_method="independent deterministic test fixture",
                features=features,
            ))
        session.flush()
        result = train(session, tmp_path / "trained.json")

    assert result["labels"] == {"n": 100, "positives": 50, "negatives": 50}
    assert result["metrics"]["false_positive_rate"] == 0.0
    assert result["activation_eligible"] is True
    loaded = load_model(tmp_path / "trained.json")
    assert loaded.payload["kind"] == "review-assist-logistic-regression"
