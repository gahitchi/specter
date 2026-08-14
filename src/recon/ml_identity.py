"""Reviewed-label-trained identity suggestions; never performs an automatic merge."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

import jellyfish
from sqlalchemy import select

from .correlate.resolver import Record, record_from, score as heuristic_score
from .store import models_db as m

FEATURE_NAMES = (
    "heuristic_weight",
    "shared_strong",
    "conflicting_strong",
    "shared_email",
    "shared_username",
    "name_similarity",
    "confidence_mean",
    "reliability_mean",
    "same_source",
)
MODEL_SCHEMA = 1
MIN_LABELS = 100
MIN_CLASS = 20


def _record(observation: m.Observation) -> Record:
    return record_from(
        observation.id, observation.category, observation.label, observation.signals or {}
    )


def pair_features(left: m.Observation, right: m.Observation) -> dict[str, float]:
    a, b = _record(left), _record(right)
    weight, _ = heuristic_score(a, b)
    shared_strong = 0
    conflicting_strong = 0
    for key in set(a.strong) | set(b.strong):
        av, bv = a.strong.get(key, set()), b.strong.get(key, set())
        if av and bv:
            if av & bv:
                shared_strong += 1
            else:
                conflicting_strong += 1
    name_similarity = 0.0
    if a.names and b.names:
        name_similarity = max(
            jellyfish.jaro_winkler_similarity(x, y) for x in a.names for y in b.names
        )
    return {
        "heuristic_weight": float(weight),
        "shared_strong": float(shared_strong),
        "conflicting_strong": float(conflicting_strong),
        "shared_email": float(bool(a.emails & b.emails)),
        "shared_username": float(bool(a.usernames & b.usernames)),
        "name_similarity": float(name_similarity),
        "confidence_mean": float((left.confidence + right.confidence) / 2),
        "reliability_mean": float((left.reliability + right.reliability) / 2),
        "same_source": float(left.source == right.source),
    }


def review_pair(
    session,
    left_observation_id: int,
    right_observation_id: int,
    same_identity: bool,
    *,
    reviewer: str,
    verification_method: str,
    note: str = "",
    reviewer_user_id: int | None = None,
) -> m.EntityPairReview:
    if left_observation_id == right_observation_id:
        raise ValueError("pair must contain two different observations")
    left_id, right_id = sorted((left_observation_id, right_observation_id))
    left = session.get(m.Observation, left_id)
    right = session.get(m.Observation, right_id)
    if left is None or right is None:
        raise LookupError("one or both observations were not found")
    method = verification_method.strip()
    if len(method) < 5:
        raise ValueError("an independent verification method is required")
    row = m.EntityPairReview(
        left_observation_id=left_id,
        right_observation_id=right_id,
        same_identity=bool(same_identity),
        reviewer_user_id=reviewer_user_id,
        reviewer=reviewer.strip()[:120] or "local",
        verification_method=method[:200],
        note=note[:4000],
        features=pair_features(left, right),
    )
    session.add(row)
    session.flush()
    return row


def _latest_reviews(session) -> list[m.EntityPairReview]:
    rows = list(session.execute(
        select(m.EntityPairReview).order_by(m.EntityPairReview.id.desc())
    ).scalars())
    latest = {}
    for row in rows:
        key = (row.left_observation_id, row.right_observation_id)
        latest.setdefault(key, row)
    return list(latest.values())


def _ece(probabilities, outcomes, bins: int = 10) -> float:
    total = len(outcomes)
    if not total:
        return 1.0
    error = 0.0
    for index in range(bins):
        lo, hi = index / bins, (index + 1) / bins
        indexes = [
            i for i, probability in enumerate(probabilities)
            if lo <= probability < hi or (index == bins - 1 and probability == 1)
        ]
        if indexes:
            predicted = sum(probabilities[i] for i in indexes) / len(indexes)
            observed = sum(outcomes[i] for i in indexes) / len(indexes)
            error += len(indexes) / total * abs(predicted - observed)
    return round(error, 6)


def train(session, output: str | Path) -> dict:
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import brier_score_loss, precision_score, recall_score
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError("ML training requires: pip install 'osint-recon[ml]'") from exc

    rows = _latest_reviews(session)
    positives = sum(row.same_identity for row in rows)
    negatives = len(rows) - positives
    if len(rows) < MIN_LABELS or min(positives, negatives) < MIN_CLASS:
        raise ValueError(
            f"need at least {MIN_LABELS} reviewed pairs with {MIN_CLASS} in each class; "
            f"found {len(rows)} ({positives} positive, {negatives} negative)"
        )
    x = [[float(row.features.get(name, 0.0)) for name in FEATURE_NAMES] for row in rows]
    y = [int(row.same_identity) for row in rows]
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=20260813, stratify=y
    )
    scaler = StandardScaler().fit(x_train)
    model = LogisticRegression(
        class_weight="balanced", max_iter=1000, random_state=20260813
    ).fit(scaler.transform(x_train), y_train)
    probabilities = model.predict_proba(scaler.transform(x_test))[:, 1]
    threshold = 0.80
    predictions = [int(probability >= threshold) for probability in probabilities]
    false_positives = sum(p == 1 and truth == 0 for p, truth in zip(predictions, y_test))
    test_negatives = sum(truth == 0 for truth in y_test)
    metrics = {
        "test_n": len(y_test),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
        "false_positive_rate": round(false_positives / max(1, test_negatives), 6),
        "brier": round(float(brier_score_loss(y_test, probabilities)), 6),
        "ece": _ece(list(map(float, probabilities)), y_test),
    }
    payload = {
        "schema": MODEL_SCHEMA,
        "kind": "review-assist-logistic-regression",
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "features": list(FEATURE_NAMES),
        "labels": {"n": len(rows), "positives": positives, "negatives": negatives},
        "decision_threshold": threshold,
        "scaler": {
            "mean": [float(value) for value in scaler.mean_],
            "scale": [float(value) for value in scaler.scale_],
        },
        "model": {
            "intercept": float(model.intercept_[0]),
            "coefficients": [float(value) for value in model.coef_[0]],
        },
        "metrics": metrics,
        "activation_eligible": (
            metrics["false_positive_rate"] <= 0.05 and metrics["ece"] <= 0.10
        ),
    }
    destination = Path(output).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    destination.write_bytes(encoded)
    payload["sha256"] = hashlib.sha256(encoded).hexdigest()
    payload["path"] = str(destination)
    return payload


@dataclass(frozen=True)
class IdentityModel:
    payload: dict

    def predict(self, features: dict[str, float]) -> dict:
        names = self.payload["features"]
        means = self.payload["scaler"]["mean"]
        scales = self.payload["scaler"]["scale"]
        coefficients = self.payload["model"]["coefficients"]
        values = [float(features.get(name, 0.0)) for name in names]
        standardized = [
            (value - mean) / (scale or 1.0)
            for value, mean, scale in zip(values, means, scales)
        ]
        logit = self.payload["model"]["intercept"] + sum(
            coefficient * value
            for coefficient, value in zip(coefficients, standardized)
        )
        probability = 1 / (1 + math.exp(-max(-40.0, min(40.0, logit))))
        contributions = sorted(
            (
                {"feature": name, "contribution": round(coefficient * value, 6)}
                for name, coefficient, value in zip(names, coefficients, standardized)
            ),
            key=lambda item: abs(item["contribution"]),
            reverse=True,
        )[:5]
        return {
            "probability": round(probability, 6),
            "suggest_same_identity": probability >= self.payload["decision_threshold"],
            "top_contributions": contributions,
        }


def load_model(path: str | Path) -> IdentityModel:
    candidate = Path(path).expanduser()
    if candidate.stat().st_size > 1_000_000:
        raise ValueError("identity model is too large")
    payload = json.loads(candidate.read_text(encoding="utf-8"))
    if payload.get("schema") != MODEL_SCHEMA or payload.get("features") != list(FEATURE_NAMES):
        raise ValueError("unsupported identity model schema")
    if not payload.get("activation_eligible"):
        raise ValueError("identity model did not meet held-out activation thresholds")
    if len(payload.get("model", {}).get("coefficients", [])) != len(FEATURE_NAMES):
        raise ValueError("invalid identity model coefficients")
    return IdentityModel(payload)
