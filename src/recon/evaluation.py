"""Frozen-snapshot quality evaluation for investigation behavior.

Collection is intentionally not rerun here: public sources change and live
requests would make a benchmark irreproducible.  Reviewed snapshots measure
verdict interpretation, profile synthesis, planning, and stop behavior.  Live
source health is measured separately through designated canaries.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Finding, Query, Verdict
from .profile import synthesize_profile
from .reasoning import InvestigationReasoner

DEFAULT_DATASET = Path(__file__).resolve().parent / "data" / "evaluation_cases.json"

AuthorizationBasis = Literal[
    "self_owned",
    "documented_authorization",
    "controlled_test_asset",
    "public_organization_asset",
]


class ExpectedClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    label: str = Field(min_length=1, max_length=200)
    verdict: Literal["FOUND", "NOT_FOUND"]

    @property
    def key(self) -> str:
        return f"{self.source.casefold()}|{self.label.casefold()}"


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    subject_group: str | None = Field(default=None, min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=40)
    query: Query
    observed_findings: list[Finding]
    expected_claims: list[ExpectedClaim]
    expected_profile_status: Literal["corroborated", "partial", "unresolved"]
    required_actions: list[str] = Field(default_factory=list)
    expected_stop_code: str = "authorized_frontier_exhausted"
    ground_truth_method: str | None = Field(default=None, max_length=300)
    verified_at: str | None = Field(default=None, max_length=80)
    authorization_basis: AuthorizationBasis | None = None
    reviewer_id: str | None = Field(default=None, max_length=120)
    reviewer_independent: bool = False
    blind_review: bool = False

    @model_validator(mode="after")
    def validate_case(self) -> "EvaluationCase":
        if self.query.is_empty():
            raise ValueError("evaluation case query cannot be empty")
        keys = [claim.key for claim in self.expected_claims]
        if len(keys) != len(set(keys)):
            raise ValueError("evaluation case contains duplicate expected claims")
        return self


class EvaluationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    version: int = Field(default=1, ge=1)
    provenance: Literal["functional_fixture", "operator_pilot", "externally_verified"]
    evaluation_mode: Literal["frozen_snapshot"] = "frozen_snapshot"
    review_protocol_version: int = Field(default=1, ge=1)
    description: str = Field(default="", max_length=1000)
    cases: list[EvaluationCase]

    @model_validator(mode="after")
    def validate_dataset(self) -> "EvaluationDataset":
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation case ids must be unique")
        if self.provenance in {"operator_pilot", "externally_verified"}:
            missing = [
                case.id for case in self.cases
                if (
                    not case.subject_group
                    or not case.ground_truth_method
                    or not case.verified_at
                    or not case.authorization_basis
                    or not case.reviewer_id
                )
            ]
            if missing:
                raise ValueError(
                    "reviewed cases require a subject group, authorization, verification "
                    "method, date, and reviewer identifier: "
                    + ", ".join(missing[:5])
                )
        if self.provenance == "externally_verified":
            invalid = [
                case.id for case in self.cases
                if not case.reviewer_independent or not case.blind_review
            ]
            if invalid:
                raise ValueError(
                    "externally verified cases require independent blind review metadata: "
                    + ", ".join(invalid[:5])
                )
        if self.provenance == "operator_pilot":
            invalid = [case.id for case in self.cases if case.reviewer_independent]
            if invalid:
                raise ValueError(
                    "operator pilot cases must be declared non-independent: "
                    + ", ".join(invalid[:5])
                )
        return self


def load_dataset(path: str | Path | None = None) -> tuple[EvaluationDataset, str]:
    target = Path(path) if path else DEFAULT_DATASET
    if not target.is_file():
        raise ValueError(f"evaluation dataset does not exist: {target}")
    if target.stat().st_size > 20_000_000:
        raise ValueError("evaluation dataset is too large")
    raw = target.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid evaluation JSON: {exc}") from exc
    return EvaluationDataset.model_validate(payload), hashlib.sha256(raw).hexdigest()


def _claim_metrics(expected: list[ExpectedClaim], observed: list[Finding]) -> dict[str, int]:
    predictions: dict[str, Verdict] = {}
    for finding in observed:
        key = f"{finding.source.casefold()}|{finding.label.casefold()}"
        if key not in predictions or finding.verdict == Verdict.FOUND:
            predictions[key] = finding.verdict
    tp = fp = tn = fn = exact = indeterminate = 0
    expected_keys = {claim.key for claim in expected}
    for claim in expected:
        predicted = predictions.get(claim.key)
        predicted_value = (
            predicted.value if isinstance(predicted, Verdict) else str(predicted or "")
        )
        expected_present = claim.verdict == "FOUND"
        predicted_present = predicted_value == Verdict.FOUND.value
        if expected_present and predicted_present:
            tp += 1
        elif expected_present:
            fn += 1
        elif predicted_present:
            fp += 1
        elif predicted_value == Verdict.NOT_FOUND.value:
            tn += 1
        else:
            indeterminate += 1
        if predicted_value not in {Verdict.FOUND.value, Verdict.NOT_FOUND.value}:
            indeterminate += int(expected_present)
        exact += predicted is not None and predicted_value == claim.verdict
    unsupported_positive = sum(
        key not in expected_keys and verdict == Verdict.FOUND
        for key, verdict in predictions.items()
    )
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "exact": exact,
        "indeterminate": indeterminate,
        "unsupported_positive": unsupported_positive,
        "expected_positives": sum(claim.verdict == "FOUND" for claim in expected),
        "expected_negatives": sum(claim.verdict == "NOT_FOUND" for claim in expected),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def evaluate_dataset(dataset: EvaluationDataset, dataset_sha256: str = "") -> dict[str, Any]:
    totals = Counter()
    source_totals: dict[str, Counter] = defaultdict(Counter)
    case_results = []
    action_expected = action_matched = profile_matches = stop_matches = 0
    categories = Counter()
    subject_groups = Counter(
        case.subject_group for case in dataset.cases if case.subject_group
    )

    for case in dataset.cases:
        categories[case.category] += 1
        claims = _claim_metrics(case.expected_claims, case.observed_findings)
        totals.update(claims)
        expected_by_source: dict[str, list[ExpectedClaim]] = defaultdict(list)
        observed_by_source: dict[str, list[Finding]] = defaultdict(list)
        source_labels: dict[str, str] = {}
        for claim in case.expected_claims:
            key = claim.source.casefold()
            expected_by_source[key].append(claim)
            source_labels.setdefault(key, claim.source)
        for finding in case.observed_findings:
            key = finding.source.casefold()
            observed_by_source[key].append(finding)
            source_labels.setdefault(key, finding.source)
        for key in expected_by_source.keys() | observed_by_source.keys():
            source_totals[source_labels[key]].update(_claim_metrics(
                expected_by_source[key], observed_by_source[key]
            ))

        artifacts = case.query.normalized().to_seed_artifacts()
        summary: dict[str, Any] = {"clusters": [], "identities": 0}
        profile = synthesize_profile(case.query, case.observed_findings, artifacts, summary)
        report = InvestigationReasoner().report(
            case.query,
            case.observed_findings,
            artifacts,
            summary,
            stop_reason=None,
            scope_mode="strict",
            passive_only=True,
            out_of_scope=[],
        )
        action_ids = {action["id"] for action in report["next_actions"]}
        matched_actions = sorted(set(case.required_actions) & action_ids)
        action_expected += len(case.required_actions)
        action_matched += len(matched_actions)
        profile_match = profile["status"] == case.expected_profile_status
        stop_match = report["stop_decision"]["code"] == case.expected_stop_code
        profile_matches += profile_match
        stop_matches += stop_match
        case_results.append({
            "id": case.id,
            "category": case.category,
            "claims": claims,
            "profile": {
                "expected": case.expected_profile_status,
                "actual": profile["status"],
                "match": profile_match,
            },
            "actions": {
                "expected": case.required_actions,
                "actual": sorted(action_ids),
                "matched": matched_actions,
            },
            "stop": {
                "expected": case.expected_stop_code,
                "actual": report["stop_decision"]["code"],
                "match": stop_match,
            },
        })

    unsupported_positive = totals["unsupported_positive"]
    false_positives = totals["fp"] + unsupported_positive
    expected_claims = totals["expected_positives"] + totals["expected_negatives"]
    claims_n = expected_claims + unsupported_positive
    positives = totals["expected_positives"]
    negatives = totals["expected_negatives"]
    metrics = {
        "claims": claims_n,
        "positives": positives,
        "negatives": negatives,
        "precision": _ratio(totals["tp"], totals["tp"] + false_positives),
        "recall": _ratio(totals["tp"], positives),
        "false_positive_rate": _ratio(totals["fp"], totals["fp"] + totals["tn"]),
        "decision_coverage": _ratio(expected_claims - totals["indeterminate"], expected_claims),
        "unsupported_positive_claims": unsupported_positive,
        "verdict_accuracy": _ratio(totals["exact"], claims_n),
        "profile_accuracy": _ratio(profile_matches, len(dataset.cases)),
        "action_recall": _ratio(action_matched, action_expected) if action_expected else 1.0,
        "stop_accuracy": _ratio(stop_matches, len(dataset.cases)),
        "confusion": {
            "tp": totals["tp"],
            "fp": false_positives,
            "tn": totals["tn"],
            "fn": totals["fn"],
            "indeterminate": totals["indeterminate"],
        },
    }
    sample_requirements = {
        "cases": 50,
        "subjects": 25,
        "positives": 15,
        "negatives": 15,
        "categories": 3,
        "phone_cases": 10,
    }
    performance_requirements = {
        "precision": 0.99,
        "recall": 0.85,
        "verdict_accuracy": 0.85,
        "profile_accuracy": 0.9,
        "action_recall": 0.9,
        "stop_accuracy": 0.9,
        "decision_coverage": 0.95,
    }
    maximum_requirements = {"false_positive_rate": 0.01}
    sample_actual = {
        "cases": len(dataset.cases),
        "subjects": len(subject_groups),
        "positives": positives,
        "negatives": negatives,
        "categories": len(categories),
        "phone_cases": categories["phone"],
    }
    reasons = []
    if dataset.provenance == "functional_fixture":
        reasons.append("The packaged dataset is a functional fixture, not real calibration evidence.")
    elif dataset.provenance == "operator_pilot":
        reasons.append(
            "The operator pilot is useful engineering evidence, but it is not independent "
            "accuracy evidence."
        )
    for key, minimum in sample_requirements.items():
        if sample_actual[key] < minimum:
            reasons.append(f"{key} requires at least {minimum}; dataset has {sample_actual[key]}.")
    for key, minimum in performance_requirements.items():
        if metrics[key] < minimum:
            reasons.append(f"{key} requires {minimum:.0%}; measured {metrics[key]:.0%}.")
    for key, maximum in maximum_requirements.items():
        if metrics[key] > maximum:
            reasons.append(
                f"{key} must be at most {maximum:.0%}; measured {metrics[key]:.0%}."
            )
    ready = not reasons
    return {
        "version": 2,
        "dataset": {
            "name": dataset.name,
            "version": dataset.version,
            "provenance": dataset.provenance,
            "sha256": dataset_sha256,
            "description": dataset.description,
            "evaluation_mode": dataset.evaluation_mode,
            "review_protocol_version": dataset.review_protocol_version,
        },
        "metrics": metrics,
        "categories": dict(sorted(categories.items())),
        "sources": {
            source: {
                "claims": (
                    counts["expected_positives"]
                    + counts["expected_negatives"]
                    + counts["unsupported_positive"]
                ),
                "precision": _ratio(
                    counts["tp"],
                    counts["tp"] + counts["fp"] + counts["unsupported_positive"],
                ),
                "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "false_positive_rate": _ratio(counts["fp"], counts["fp"] + counts["tn"]),
                "decision_coverage": _ratio(
                    counts["expected_positives"] + counts["expected_negatives"]
                    - counts["indeterminate"],
                    counts["expected_positives"] + counts["expected_negatives"],
                ),
            }
            for source, counts in sorted(source_totals.items())
        },
        "gate": {
            "status": "READY" if ready else "NEEDS_EVIDENCE",
            "ready": ready,
            "sample_requirements": sample_requirements,
            "sample_actual": sample_actual,
            "performance_requirements": performance_requirements,
            "maximum_requirements": maximum_requirements,
            "reasons": reasons,
        },
        "cases": case_results,
    }


def run_evaluation(path: str | Path | None = None) -> dict[str, Any]:
    dataset, digest = load_dataset(path)
    return evaluate_dataset(dataset, digest)
