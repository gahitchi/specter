"""Replayable end-to-end quality evaluation for investigation behavior."""

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
    category: str = Field(min_length=1, max_length=40)
    query: Query
    observed_findings: list[Finding]
    expected_claims: list[ExpectedClaim]
    expected_profile_status: Literal["corroborated", "partial", "unresolved"]
    required_actions: list[str] = Field(default_factory=list)
    expected_stop_code: str = "authorized_frontier_exhausted"
    ground_truth_method: str | None = Field(default=None, max_length=300)
    verified_at: str | None = Field(default=None, max_length=80)

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
    provenance: Literal["functional_fixture", "externally_verified"]
    description: str = Field(default="", max_length=1000)
    cases: list[EvaluationCase]

    @model_validator(mode="after")
    def validate_dataset(self) -> "EvaluationDataset":
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation case ids must be unique")
        if self.provenance == "externally_verified":
            missing = [
                case.id for case in self.cases
                if not case.ground_truth_method or not case.verified_at
            ]
            if missing:
                raise ValueError(
                    "externally verified cases require ground_truth_method and verified_at: "
                    + ", ".join(missing[:5])
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
    tp = fp = tn = fn = exact = 0
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
        else:
            tn += 1
        exact += predicted is not None and predicted_value == claim.verdict
    fp += sum(
        key not in expected_keys and verdict == Verdict.FOUND
        for key, verdict in predictions.items()
    )
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "exact": exact}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def evaluate_dataset(dataset: EvaluationDataset, dataset_sha256: str = "") -> dict[str, Any]:
    totals = Counter()
    source_totals: dict[str, Counter] = defaultdict(Counter)
    case_results = []
    action_expected = action_matched = profile_matches = stop_matches = 0
    categories = Counter()

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

    claims_n = totals["tp"] + totals["fp"] + totals["tn"] + totals["fn"]
    positives = totals["tp"] + totals["fn"]
    negatives = totals["tn"] + totals["fp"]
    metrics = {
        "claims": claims_n,
        "positives": positives,
        "negatives": negatives,
        "precision": _ratio(totals["tp"], totals["tp"] + totals["fp"]),
        "recall": _ratio(totals["tp"], positives),
        "false_positive_rate": _ratio(totals["fp"], negatives),
        "verdict_accuracy": _ratio(totals["exact"], claims_n),
        "profile_accuracy": _ratio(profile_matches, len(dataset.cases)),
        "action_recall": _ratio(action_matched, action_expected) if action_expected else 1.0,
        "stop_accuracy": _ratio(stop_matches, len(dataset.cases)),
        "confusion": {key: totals[key] for key in ("tp", "fp", "tn", "fn")},
    }
    sample_requirements = {
        "cases": 50,
        "positives": 15,
        "negatives": 15,
        "categories": 3,
        "phone_cases": 10,
    }
    performance_requirements = {
        "precision": 0.95,
        "recall": 0.85,
        "verdict_accuracy": 0.85,
        "profile_accuracy": 0.9,
        "action_recall": 0.9,
        "stop_accuracy": 0.9,
    }
    sample_actual = {
        "cases": len(dataset.cases),
        "positives": positives,
        "negatives": negatives,
        "categories": len(categories),
        "phone_cases": categories["phone"],
    }
    reasons = []
    if dataset.provenance != "externally_verified":
        reasons.append("The packaged dataset is a functional fixture, not real calibration evidence.")
    for key, minimum in sample_requirements.items():
        if sample_actual[key] < minimum:
            reasons.append(f"{key} requires at least {minimum}; dataset has {sample_actual[key]}.")
    for key, minimum in performance_requirements.items():
        if metrics[key] < minimum:
            reasons.append(f"{key} requires {minimum:.0%}; measured {metrics[key]:.0%}.")
    ready = not reasons
    return {
        "version": 1,
        "dataset": {
            "name": dataset.name,
            "version": dataset.version,
            "provenance": dataset.provenance,
            "sha256": dataset_sha256,
            "description": dataset.description,
        },
        "metrics": metrics,
        "categories": dict(sorted(categories.items())),
        "sources": {
            source: {
                "claims": counts["tp"] + counts["fp"] + counts["tn"] + counts["fn"],
                "precision": _ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "false_positive_rate": _ratio(counts["fp"], counts["fp"] + counts["tn"]),
            }
            for source, counts in sorted(source_totals.items())
        },
        "gate": {
            "status": "READY" if ready else "NEEDS_EVIDENCE",
            "ready": ready,
            "sample_requirements": sample_requirements,
            "sample_actual": sample_actual,
            "performance_requirements": performance_requirements,
            "reasons": reasons,
        },
        "cases": case_results,
    }


def run_evaluation(path: str | Path | None = None) -> dict[str, Any]:
    dataset, digest = load_dataset(path)
    return evaluate_dataset(dataset, digest)
