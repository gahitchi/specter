"""Private, blind-review workflow for building real evaluation snapshots."""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .evaluation import AuthorizationBasis, EvaluationCase, EvaluationDataset
from .evidence import EvidenceClass, infer_origin
from .models import Finding, Query
from .reasoning import NEXT_ACTION_IDS as ACTION_IDS
from .reasoning import STOP_CODES

REVIEW_COLUMNS = [
    "case_id",
    "subject_group",
    "category",
    "query",
    "source",
    "claim",
    "evidence_url",
    "expected_verdict",
    "expected_profile_status",
    "required_actions",
    "expected_stop_code",
    "ground_truth_method",
    "verified_at",
    "reviewer_id",
    "reviewer_independent",
    "authorization_basis",
    "review_note",
]
PROFILE_STATUSES = {"corroborated", "partial", "unresolved"}
ReviewMode = Literal["operator_pilot", "independent"]


def default_paths() -> dict[str, Path]:
    from .desktop_settings import data_root

    root = data_root() / "evaluation"
    return {
        "root": root,
        "kit": root / "review-kit.json",
        "sheet": root / "quality-review.csv",
        "review": root / "completed-review.csv",
        "dataset": root / "reviewed-dataset.json",
    }


class ReviewClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    label: str = Field(min_length=1, max_length=200)
    evidence_url: str | None = Field(default=None, max_length=2048)

    @property
    def key(self) -> str:
        return f"{self.source.casefold()}|{self.label.casefold()}"


class CapturedCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    subject_group: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    category: str = Field(min_length=1, max_length=40)
    query: Query
    source_run_id: int = Field(ge=1)
    captured_at: str = Field(min_length=1, max_length=80)
    authorization_basis: AuthorizationBasis
    observed_findings: list[Finding]
    review_claims: list[ReviewClaim]

    @model_validator(mode="after")
    def validate_claims(self) -> "CapturedCase":
        keys = [claim.key for claim in self.review_claims]
        if not keys:
            raise ValueError("captured case has no reviewable claims")
        if len(keys) != len(set(keys)):
            raise ValueError("captured case contains duplicate review claims")
        return self


class ReviewKit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    version: int = Field(default=1, ge=1)
    review_mode: ReviewMode = "independent"
    description: str = Field(default="", max_length=1000)
    created_at: str = Field(min_length=1, max_length=80)
    cases: list[CapturedCase] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_case_ids(self) -> "ReviewKit":
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("review-kit case ids must be unique")
        return self


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_private(path: Path, text: str) -> Path:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, path)
    return path


def create_kit(
    path: str | Path,
    name: str,
    description: str = "",
    review_mode: ReviewMode = "independent",
) -> ReviewKit:
    target = Path(path)
    if target.exists():
        raise ValueError(f"review kit already exists: {target}")
    kit = ReviewKit(
        name=name,
        description=description,
        review_mode=review_mode,
        created_at=_now(),
    )
    save_kit(target, kit)
    return kit


def load_kit(path: str | Path) -> ReviewKit:
    target = Path(path).expanduser()
    if not target.is_file():
        raise ValueError(f"review kit does not exist: {target}")
    if target.stat().st_size > 20_000_000:
        raise ValueError("review kit is too large")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid review-kit JSON: {exc}") from exc
    return ReviewKit.model_validate(payload)


def save_kit(path: str | Path, kit: ReviewKit) -> Path:
    return _write_private(
        Path(path),
        json.dumps(kit.model_dump(mode="json"), indent=2) + "\n",
    )


def kit_status(path: str | Path) -> dict:
    target = Path(path).expanduser()
    if not target.is_file():
        return {
            "exists": False,
            "cases": 0,
            "claims": 0,
            "subjects": 0,
            "categories": [],
            "phone_cases": 0,
        }
    kit = load_kit(target)
    categories = sorted({case.category for case in kit.cases})
    return {
        "exists": True,
        "name": kit.name,
        "review_mode": kit.review_mode,
        "cases": len(kit.cases),
        "claims": sum(len(case.review_claims) for case in kit.cases),
        "subjects": len({case.subject_group for case in kit.cases}),
        "categories": categories,
        "phone_cases": sum(case.category == "phone" for case in kit.cases),
        "ready_for_review": bool(kit.cases),
    }


def _observation_finding(observation) -> Finding:
    evidence_class = EvidenceClass(observation.evidence_class or "unknown")
    origin = infer_origin(
        observation.source,
        observation.url,
        collector=observation.collector,
        evidence_class=evidence_class,
        independence_key=observation.independence_key,
    )
    return Finding.model_validate({
        "source": observation.source,
        "category": observation.category,
        "label": observation.label,
        "url": observation.url,
        "verdict": observation.verdict,
        "confidence": observation.confidence,
        "reasons": observation.reasons or [],
        "breakdown": observation.breakdown,
        "trace": observation.trace,
        "signals": observation.signals or {},
        "data": observation.data or {},
        "origin": origin.model_dump(mode="json"),
        "extractions": observation.extractions or [],
        "temporal": {
            "observed_at": observation.observed_at,
            "valid_from": observation.valid_from,
            "valid_until": observation.valid_until,
            "first_seen_at": observation.first_seen_at,
            "last_seen_at": observation.last_seen_at,
            "status": observation.temporal_status or "unknown",
        },
        "completeness": observation.completeness or "unknown",
        "confidence_dimensions": observation.confidence_dimensions,
        "policy": observation.policy or {},
    })


def capture_run(
    kit_path: str | Path,
    *,
    run_id: int,
    case_id: str,
    subject_group: str,
    category: str,
    authorization_basis: AuthorizationBasis,
) -> CapturedCase:
    from .store import get_db, repo
    from .store import models_db as m

    kit = load_kit(kit_path)
    if any(case.id == case_id for case in kit.cases):
        raise ValueError(f"review kit already contains case id: {case_id}")
    with get_db().session() as session:
        run = session.get(m.Run, run_id)
        if run is None:
            raise ValueError(f"run does not exist: {run_id}")
        if run.status != "done":
            raise ValueError(f"run #{run_id} is not complete")
        target = session.get(m.Target, run.target_id)
        if target is None:
            raise ValueError(f"run #{run_id} has no target")
        findings = [_observation_finding(row) for row in repo.observations_for_run(session, run_id)]
        query = Query.model_validate(target.query)

    claims: dict[str, ReviewClaim] = {}
    for finding in findings:
        claim = ReviewClaim(
            source=finding.source,
            label=finding.label,
            evidence_url=finding.url,
        )
        claims.setdefault(claim.key, claim)
    captured = CapturedCase(
        id=case_id,
        subject_group=subject_group,
        category=category,
        query=query,
        source_run_id=run_id,
        captured_at=_now(),
        authorization_basis=authorization_basis,
        observed_findings=findings,
        review_claims=list(claims.values()),
    )
    kit.cases.append(captured)
    save_kit(kit_path, kit)
    return captured


def _safe_csv(value: object) -> str:
    text = str(value or "")
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def review_sheet(kit_path: str | Path, output: str | Path) -> Path:
    kit = load_kit(kit_path)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=REVIEW_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for case in kit.cases:
        query = json.dumps(case.query.model_dump(exclude_none=True), sort_keys=True)
        for claim in case.review_claims:
            row = {
                "case_id": case.id,
                "subject_group": case.subject_group,
                "category": case.category,
                "query": query,
                "source": claim.source,
                "claim": claim.label,
                "evidence_url": claim.evidence_url or "",
                "expected_verdict": "",
                "expected_profile_status": "",
                "required_actions": "",
                "expected_stop_code": "",
                "ground_truth_method": "",
                "verified_at": "",
                "reviewer_id": "operator" if kit.review_mode == "operator_pilot" else "",
                "reviewer_independent": (
                    "false" if kit.review_mode == "operator_pilot" else ""
                ),
                "authorization_basis": case.authorization_basis,
                "review_note": "",
            }
            writer.writerow({key: _safe_csv(value) for key, value in row.items()})
    return _write_private(Path(output), buffer.getvalue())


def _read_review(path: str | Path) -> list[dict[str, str]]:
    target = Path(path).expanduser()
    if not target.is_file():
        raise ValueError(f"review sheet does not exist: {target}")
    if target.stat().st_size > 5_000_000:
        raise ValueError("review sheet is too large")
    with target.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != REVIEW_COLUMNS:
            raise ValueError("review sheet columns were changed")
        rows = []
        for row in reader:
            cleaned = {}
            for key, value in row.items():
                cell = (value or "").strip()
                if len(cell) > 1 and cell[0] == "'" and cell[1] in "=+-@":
                    cell = cell[1:]
                cleaned[key] = cell
            rows.append(cleaned)
        return rows


def save_review_submission(path: str | Path, text: str) -> Path:
    if not text.strip():
        raise ValueError("completed review sheet is empty")
    if len(text.encode("utf-8")) > 900_000:
        raise ValueError("completed review sheet is too large")
    if "\x00" in text:
        raise ValueError("completed review sheet contains invalid data")
    return _write_private(Path(path), text)


def _one_value(rows: list[dict[str, str]], key: str, case_id: str) -> str:
    values = {row[key] for row in rows}
    if len(values) != 1 or not next(iter(values)):
        raise ValueError(f"case {case_id}: {key} must be completed consistently")
    return next(iter(values))


def _validate_review_date(value: str, case_id: str) -> str:
    try:
        reviewed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"case {case_id}: verified_at must be an ISO date or timestamp") from exc
    if reviewed.tzinfo is None:
        reviewed = reviewed.replace(tzinfo=timezone.utc)
    if reviewed > datetime.now(timezone.utc):
        raise ValueError(f"case {case_id}: verified_at cannot be in the future")
    return value


def finalize_kit(
    kit_path: str | Path,
    review_path: str | Path,
    output: str | Path,
) -> EvaluationDataset:
    kit = load_kit(kit_path)
    rows = _read_review(review_path)
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row["case_id"], []).append(row)
    if set(grouped) != {case.id for case in kit.cases}:
        raise ValueError("review sheet cases do not match the captured review kit")

    evaluated_cases = []
    for case in kit.cases:
        case_rows = grouped[case.id]
        if _one_value(case_rows, "subject_group", case.id) != case.subject_group:
            raise ValueError(f"case {case.id}: subject group does not match capture")
        expected_keys = {claim.key for claim in case.review_claims}
        actual_keys = {
            f"{row['source'].casefold()}|{row['claim'].casefold()}" for row in case_rows
        }
        if actual_keys != expected_keys or len(actual_keys) != len(case_rows):
            raise ValueError(f"case {case.id}: review claims do not match the captured claims")
        verdicts = {row["expected_verdict"] for row in case_rows}
        if not verdicts <= {"FOUND", "NOT_FOUND"} or "" in verdicts:
            raise ValueError(f"case {case.id}: every expected_verdict must be FOUND or NOT_FOUND")
        profile_status = _one_value(case_rows, "expected_profile_status", case.id)
        if profile_status not in PROFILE_STATUSES:
            raise ValueError(f"case {case.id}: invalid expected_profile_status")
        actions_text = _one_value(case_rows, "required_actions", case.id)
        actions = [] if actions_text.casefold() == "none" else [
            item.strip() for item in actions_text.split(";") if item.strip()
        ]
        if not set(actions) <= ACTION_IDS:
            raise ValueError(f"case {case.id}: required_actions contains an unknown action")
        stop_code = _one_value(case_rows, "expected_stop_code", case.id)
        if stop_code not in STOP_CODES:
            raise ValueError(f"case {case.id}: invalid expected_stop_code")
        method = _one_value(case_rows, "ground_truth_method", case.id)
        reviewer = _one_value(case_rows, "reviewer_id", case.id)
        independent = _one_value(case_rows, "reviewer_independent", case.id).casefold()
        if kit.review_mode == "independent" and independent not in {"true", "yes", "1"}:
            raise ValueError(
                f"case {case.id}: reviewer must be independent of Specter development"
            )
        if kit.review_mode == "operator_pilot" and independent not in {"false", "no", "0"}:
            raise ValueError(
                f"case {case.id}: a private self-check must be declared non-independent"
            )
        authorization = _one_value(case_rows, "authorization_basis", case.id)
        if authorization != case.authorization_basis:
            raise ValueError(f"case {case.id}: authorization basis does not match capture")
        verified_at = _validate_review_date(
            _one_value(case_rows, "verified_at", case.id), case.id
        )
        expected_claims = [
            {
                "source": row["source"],
                "label": row["claim"],
                "verdict": row["expected_verdict"],
            }
            for row in case_rows
        ]
        evaluated_cases.append(EvaluationCase(
            id=case.id,
            subject_group=case.subject_group,
            category=case.category,
            query=case.query,
            observed_findings=case.observed_findings,
            expected_claims=expected_claims,
            expected_profile_status=profile_status,
            required_actions=actions,
            expected_stop_code=stop_code,
            ground_truth_method=method,
            verified_at=verified_at,
            authorization_basis=authorization,
            reviewer_id=reviewer,
            reviewer_independent=kit.review_mode == "independent",
            blind_review=kit.review_mode == "independent",
        ))

    dataset = EvaluationDataset(
        name=kit.name,
        version=kit.version,
        provenance=(
            "externally_verified" if kit.review_mode == "independent" else "operator_pilot"
        ),
        description=kit.description,
        cases=evaluated_cases,
    )
    _write_private(
        Path(output),
        json.dumps(dataset.model_dump(mode="json"), indent=2) + "\n",
    )
    return dataset
