"""Objective gate that must pass before high-risk feature expansion."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from .keys import VAULT
from .modules.registry import MODULES
from .sources import CONTRACTS, validate_contracts
from .store import repo

MAX_CANARY_AGE_DAYS = 14
MAX_ECE = 0.10
MAX_FALSE_POSITIVE_RATE = 0.01
MIN_EVALUATION_PRECISION = 0.99
MAX_EVALUATION_FALSE_POSITIVE_RATE = 0.01


def _utc(value: dt.datetime) -> dt.datetime:
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value


def _migration_head() -> str:
    config = Config()
    migrations = Path(__file__).resolve().parent / "migrations"
    config.set_main_option("script_location", str(migrations))
    return ScriptDirectory.from_config(config).get_current_head()


def _evaluation_meets_current_policy(evaluation: dict | None) -> bool:
    gate = (evaluation or {}).get("gate") or {}
    dataset = (evaluation or {}).get("dataset") or {}
    metrics = (evaluation or {}).get("metrics") or {}
    return bool(
        evaluation
        and gate.get("ready")
        and dataset.get("provenance") == "externally_verified"
        and metrics.get("precision", 0.0) >= MIN_EVALUATION_PRECISION
        and metrics.get("false_positive_rate", 1.0)
        <= MAX_EVALUATION_FALSE_POSITIVE_RATE
    )


def assess(db, *, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    checks = []

    contract_errors = validate_contracts()
    checks.append({
        "name": "source contracts",
        "passed": not contract_errors,
        "detail": "complete" if not contract_errors else "; ".join(contract_errors),
    })

    current, head = db.schema_revision(), _migration_head()
    checks.append({
        "name": "database migration",
        "passed": current == head,
        "detail": f"current={current or 'none'}, head={head}",
    })

    with db.session() as session:
        calibration = repo.list_calibration(session, limit=1)
        evaluations = repo.list_evaluations(session, limit=1)
        latest_checks = repo.latest_source_health_checks(session)
    report = calibration[0].report if calibration else None
    quality = (report or {}).get("sample_quality", {})
    confusion = (report or {}).get("confusion_found", {})
    calibration_passed = bool(
        report
        and quality.get("adequate")
        and (report.get("label_provenance") or {}).get("source") == "external"
        and report.get("ece", 1.0) <= MAX_ECE
        and confusion.get("fp_rate", 1.0) <= MAX_FALSE_POSITIVE_RATE
    )
    checks.append({
        "name": "representative calibration",
        "passed": calibration_passed,
        "detail": (
            f"n={(report or {}).get('n', 0)}, ECE={(report or {}).get('ece', 'n/a')}, "
            f"FP-rate={confusion.get('fp_rate', 'n/a')}, "
            f"labels={(report or {}).get('label_provenance', {}).get('source', 'untracked')}"
        ),
    })

    evaluation = evaluations[0].report if evaluations else None
    evaluation_gate = (evaluation or {}).get("gate") or {}
    evaluation_dataset = (evaluation or {}).get("dataset") or {}
    evaluation_metrics = (evaluation or {}).get("metrics") or {}
    evaluation_passed = _evaluation_meets_current_policy(evaluation)
    checks.append({
        "name": "representative evaluation",
        "passed": evaluation_passed,
        "detail": (
            f"status={evaluation_gate.get('status', 'missing')}, "
            f"cases={len((evaluation or {}).get('cases') or [])}, "
            f"provenance={evaluation_dataset.get('provenance', 'untracked')}, "
            f"precision={evaluation_metrics.get('precision', 'n/a')}, "
            f"FP-rate={evaluation_metrics.get('false_positive_rate', 'n/a')}"
        ),
    })

    required_modules = [
        module for module in MODULES
        if module.enabled
        and not module.expansion
        and CONTRACTS[module.name].interaction != "offline"
        and (not module.requires_keys or VAULT.has_all(module.requires_keys))
    ]
    stale_or_missing = []
    for module in required_modules:
        check = latest_checks.get(module.name)
        if check is None:
            stale_or_missing.append(f"{module.name}:missing")
            continue
        age = now - _utc(check.created_at)
        if check.status != "passed" or age > dt.timedelta(days=MAX_CANARY_AGE_DAYS):
            stale_or_missing.append(f"{module.name}:{check.status}")
    checks.append({
        "name": "live source canaries",
        "passed": not stale_or_missing,
        "detail": "current" if not stale_or_missing else ", ".join(stale_or_missing),
    })

    return {
        "expansion_ready": all(check["passed"] for check in checks),
        "policy": {
            "maximum_canary_age_days": MAX_CANARY_AGE_DAYS,
            "maximum_ece": MAX_ECE,
            "maximum_false_positive_rate": MAX_FALSE_POSITIVE_RATE,
            "minimum_evaluation_precision": MIN_EVALUATION_PRECISION,
            "maximum_evaluation_false_positive_rate": MAX_EVALUATION_FALSE_POSITIVE_RATE,
        },
        "checks": checks,
    }
