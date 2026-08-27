"""Run non-destructive local or staging production-readiness drills."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from recon.evaluation import run_evaluation
from recon.models import Query
from recon.store.db import Database
from recon.store import repo

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _result(name: str, ok: bool, detail: str, duration: float) -> dict:
    return {
        "name": name,
        "ok": ok,
        "detail": detail,
        "duration_ms": round(duration * 1000),
    }


def _sqlite_backup_restore(root: Path) -> dict:
    started = time.perf_counter()
    source = root / "source.db"
    backup = root / "backup.db"
    restored = root / "restored.db"
    with Database(f"sqlite:///{source.as_posix()}") as database:
        database.create_all()
        with database.session() as session:
            target = repo.get_or_create_target(session, Query(username="drill-subject"))
            run = repo.create_run(session, target)
            repo.finish_run(session, run, "done", {"drill": True})
        source_connection = sqlite3.connect(source)
        backup_connection = sqlite3.connect(backup)
        try:
            source_connection.backup(backup_connection)
        finally:
            backup_connection.close()
            source_connection.close()
    backup_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    backup_connection = sqlite3.connect(backup)
    restored_connection = sqlite3.connect(restored)
    try:
        backup_connection.backup(restored_connection)
    finally:
        restored_connection.close()
        backup_connection.close()
    with Database(f"sqlite:///{restored.as_posix()}") as database:
        database.ping()
        revision_ok = database.schema_revision() == database.migration_head()
        with database.session() as session:
            runs = repo.list_runs(session)
            data_ok = len(runs) == 1 and (runs[0].stats or {}).get("drill") is True
    ok = revision_ok and data_ok
    return _result(
        "sqlite_backup_restore",
        ok,
        f"Backup {backup_hash[:12]} restored with current schema and preserved drill data.",
        time.perf_counter() - started,
    )


def _evaluation_replay() -> dict:
    started = time.perf_counter()
    report = run_evaluation()
    metrics = report["metrics"]
    behavior_ok = (
        metrics["precision"] == 1.0
        and metrics["recall"] == 1.0
        and metrics["stop_accuracy"] == 1.0
    )
    fixture_honest = report["gate"]["status"] == "NEEDS_EVIDENCE"
    return _result(
        "functional_replay",
        behavior_ok and fixture_honest,
        (
            "Functional cases passed and remained correctly excluded from real-world "
            "readiness evidence."
        ),
        time.perf_counter() - started,
    )


def _staging_readiness(base_url: str, digest: str, timeout: float) -> dict:
    started = time.perf_counter()
    if not _DIGEST.fullmatch(digest):
        return _result(
            "staging_readiness", False, "Container digest must be sha256 followed by 64 hex characters.",
            time.perf_counter() - started,
        )
    url = base_url.rstrip("/") + "/health/ready"
    request = urllib.request.Request(url, headers={"User-Agent": "Specter-Operational-Drill/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            payload = json.loads(response.read(64_000))
            ok = response.status == 200 and payload.get("status") == "ready"
            detail = f"{url} returned HTTP {response.status} for tested image {digest[:19]}."
    except (OSError, ValueError, urllib.error.URLError) as exc:
        ok = False
        detail = f"Staging readiness failed: {type(exc).__name__}: {exc}"
    return _result("staging_readiness", ok, detail, time.perf_counter() - started)


def run(*, staging_url: str | None = None, container_digest: str | None = None,
        timeout: float = 15.0) -> dict:
    with tempfile.TemporaryDirectory(prefix="specter-drill-") as temporary:
        checks = [_sqlite_backup_restore(Path(temporary)), _evaluation_replay()]
    if staging_url or container_digest:
        if not staging_url or not container_digest:
            checks.append(_result(
                "staging_readiness", False,
                "Both --staging-url and --container-digest are required for a staging drill.", 0,
            ))
        else:
            checks.append(_staging_readiness(staging_url, container_digest, timeout))
    return {
        "version": 1,
        "status": "PASSED" if all(check["ok"] for check in checks) else "FAILED",
        "checks": checks,
        "notes": [
            "The local drill uses temporary synthetic data and never touches the operator database.",
            "PostgreSQL production restores still require the isolated restore procedure in PRODUCTION.md.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-url")
    parser.add_argument("--container-digest")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = run(
        staging_url=args.staging_url,
        container_digest=args.container_digest,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Specter operational drill: {report['status']}")
        for check in report["checks"]:
            print(f"  [{'OK' if check['ok'] else 'FAIL'}] {check['name']}: {check['detail']}")
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
