"""Redacted, cross-platform installation and runtime diagnostics."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import SETTINGS, Settings, data_root


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "required": required, "detail": detail}


def collect(settings: Settings = SETTINGS) -> dict[str, Any]:
    """Return support-safe diagnostics without identifiers, credentials, or DSNs."""
    from .sources import validate_contracts
    from .store import get_db
    from .updater import get_update_status

    checks = []
    supported_python = (3, 10) <= sys.version_info[:2] < (3, 15)
    checks.append(_check(
        "python_version",
        supported_python,
        f"Python {platform.python_version()}" + (" is supported" if supported_python else " is unsupported"),
    ))

    package_root = Path(__file__).resolve().parent
    required_assets = [
        package_root / "web" / "index.html",
        package_root / "web" / "app.js",
        package_root / "assets" / "specter.png",
        package_root / "data" / "evaluation_cases.json",
    ]
    missing = [path.name for path in required_assets if not path.is_file()]
    checks.append(_check(
        "package_assets",
        not missing,
        "Required application assets are present." if not missing else f"Missing: {', '.join(missing)}",
    ))

    root = data_root()
    writable = False
    try:
        root.mkdir(parents=True, exist_ok=True)
        writable = os.access(root, os.W_OK)
    except OSError:
        pass
    checks.append(_check(
        "data_directory",
        writable,
        f"Application data directory is {'writable' if writable else 'not writable'}.",
    ))

    db_revision = db_head = None
    try:
        db = get_db()
        db.ping()
        db_revision = db.schema_revision()
        db_head = db.migration_head()
        database_ok = db_revision == db_head
        db_detail = f"Database reachable; schema {db_revision or 'none'} / head {db_head or 'none'}."
    except Exception as exc:  # noqa: BLE001 - diagnostics must report startup failures
        database_ok = False
        db_detail = f"Database check failed: {type(exc).__name__}: {exc}"
    checks.append(_check("database", database_ok, db_detail))

    contract_errors = validate_contracts()
    checks.append(_check(
        "source_contracts",
        not contract_errors,
        "All source contracts are valid." if not contract_errors else "; ".join(contract_errors[:5]),
    ))

    update = get_update_status()
    checks.append(_check(
        "update_manager",
        update.supported,
        (
            "Installed with a supported tool manager."
            if update.supported else
            "This installation can run normally, but updates must be installed manually."
        ),
        required=False,
    ))

    production_warnings = []
    if settings.production_mode:
        if settings.auto_migrate:
            production_warnings.append("automatic database migration is enabled")
        if settings.remote_mode and not settings.auth_required:
            production_warnings.append("remote mode has no authentication")
        if settings.remote_mode and settings.tls_termination not in {"direct", "proxy"}:
            production_warnings.append("TLS termination is not configured")
    checks.append(_check(
        "production_configuration",
        not production_warnings,
        "Production safeguards are coherent." if not production_warnings else "; ".join(production_warnings),
        required=settings.production_mode,
    ))

    required_failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    return {
        "version": 1,
        "status": "READY" if not required_failures else "NEEDS_ATTENTION",
        "product": "Specter",
        "specter_version": __version__,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "runtime": {
            "environment": settings.environment,
            "storage_backend": "sqlite" if settings.storage_dsn.startswith("sqlite") else "postgresql",
            "queue_backend": settings.queue_backend,
            "remote_mode": settings.remote_mode,
            "auth_required": settings.auth_required,
            "schema_revision": db_revision,
            "schema_head": db_head,
        },
        "updates": {
            "supported": update.supported,
            "installed_revision": update.installed_revision,
            "pending_revision": update.pending_revision,
            "pending_selected": update.pending_selected,
        },
        "checks": checks,
        "required_failures": required_failures,
        "privacy_note": "This report excludes investigation inputs, API keys, cookies, and database credentials.",
    }
