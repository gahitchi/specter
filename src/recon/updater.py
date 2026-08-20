"""Conservative self-update support for the local ``specter`` launcher."""

from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from dataclasses import dataclass

PACKAGE_NAME = "osint-recon"
_RESTART_ENV = "RECON_UPDATE_RESTARTED"


@dataclass(frozen=True)
class UpdateResult:
    attempted: bool = False
    restart_required: bool = False
    message: str = ""


def _env_enabled(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except (OSError, ValueError):
        return False
    return True


def _command_output(command: list[str], timeout: float = 5.0) -> str | None:
    try:
        completed = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode:
        return None
    return completed.stdout.strip()


def _update_command() -> tuple[list[str], str] | None:
    """Return the updater only when it owns the active Python environment."""
    uv = shutil.which("uv")
    if uv:
        tool_dir = _command_output([uv, "tool", "dir"])
        if tool_dir and _within(Path(sys.prefix), Path(tool_dir)):
            return [
                uv,
                "tool",
                "upgrade",
                PACKAGE_NAME,
                "--reinstall-package",
                PACKAGE_NAME,
                "--quiet",
                "--no-progress",
            ], "uv"

    pipx = shutil.which("pipx")
    if pipx:
        venv_dir = _command_output([pipx, "environment", "--value", "PIPX_LOCAL_VENVS"])
        if venv_dir and _within(Path(sys.prefix), Path(venv_dir)):
            return [pipx, "upgrade", PACKAGE_NAME, "--quiet"], "pipx"
    return None


def _installation_fingerprint() -> tuple[str, str | None]:
    distribution = importlib.metadata.distribution(PACKAGE_NAME)
    commit: str | None = None
    direct_url = distribution.read_text("direct_url.json")
    if direct_url:
        try:
            payload = json.loads(direct_url)
            commit = (payload.get("vcs_info") or {}).get("commit_id")
        except (AttributeError, json.JSONDecodeError, TypeError):
            pass
    return distribution.version, commit


def auto_update(
    *, enabled: bool = True, force: bool = False, timeout: float = 45.0
) -> UpdateResult:
    """Refresh an isolated tool install; failures never prevent local startup."""
    if not enabled or (not force and not _env_enabled("RECON_AUTO_UPDATE")):
        return UpdateResult(message="automatic updates disabled")
    if os.environ.get(_RESTART_ENV) == "1":
        return UpdateResult()
    if os.environ.get("RECON_ENV", "development").strip().lower() == "production":
        return UpdateResult(message="automatic updates are disabled in production")

    manager = _update_command()
    if manager is None:
        return UpdateResult()

    command, manager_name = manager
    try:
        before = _installation_fingerprint()
        completed = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        after = _installation_fingerprint()
    except (importlib.metadata.PackageNotFoundError, OSError, subprocess.TimeoutExpired):
        return UpdateResult(
            attempted=True,
            message="update check unavailable; starting the installed version",
        )

    if completed.returncode:
        return UpdateResult(
            attempted=True,
            message="update check unavailable; starting the installed version",
        )
    if before == after:
        return UpdateResult(attempted=True, message="application is up to date")

    old_version, old_commit = before
    new_version, new_commit = after
    old_label = old_commit[:8] if old_commit else old_version
    new_label = new_commit[:8] if new_commit else new_version
    return UpdateResult(
        attempted=True,
        restart_required=True,
        message=f"updated with {manager_name}: {old_label} -> {new_label}",
    )


def restart(argv: list[str]) -> None:
    """Replace the launcher once so newly installed modules are imported."""
    environment = os.environ.copy()
    environment[_RESTART_ENV] = "1"
    # The executable and module are fixed; arguments are passed without a shell.
    os.execve(  # nosec B606
        sys.executable,
        [sys.executable, "-m", "recon.launch", *argv],
        environment,
    )
