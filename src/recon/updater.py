"""Download Specter updates in the background and apply them only on request."""

from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable
import urllib.request

PACKAGE_NAME = "osint-recon"  # Compatibility identifier used by existing installs.
PRODUCT_NAME = "Specter"
UPDATE_INTERVAL_SECONDS = 300.0
GITHUB_API_URL = "https://api.github.com/repos/gahitchi/osint-recon/commits/gpt-branch"
GITHUB_ARCHIVE_URL = "https://github.com/gahitchi/osint-recon/archive/{revision}.tar.gz"
_MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 250 * 1024 * 1024


@dataclass(frozen=True)
class UpdateResult:
    attempted: bool = False
    update_available: bool = False
    downloaded: bool = False
    applied: bool = False
    message: str = ""


@dataclass
class UpdateMonitor:
    stop_event: threading.Event
    thread: threading.Thread

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=1)


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


def _installation_manager() -> tuple[str, str] | None:
    """Return the package manager only when it owns this Python environment."""
    uv = shutil.which("uv")
    if uv:
        tool_dir = _command_output([uv, "tool", "dir"])
        if tool_dir and _within(Path(sys.prefix), Path(tool_dir)):
            return "uv", uv

    pipx = shutil.which("pipx")
    if pipx:
        venv_dir = _command_output([pipx, "environment", "--value", "PIPX_LOCAL_VENVS"])
        if venv_dir and _within(Path(sys.prefix), Path(venv_dir)):
            return "pipx", pipx
    return None


def _cache_root() -> Path:
    override = os.environ.get("SPECTER_UPDATE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Specter" / "updates"
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "specter" / "updates"


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _valid_revision(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 40:
        return None
    lowered = value.lower()
    return lowered if all(char in "0123456789abcdef" for char in lowered) else None


def _installed_revision() -> str | None:
    try:
        distribution = importlib.metadata.distribution(PACKAGE_NAME)
        direct_url = distribution.read_text("direct_url.json")
        if direct_url:
            payload = json.loads(direct_url)
            revision = _valid_revision((payload.get("vcs_info") or {}).get("commit_id"))
            if revision:
                return revision
    except (AttributeError, importlib.metadata.PackageNotFoundError, json.JSONDecodeError, TypeError):
        pass
    return _valid_revision(_read_json(_cache_root() / "installed.json").get("revision"))


def _remote_revision(timeout: float) -> str:
    request = urllib.request.Request(
        GITHUB_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Specter update checker",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        payload = json.loads(response.read(1024 * 1024))
    revision = _valid_revision(payload.get("sha") if isinstance(payload, dict) else None)
    if revision is None:
        raise ValueError("GitHub returned an invalid revision")
    return revision


def _safe_member_path(member_name: str) -> tuple[str, ...] | None:
    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        return None
    relative = path.parts[1:]
    return relative if relative and all(part not in {"", "."} for part in relative) else None


def _download_revision(revision: str, timeout: float) -> Path:
    root = _cache_root()
    destination = root / revision
    if (destination / "pyproject.toml").is_file():
        return destination

    root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"{revision[:8]}-", dir=root))
    request = urllib.request.Request(
        GITHUB_ARCHIVE_URL.format(revision=revision),
        headers={"User-Agent": "Specter update downloader"},
    )
    extracted_bytes = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            content_length = int(response.headers.get("Content-Length", "0") or 0)
            if content_length > _MAX_ARCHIVE_BYTES:
                raise ValueError("update archive is too large")
            with tarfile.open(fileobj=response, mode="r|gz") as archive:
                for member in archive:
                    relative = _safe_member_path(member.name)
                    if relative is None:
                        if len(PurePosixPath(member.name).parts) == 1 and member.isdir():
                            continue
                        raise ValueError("update archive contains an unsafe path")
                    target = temporary.joinpath(*relative)
                    if not _within(target, temporary):
                        raise ValueError("update archive escapes its destination")
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isfile():
                        raise ValueError("update archive contains unsupported entries")
                    extracted_bytes += member.size
                    if extracted_bytes > _MAX_EXTRACTED_BYTES:
                        raise ValueError("expanded update is too large")
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("update archive is incomplete")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    try:
                        target.chmod(member.mode & 0o777)
                    except OSError:
                        pass
        if not (temporary / "pyproject.toml").is_file():
            raise ValueError("update archive does not contain Specter")
        try:
            os.replace(temporary, destination)
        except FileExistsError:
            shutil.rmtree(temporary, ignore_errors=True)
        return destination
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _pending_revision() -> tuple[str, Path] | None:
    revision = _valid_revision(_read_json(_cache_root() / "pending.json").get("revision"))
    if revision is None:
        return None
    project = _cache_root() / revision
    return (revision, project) if (project / "pyproject.toml").is_file() else None


def _prune_cached_revisions(*, keep: set[str] | None = None) -> None:
    keep = keep or set()
    root = _cache_root()
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.is_dir() and _valid_revision(entry.name) and entry.name not in keep:
            shutil.rmtree(entry, ignore_errors=True)


def check_for_update(
    *, enabled: bool = True, force: bool = False, timeout: float = 20.0
) -> UpdateResult:
    """Check GitHub and cache a new immutable revision without installing it."""
    if not enabled or (not force and not _env_enabled("RECON_AUTO_UPDATE")):
        return UpdateResult(message="update checks disabled")
    if os.environ.get("RECON_ENV", "development").strip().lower() == "production":
        return UpdateResult(message="update checks are disabled in production")
    if _installation_manager() is None:
        return UpdateResult()

    try:
        installed = _installed_revision()
        remote = _remote_revision(timeout)
        if installed == remote:
            (_cache_root() / "pending.json").unlink(missing_ok=True)
            return UpdateResult(attempted=True, message=f"{PRODUCT_NAME} is up to date")
        pending = _pending_revision()
        if pending and pending[0] == remote:
            return UpdateResult(
                attempted=True,
                update_available=True,
                message=f"{PRODUCT_NAME} update {remote[:8]} is ready; run specter --update",
            )
        _download_revision(remote, timeout)
        _write_json(
            _cache_root() / "pending.json",
            {"revision": remote, "downloaded_at": int(time.time())},
        )
        _prune_cached_revisions(keep={remote})
        return UpdateResult(
            attempted=True,
            update_available=True,
            downloaded=True,
            message=f"{PRODUCT_NAME} update {remote[:8]} downloaded; run specter --update",
        )
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError):
        return UpdateResult(
            attempted=True,
            message="update check unavailable; Specter will keep running",
        )


def _apply_command(manager: tuple[str, str], project: Path) -> list[str]:
    manager_name, executable = manager
    if manager_name == "uv":
        return [
            executable,
            "tool",
            "install",
            "--force",
            "--reinstall-package",
            PACKAGE_NAME,
            "--quiet",
            "--no-progress",
            str(project),
        ]
    return [executable, "install", "--force", "--quiet", str(project)]


def apply_pending_update(*, timeout: float = 180.0) -> UpdateResult:
    """Apply the newest cached revision after an explicit user request."""
    manager = _installation_manager()
    if manager is None:
        return UpdateResult(message="updates are unavailable for this installation")

    check = check_for_update(force=True, timeout=min(timeout, 20.0))
    pending = _pending_revision()
    if pending is None:
        return check
    revision, project = pending
    try:
        completed = subprocess.run(  # nosec B603
            _apply_command(manager, project),
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return UpdateResult(
            attempted=True,
            update_available=True,
            message="the downloaded update could not be applied; the current version is unchanged",
        )
    if completed.returncode:
        return UpdateResult(
            attempted=True,
            update_available=True,
            message="the downloaded update could not be applied; the current version is unchanged",
        )
    _write_json(
        _cache_root() / "installed.json",
        {"revision": revision, "applied_at": int(time.time())},
    )
    (_cache_root() / "pending.json").unlink(missing_ok=True)
    _prune_cached_revisions()
    return UpdateResult(
        attempted=True,
        applied=True,
        message=f"Specter update {revision[:8]} applied; start Specter normally",
    )


def start_update_monitor(
    *,
    enabled: bool = True,
    interval: float = UPDATE_INTERVAL_SECONDS,
    notify: Callable[[str], None] | None = None,
) -> UpdateMonitor | None:
    """Start a daemon that checks immediately and then at the requested interval."""
    if not enabled or not _env_enabled("RECON_AUTO_UPDATE"):
        return None
    if os.environ.get("RECON_ENV", "development").strip().lower() == "production":
        return None
    if _installation_manager() is None:
        return None

    stop_event = threading.Event()

    def run() -> None:
        first = True
        while not stop_event.is_set():
            result = check_for_update()
            if notify and result.update_available and (first or result.downloaded):
                notify(result.message)
            first = False
            if stop_event.wait(interval):
                break

    thread = threading.Thread(target=run, name="specter-update-monitor", daemon=True)
    thread.start()
    return UpdateMonitor(stop_event, thread)
