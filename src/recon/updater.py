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
from datetime import datetime
from typing import Callable
import urllib.error
import urllib.request

PACKAGE_NAME = "osint-recon"  # Compatibility identifier used by existing installs.
PRODUCT_NAME = "Specter"
UPDATE_INTERVAL_SECONDS = 300.0
GITHUB_API_URL = "https://api.github.com/repos/gahitchi/specter/commits/gpt-branch"
GITHUB_COMMITS_URL = (
    "https://api.github.com/repos/gahitchi/specter/commits?sha=gpt-branch&per_page={limit}"
)
GITHUB_ARCHIVE_URL = "https://github.com/gahitchi/specter/archive/{revision}.tar.gz"
GITHUB_ARCHIVE_URLS = (
    "https://codeload.github.com/gahitchi/specter/tar.gz/{revision}",
    GITHUB_ARCHIVE_URL,
)
_MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
_UPDATE_LOCK = threading.Lock()


@dataclass(frozen=True)
class UpdateResult:
    attempted: bool = False
    update_available: bool = False
    downloaded: bool = False
    applied: bool = False
    message: str = ""


@dataclass(frozen=True)
class AvailableBuild:
    revision: str
    title: str
    authored_at: str
    author: str = ""

    @property
    def date_label(self) -> str:
        try:
            date = datetime.fromisoformat(self.authored_at.replace("Z", "+00:00"))
        except ValueError:
            return "Date unavailable"
        return date.astimezone().strftime("%d %b %Y, %H:%M")


@dataclass(frozen=True)
class UpdateStatus:
    supported: bool
    installed_revision: str | None
    pending_revision: str | None
    pending_title: str | None = None
    pending_selected: bool = False

    @property
    def installed_label(self) -> str:
        return f"Build {self.installed_revision[:12]}" if self.installed_revision else "Unknown"

    @property
    def pending_label(self) -> str:
        if self.pending_title:
            return f"{self.pending_title} (Build {self.pending_revision[:12]})"
        return f"Build {self.pending_revision[:12]}" if self.pending_revision else "None"


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


def explain_update_error(error: BaseException) -> str:
    """Turn updater failures into a short message that a user can act on."""
    if isinstance(error, urllib.error.HTTPError):
        if error.code in {403, 429}:
            return "GitHub temporarily limited update requests; try again in a few minutes"
        if error.code == 404:
            return "that build is no longer available on GitHub"
        return f"GitHub returned HTTP {error.code}"
    if isinstance(error, urllib.error.URLError):
        return "Specter could not reach GitHub; check the internet connection and try again"
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "the request timed out; check the connection and try again"
    if isinstance(error, PermissionError):
        return "Specter could not write to its update folder"
    if isinstance(error, tarfile.TarError):
        return "GitHub returned an unreadable update archive"
    if isinstance(error, json.JSONDecodeError):
        return "GitHub returned an unreadable response"
    if isinstance(error, ValueError):
        return str(error).rstrip(".")
    return "the update service is temporarily unavailable"


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
    except (
        AttributeError,
        importlib.metadata.PackageNotFoundError,
        json.JSONDecodeError,
        TypeError,
    ):
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


def list_available_builds(*, timeout: float = 20.0, limit: int = 20) -> list[AvailableBuild]:
    """Return recent immutable builds from the configured GitHub branch."""
    bounded_limit = max(1, min(limit, 50))
    request = urllib.request.Request(
        GITHUB_COMMITS_URL.format(limit=bounded_limit),
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Specter version history",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        payload = json.loads(response.read(4 * 1024 * 1024))
    if not isinstance(payload, list):
        raise ValueError("GitHub returned an invalid build history")

    builds: list[AvailableBuild] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        revision = _valid_revision(item.get("sha"))
        commit = item.get("commit")
        if revision is None or not isinstance(commit, dict):
            continue
        author = commit.get("author")
        author = author if isinstance(author, dict) else {}
        message = commit.get("message")
        title = str(message).splitlines()[0].strip() if isinstance(message, str) else ""
        builds.append(
            AvailableBuild(
                revision=revision,
                title=title or "Untitled build",
                authored_at=str(author.get("date") or ""),
                author=str(author.get("name") or ""),
            )
        )
    if not builds:
        raise ValueError("GitHub returned no usable builds")
    return builds


def _safe_member_path(member_name: str) -> tuple[str, ...] | None:
    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        return None
    relative = path.parts[1:]
    return relative if relative and all(part not in {"", "."} for part in relative) else None


def _download_archive(revision: str, archive_path: Path, timeout: float) -> None:
    last_error: BaseException | None = None
    for url_template in GITHUB_ARCHIVE_URLS:
        archive_path.unlink(missing_ok=True)
        request = urllib.request.Request(
            url_template.format(revision=revision),
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "Specter update downloader",
            },
        )
        downloaded_bytes = 0
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                content_length = int(response.headers.get("Content-Length", "0") or 0)
                if content_length > _MAX_ARCHIVE_BYTES:
                    raise ValueError("the update archive is too large")
                with archive_path.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        downloaded_bytes += len(chunk)
                        if downloaded_bytes > _MAX_ARCHIVE_BYTES:
                            raise ValueError("the update archive is too large")
                        output.write(chunk)
            if downloaded_bytes == 0:
                raise ValueError("GitHub returned an empty update archive")
            return
        except ValueError:
            archive_path.unlink(missing_ok=True)
            raise
        except (OSError, TimeoutError) as error:
            archive_path.unlink(missing_ok=True)
            last_error = error
    if last_error is None:
        raise OSError("no update download service is configured")
    raise last_error


def _download_revision(revision: str, timeout: float) -> Path:
    root = _cache_root()
    destination = root / revision
    if (destination / "pyproject.toml").is_file():
        return destination

    root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"{revision[:8]}-", dir=root))
    archive_path = temporary / ".specter-update.tar.gz"
    extracted_bytes = 0
    try:
        _download_archive(revision, archive_path, timeout)
        with tarfile.open(archive_path, mode="r:gz") as archive:
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
                    raise ValueError("the expanded update is too large")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("the update archive is incomplete")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                try:
                    target.chmod(member.mode & 0o777)
                except OSError:
                    pass
        archive_path.unlink(missing_ok=True)
        if not (temporary / "pyproject.toml").is_file():
            raise ValueError("the update archive does not contain Specter")
        try:
            os.replace(temporary, destination)
        except FileExistsError:
            shutil.rmtree(temporary, ignore_errors=True)
        return destination
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _pending_metadata() -> dict:
    payload = _read_json(_cache_root() / "pending.json")
    revision = _valid_revision(payload.get("revision"))
    if revision is None:
        return {}
    project = _cache_root() / revision
    if not (project / "pyproject.toml").is_file():
        return {}
    return {
        "revision": revision,
        "project": project,
        "title": str(payload.get("title") or "").strip() or None,
        "selected": payload.get("selected") is True,
    }


def _pending_revision() -> tuple[str, Path] | None:
    pending = _pending_metadata()
    if not pending:
        return None
    return pending["revision"], pending["project"]


def get_update_status() -> UpdateStatus:
    """Return local update state without making a network request."""
    pending = _pending_metadata()
    return UpdateStatus(
        supported=_installation_manager() is not None,
        installed_revision=_installed_revision(),
        pending_revision=pending.get("revision"),
        pending_title=pending.get("title"),
        pending_selected=bool(pending.get("selected")),
    )


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

    with _UPDATE_LOCK:
        try:
            installed = _installed_revision()
            remote = _remote_revision(timeout)
            pending_metadata = _pending_metadata()
            if pending_metadata.get("selected"):
                return UpdateResult(
                    attempted=True,
                    update_available=pending_metadata["revision"] != installed,
                    message="Your selected build is downloaded and ready to install",
                )
            if installed == remote:
                (_cache_root() / "pending.json").unlink(missing_ok=True)
                _prune_cached_revisions()
                return UpdateResult(attempted=True, message=f"{PRODUCT_NAME} is up to date")
            pending = _pending_revision()
            if pending and pending[0] == remote:
                return UpdateResult(
                    attempted=True,
                    update_available=True,
                    message=f"A {PRODUCT_NAME} update is ready to install",
                )
            _download_revision(remote, timeout)
            _write_json(
                _cache_root() / "pending.json",
                {
                    "revision": remote,
                    "downloaded_at": int(time.time()),
                    "selected": False,
                },
            )
            _prune_cached_revisions(keep={remote})
            return UpdateResult(
                attempted=True,
                update_available=True,
                downloaded=True,
                message=f"A {PRODUCT_NAME} update was downloaded and is ready to install",
            )
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
            return UpdateResult(
                attempted=True,
                message=f"Update check failed: {explain_update_error(error)}. Specter will keep running.",
            )


def download_build(
    revision: str, *, title: str | None = None, timeout: float = 60.0
) -> UpdateResult:
    """Cache an exact user-selected build without applying it."""
    validated = _valid_revision(revision)
    if validated is None:
        return UpdateResult(attempted=True, message="The selected build is invalid")
    if _installation_manager() is None:
        return UpdateResult(message="updates are unavailable for this installation")

    with _UPDATE_LOCK:
        if _installed_revision() == validated:
            return UpdateResult(attempted=True, message="That build is already installed")
        try:
            _download_revision(validated, timeout)
            _write_json(
                _cache_root() / "pending.json",
                {
                    "revision": validated,
                    "title": (title or "").strip() or None,
                    "downloaded_at": int(time.time()),
                    "selected": True,
                },
            )
            _prune_cached_revisions(keep={validated})
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
            return UpdateResult(
                attempted=True,
                message=(
                    f"Download failed: {explain_update_error(error)}. "
                    "The installed version was not changed."
                ),
            )
    return UpdateResult(
        attempted=True,
        update_available=True,
        downloaded=True,
        message=f"Build {validated[:12]} is downloaded and ready to install",
    )


def _apply_command(manager: tuple[str, str], project: Path) -> list[str]:
    manager_name, executable = manager
    desktop_project = f"{project}[desktop]"
    if manager_name == "uv":
        return [
            executable,
            "tool",
            "install",
            "--force",
            "--quiet",
            "--no-progress",
            desktop_project,
        ]
    return [executable, "install", "--force", "--quiet", desktop_project]


def _installation_is_healthy(*, timeout: float = 20.0) -> bool:
    """Verify the replacement environment from a fresh Python process."""
    try:
        completed = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-c",
                (
                    "from recon.launch import _icon_path; "
                    "from PySide6 import QtWidgets; "
                    "raise SystemExit(0 if _icon_path().is_file() else 1)"
                ),
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def apply_pending_update(*, timeout: float = 180.0) -> UpdateResult:
    """Apply the exact cached revision after an explicit user request."""
    manager = _installation_manager()
    if manager is None:
        return UpdateResult(message="updates are unavailable for this installation")

    pending = _pending_revision()
    if pending is None:
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
    if completed.returncode or not _installation_is_healthy(timeout=min(timeout, 20.0)):
        return UpdateResult(
            attempted=True,
            update_available=True,
            message=(
                "the downloaded update could not be verified. Run the official installer once "
                "to repair Specter; your research data is unaffected"
            ),
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
        message="Specter was updated successfully",
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
