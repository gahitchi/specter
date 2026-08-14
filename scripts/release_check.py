"""Validate source metadata and built release artifacts before publication."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_WHEEL_FILES = {
    "recon/data/calibration_labels.json",
    "recon/data/sites.json",
    "recon/migrations/versions/20260814_0004_job_activity.py",
    "recon/web/app.js",
    "recon/web/index.html",
    "recon/web/style.css",
}
REQUIRED_SDIST_FILES = {
    "CHANGELOG.md",
    "LICENSE",
    "PRODUCTION.md",
    "README.md",
    "RELEASING.md",
    "pyproject.toml",
}
PROJECT_URLS = {"Homepage", "Documentation", "Repository", "Issues", "Changelog"}
SENSITIVE_DIRS = {"backups", "reports"}
SENSITIVE_FILES = {
    ".env",
    "admin_password",
    "canaries.json",
    "db_dsn",
    "db_password",
    "keys.toml",
    "metrics_token",
    "redis_dsn",
    "redis_password",
    "wmn-data.json",
}
SENSITIVE_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".dump",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
)
RELEASE_VERSION = re.compile(
    r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}(?:[a-z0-9.-]+)?"
)


def _version_from_source() -> str:
    content = (ROOT / "src" / "recon" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    if match is None:
        raise ValueError("src/recon/__init__.py does not define __version__")
    return match.group(1)


def _is_release_version(value: str) -> bool:
    return RELEASE_VERSION.fullmatch(value) is not None


def _normalized_archive_names(names: list[str]) -> set[str]:
    normalized: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        parts = path.parts
        if len(parts) > 1 and re.match(r"^osint[_-]recon-[^/]+$", parts[0]):
            path = PurePosixPath(*parts[1:])
        normalized.add(path.as_posix())
    return normalized


def _sensitive_members(names: set[str]) -> list[str]:
    violations: list[str] = []
    for name in names:
        path = PurePosixPath(name)
        lowered_parts = tuple(part.lower() for part in path.parts)
        basename = path.name.lower()
        if any(part in SENSITIVE_DIRS for part in lowered_parts):
            violations.append(name)
        elif basename in SENSITIVE_FILES and not basename.endswith(".example"):
            violations.append(name)
        elif basename.endswith(SENSITIVE_SUFFIXES):
            violations.append(name)
    return sorted(violations)


def _check_changelog(version: str, tag: str | None, errors: list[str]) -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\] - (Unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.MULTILINE,
    )
    if match is None:
        errors.append(f"CHANGELOG.md has no heading for {version}")
        return
    if tag and match.group(1) == "Unreleased":
        errors.append(f"CHANGELOG.md must date {version} before creating {tag}")


def _check_wheel(wheel: Path, version: str, errors: list[str]) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        missing = REQUIRED_WHEEL_FILES - names
        if missing:
            errors.append(f"wheel is missing required files: {sorted(missing)}")
        sensitive = _sensitive_members(names)
        if sensitive:
            errors.append(f"wheel contains sensitive paths: {sensitive}")

        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_paths = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata_paths) != 1:
            errors.append("wheel must contain exactly one METADATA file")
            return
        metadata = Parser().parsestr(archive.read(metadata_paths[0]).decode("utf-8"))
        if metadata.get("Name") != "osint-recon":
            errors.append("wheel metadata has the wrong project name")
        if metadata.get("Version") != version:
            errors.append("wheel metadata version does not match pyproject.toml")
        if metadata.get("Requires-Python") != ">=3.10":
            errors.append("wheel metadata has an unexpected Requires-Python value")
        if metadata.get("License-Expression") != "MIT":
            errors.append("wheel metadata must contain License-Expression: MIT")
        urls = {
            value.split(",", 1)[0].strip()
            for value in metadata.get_all("Project-URL", failobj=[])
        }
        if missing_urls := PROJECT_URLS - urls:
            errors.append(f"wheel metadata is missing project URLs: {sorted(missing_urls)}")
        if len(entry_paths) != 1:
            errors.append("wheel must contain console entry points")
        else:
            entries = archive.read(entry_paths[0]).decode("utf-8")
            for command in ("recon = recon.cli:main", "specter = recon.launch:main"):
                if command not in entries:
                    errors.append(f"wheel is missing entry point: {command}")


def _check_sdist(sdist: Path, errors: list[str]) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = _normalized_archive_names(archive.getnames())
    missing = REQUIRED_SDIST_FILES - names
    if missing:
        errors.append(f"source distribution is missing required files: {sorted(missing)}")
    sensitive = _sensitive_members(names)
    if sensitive:
        errors.append(f"source distribution contains sensitive paths: {sensitive}")


def validate(dist_dir: Path, tag: str | None = None) -> list[str]:
    errors: list[str] = []
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    version = str(project["version"])
    source_version = _version_from_source()

    if not _is_release_version(version):
        errors.append(f"project version is not release-shaped: {version}")
    if source_version != version:
        errors.append(f"source version {source_version} does not match project version {version}")
    if tag and tag != f"v{version}":
        errors.append(f"tag {tag} does not match project version v{version}")
    _check_changelog(version, tag, errors)

    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1:
        errors.append(f"expected one wheel in {dist_dir}, found {len(wheels)}")
    else:
        _check_wheel(wheels[0], version, errors)
    if len(sdists) != 1:
        errors.append(f"expected one source distribution in {dist_dir}, found {len(sdists)}")
    else:
        _check_sdist(sdists[0], errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME"))
    args = parser.parse_args()

    errors = validate(args.dist_dir.resolve(), args.tag)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Release metadata and artifacts are internally consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
