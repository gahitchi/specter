"""Optional Maigret adapter that returns profile candidates, never identities."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..graph_models import ArtifactType
from ..evidence import Completeness, EvidencePolicy, ExtractionProvenance
from ..web_document import collapse_text, public_http_url
from .base import (
    AdapterManifest,
    ExternalObservation,
    ObservationDisposition,
    ObservationProvenance,
)
from .conformance import assert_conformant
from .process import ProcessOutputLimitError, run_process

_TOP_SITES = 25
_MAX_CONNECTIONS = 4
_SITE_TIMEOUT_SECONDS = 8
_PROCESS_TIMEOUT_SECONDS = 120
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_CANDIDATES = 25
_USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class AdapterUnavailableError(RuntimeError):
    pass


class AdapterInputError(ValueError):
    pass


@dataclass(frozen=True)
class MaigretRun:
    observations: tuple[ExternalObservation, ...]
    tool_version: str | None


@dataclass(frozen=True)
class AdapterCompatibility:
    available: bool
    compatible: bool | None
    version: str | None
    supported: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "compatible": self.compatible,
            "version": self.version,
            "supported": self.supported,
            "detail": self.detail,
        }


MANIFEST = AdapterManifest(
    adapter="maigret",
    display_name="Maigret username discovery",
    consumes=(ArtifactType.USERNAME,),
    candidate_only=True,
    external_network=True,
    interaction="external public-site probes",
    capabilities=("username-candidate-discovery", "bounded-subprocess"),
    supported_tool_versions=">=0.6.4,<0.7",
)


def _tool_version() -> str | None:
    try:
        return importlib.metadata.version("maigret")[:80]
    except importlib.metadata.PackageNotFoundError:
        return None


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", value.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def compatibility(executable: str | None = None) -> AdapterCompatibility:
    supported = ">=0.6.4,<0.7"
    try:
        resolve_command(executable)
    except AdapterUnavailableError as exc:
        return AdapterCompatibility(False, None, None, supported, str(exc))
    version = _tool_version()
    parsed = _version_tuple(version) if version else None
    if parsed is None:
        return AdapterCompatibility(
            True,
            None,
            version,
            supported,
            "Maigret is available, but its installed package version could not be verified.",
        )
    compatible = (0, 6, 4) <= parsed < (0, 7, 0)
    detail = (
        "Installed Maigret version is supported."
        if compatible
        else f"Installed Maigret {version} is outside Specter's supported range {supported}."
    )
    return AdapterCompatibility(True, compatible, version, supported, detail)


def resolve_command(executable: str | None = None) -> tuple[str, ...]:
    if executable:
        if "\x00" in executable or len(executable) > 2048:
            raise AdapterUnavailableError("configured Maigret executable is invalid")
        path = Path(executable).expanduser()
        resolved = str(path.resolve()) if path.is_file() else shutil.which(executable)
        if not resolved:
            raise AdapterUnavailableError("configured Maigret executable was not found")
        return (resolved,)

    discovered = shutil.which("maigret")
    if discovered:
        return (discovered,)
    if importlib.util.find_spec("maigret") is not None:
        return (sys.executable, "-m", "maigret")
    raise AdapterUnavailableError(
        "Maigret is not installed; install Specter's optional 'maigret' extra"
    )


def _report_rows(payload: str) -> list[dict[str, Any]]:
    payload = payload.strip()
    if not payload:
        return []
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, list):
        return [row for row in decoded if isinstance(row, dict)]
    if isinstance(decoded, dict):
        return [decoded]

    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        if len(line) > 100_000:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _claimed(row: dict[str, Any]) -> bool:
    status = row.get("status")
    if isinstance(status, dict):
        status = status.get("status")
    return isinstance(status, str) and status.casefold() == "claimed"


def parse_maigret_report(
    payloads: Iterable[str],
    *,
    tool_version: str | None = None,
) -> tuple[ExternalObservation, ...]:
    observations: list[ExternalObservation] = []
    seen: set[str] = set()
    for payload in payloads:
        for row in _report_rows(payload):
            if not _claimed(row):
                continue
            raw_url = row.get("url_user") or row.get("url")
            if not isinstance(raw_url, str):
                continue
            url = public_http_url(raw_url, raw_url)
            if not url or url in seen:
                continue
            seen.add(url)
            site = collapse_text(
                str(row.get("sitename") or row.get("site_name") or "Unknown site")
            )[:120] or "Unknown site"
            tags = row.get("tags")
            if not isinstance(tags, list):
                site_data = row.get("site")
                tags = site_data.get("tags", []) if isinstance(site_data, dict) else []
            clean_tags = (
                [collapse_text(str(tag))[:80] for tag in tags[:20] if collapse_text(str(tag))]
                if isinstance(tags, list)
                else []
            )
            observations.append(ExternalObservation(
                adapter="maigret",
                artifact_type=ArtifactType.URL,
                value=url,
                url=url,
                label=f"{site} profile candidate",
                disposition=ObservationDisposition.CANDIDATE,
                confidence=0.55,
                reasons=[
                    "Maigret reported a claimed username response for this site.",
                    "The response is a candidate lead and does not establish common ownership.",
                ],
                provenance=ObservationProvenance(
                    operator=site,
                    interaction="external public-site probe",
                    method="Maigret bounded username check",
                    independence_class=f"site:{site.casefold()}",
                    data_sent=["username"],
                    tool_version=tool_version,
                    origin=(urlsplit(url).hostname or site).casefold(),
                    extraction=ExtractionProvenance(
                        method="maigret-json-report",
                        location=f"claimed-site:{site}",
                        document_url=url,
                        extracted_value=url,
                        extractor="maigret",
                        extractor_version=tool_version,
                        direct=False,
                        transformation_chain=["JSON report", "public URL validation"],
                        transformation_certainty=0.7,
                    ),
                ),
                completeness=Completeness.PARTIAL,
                policy=EvidencePolicy.candidate(),
                attributes={"site": site, "tags": clean_tags},
            ))
            if len(observations) >= _MAX_CANDIDATES:
                return tuple(observations)
    return tuple(observations)


def _read_reports(folder: Path) -> list[str]:
    root = folder.resolve()
    payloads: list[str] = []
    total = 0
    for path in sorted(folder.glob("*"))[:20]:
        if path.suffix.casefold() not in {".json", ".ndjson"} or not path.is_file():
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            continue
        size = resolved.stat().st_size
        total += size
        if size > _MAX_OUTPUT_BYTES or total > _MAX_OUTPUT_BYTES:
            raise ProcessOutputLimitError("Maigret report exceeded its size limit")
        payloads.append(resolved.read_text(encoding="utf-8", errors="replace"))
    return payloads


async def run_maigret(username: str, executable: str | None = None) -> MaigretRun:
    if not _USERNAME_RE.fullmatch(username):
        raise AdapterInputError("Maigret accepts usernames up to 64 simple characters")
    prefix = resolve_command(executable)
    version = _tool_version()
    parsed_version = _version_tuple(version) if version else None
    if parsed_version is not None and not (0, 6, 4) <= parsed_version < (0, 7, 0):
        raise AdapterUnavailableError(
            f"installed Maigret {version} is incompatible; supported range is >=0.6.4,<0.7"
        )
    with tempfile.TemporaryDirectory(prefix="specter-maigret-") as directory:
        output = Path(directory)
        command = [
            *prefix,
            username,
            "--json",
            "ndjson",
            "--folderoutput",
            str(output),
            "--top-sites",
            str(_TOP_SITES),
            "--max-connections",
            str(_MAX_CONNECTIONS),
            "--timeout",
            str(_SITE_TIMEOUT_SECONDS),
            "--retries",
            "0",
            "--no-recursion",
            "--no-extracting",
            "--no-autoupdate",
            "--no-color",
            "--no-progressbar",
        ]
        result = await run_process(
            command,
            timeout_seconds=_PROCESS_TIMEOUT_SECONDS,
            max_output_bytes=_MAX_OUTPUT_BYTES,
            cwd=output,
        )
        payloads = _read_reports(output)
        if not payloads:
            payloads = [result.stdout.decode("utf-8", errors="replace")]
        observations = parse_maigret_report(payloads, tool_version=version)
        assert_conformant(MANIFEST, observations)
        return MaigretRun(observations=observations, tool_version=version)
