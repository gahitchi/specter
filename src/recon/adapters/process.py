"""Hardened subprocess execution for optional external adapters."""

from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_ENV_ALLOWLIST = {
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
}


class ExternalProcessError(RuntimeError):
    """Base class for adapter process failures safe to surface to operators."""


class ProcessLaunchError(ExternalProcessError):
    pass


class ProcessTimeoutError(ExternalProcessError):
    pass


class ProcessOutputLimitError(ExternalProcessError):
    pass


class ProcessExecutionError(ExternalProcessError):
    def __init__(self, returncode: int, detail: str = "") -> None:
        self.returncode = returncode
        suffix = f": {detail}" if detail else ""
        super().__init__(f"external tool exited with status {returncode}{suffix}")


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def sanitized_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """Keep only process essentials; API keys and Specter secrets never cross over."""
    if source is None:
        source = dict(os.environ)
    result = {
        key: value
        for key, value in source.items()
        if key.upper() in _ENV_ALLOWLIST
    }
    result["PYTHONIOENCODING"] = "utf-8"
    result["PYTHONUNBUFFERED"] = "1"
    return result


def _validate_command(command: Iterable[str]) -> tuple[str, ...]:
    values = tuple(command)
    if not values:
        raise ProcessLaunchError("external command is empty")
    if any(not isinstance(value, str) for value in values):
        raise ProcessLaunchError("external command arguments must be strings")
    if any(not value or "\x00" in value or len(value) > 32_768 for value in values):
        raise ProcessLaunchError("external command contains an invalid argument")
    return values


async def _read_limited(
    stream: asyncio.StreamReader | None,
    limit: int,
) -> bytes:
    if stream is None:
        return b""
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise ProcessOutputLimitError("external tool output exceeded its limit")
        chunks.append(chunk)


async def run_process(
    command: Iterable[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    cwd: str | Path | None = None,
) -> ProcessResult:
    """Execute without a shell and kill on timeout or excessive output."""
    values = _validate_command(command)
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise ValueError("process limits must be positive")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        process = await asyncio.create_subprocess_exec(
            *values,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            env=sanitized_environment(),
            creationflags=creationflags,
        )
    except (OSError, ValueError) as exc:
        raise ProcessLaunchError(f"external tool could not start: {exc}") from exc

    try:
        returncode, stdout, stderr = await asyncio.wait_for(
            asyncio.gather(
                process.wait(),
                _read_limited(process.stdout, max_output_bytes),
                _read_limited(process.stderr, max_output_bytes),
            ),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise ProcessTimeoutError(
            f"external tool exceeded {timeout_seconds:g} seconds"
        ) from exc
    except BaseException:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
        raise

    result = ProcessResult(returncode=returncode, stdout=stdout, stderr=stderr)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise ProcessExecutionError(result.returncode, detail)
    return result
