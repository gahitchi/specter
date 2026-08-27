import dataclasses
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from recon.adapters.base import ExternalObservation, ObservationDisposition
from recon.adapters.conformance import conformance_errors
from recon.adapters.maigret import (
    AdapterInputError,
    MaigretRun,
    parse_maigret_report,
    run_maigret,
    MANIFEST,
    compatibility,
)
from recon.adapters.process import (
    ProcessOutputLimitError,
    ProcessResult,
    ProcessTimeoutError,
    run_process,
    sanitized_environment,
)
from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.models import Query, Verdict
from recon.modules import maigret as maigret_module
from recon.modules.base import ModuleContext
from recon.trust.independence import class_of


def _claimed(site: str, url: str) -> str:
    return json.dumps({
        "sitename": site,
        "url_user": url,
        "status": {"status": "Claimed"},
        "tags": ["coding"],
    })


def test_maigret_report_is_deduplicated_public_and_candidate_only():
    observations = parse_maigret_report([
        "\n".join([
            _claimed("GitHub", "https://github.com/alice"),
            _claimed("GitHub", "https://github.com/alice#overview"),
            _claimed("Local", "http://127.0.0.1/alice"),
            json.dumps({
                "sitename": "Missing",
                "url_user": "https://example.com/alice",
                "status": {"status": "Available"},
            }),
        ])
    ], tool_version="0.6.4")

    assert len(observations) == 1
    assert observations[0].disposition == ObservationDisposition.CANDIDATE
    assert observations[0].artifact_type == ArtifactType.URL
    assert observations[0].confidence == 0.55
    assert observations[0].provenance.tool_version == "0.6.4"


def test_external_observation_contract_rejects_unknown_fields():
    payload = parse_maigret_report([_claimed("GitHub", "https://github.com/alice")])[0]
    with pytest.raises(ValidationError):
        ExternalObservation.model_validate({**payload.model_dump(), "surprise": True})

    with pytest.raises(ValidationError, match="timezone"):
        ExternalObservation.model_validate({
            **payload.model_dump(),
            "observed_at": datetime(2026, 8, 25, 12, 0),
        })


def test_external_and_native_checks_share_the_platform_independence_class():
    assert class_of("external:maigret:GitHub") == class_of("username:GitHub")


def test_maigret_replay_conforms_to_adapter_contract():
    fixture = Path(__file__).parent / "fixtures" / "maigret" / "claimed_replay.ndjson"
    observations = parse_maigret_report([fixture.read_text(encoding="utf-8")], tool_version="0.6.4")

    assert conformance_errors(MANIFEST, observations) == []
    assert observations[0].policy.candidate_only is True
    assert observations[0].provenance.extraction.location == "claimed-site:GitHub"


def test_maigret_compatibility_reports_supported_and_unsupported_versions(monkeypatch):
    monkeypatch.setattr("recon.adapters.maigret.resolve_command", lambda _value: ("maigret",))
    monkeypatch.setattr("recon.adapters.maigret._tool_version", lambda: "0.6.4")
    assert compatibility().compatible is True

    monkeypatch.setattr("recon.adapters.maigret._tool_version", lambda: "0.7.1")
    result = compatibility()
    assert result.compatible is False
    assert result.supported == ">=0.6.4,<0.7"


def test_sanitized_environment_does_not_forward_credentials():
    result = sanitized_environment({
        "PATH": "safe-path",
        "HOME": "/home/alice",
        "RECON_KEY_SHODAN": "secret",
        "OPENAI_API_KEY": "secret",
    })

    assert result["PATH"] == "safe-path"
    assert result["HOME"] == "/home/alice"
    assert "RECON_KEY_SHODAN" not in result
    assert "OPENAI_API_KEY" not in result


@pytest.mark.asyncio
async def test_process_runner_uses_argument_array_and_scrubbed_environment(monkeypatch):
    monkeypatch.setenv("RECON_KEY_TEST", "must-not-leak")
    code = (
        "import os,sys;"
        "print(sys.argv[1]);"
        "print(os.environ.get('RECON_KEY_TEST','absent'))"
    )
    result = await run_process(
        [sys.executable, "-c", code, "literal;not-a-shell"],
        timeout_seconds=10,
        max_output_bytes=4096,
    )

    assert result.stdout.decode().splitlines() == ["literal;not-a-shell", "absent"]


@pytest.mark.asyncio
async def test_process_runner_enforces_time_and_output_limits():
    with pytest.raises(ProcessTimeoutError):
        await run_process(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            timeout_seconds=0.01,
            max_output_bytes=1024,
        )
    with pytest.raises(ProcessOutputLimitError):
        await run_process(
            [sys.executable, "-c", "print('x' * 5000)"],
            timeout_seconds=10,
            max_output_bytes=100,
        )


@pytest.mark.asyncio
async def test_maigret_command_has_hard_bounds(monkeypatch):
    captured = {}

    async def fake_process(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        Path(kwargs["cwd"], "report.ndjson").write_text(
            _claimed("GitHub", "https://github.com/alice"),
            encoding="utf-8",
        )
        return ProcessResult(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("recon.adapters.maigret.resolve_command", lambda _value: ("maigret",))
    monkeypatch.setattr("recon.adapters.maigret._tool_version", lambda: "0.6.4")
    monkeypatch.setattr("recon.adapters.maigret.run_process", fake_process)

    result = await run_maigret("alice")

    assert len(result.observations) == 1
    command = captured["command"]
    assert command[:2] == ["maigret", "alice"]
    assert command[command.index("--top-sites") + 1] == "25"
    assert command[command.index("--max-connections") + 1] == "4"
    assert "--no-recursion" in command
    assert "--no-extracting" in command
    assert "--no-autoupdate" in command
    assert captured["kwargs"]["timeout_seconds"] == 120


@pytest.mark.asyncio
async def test_maigret_rejects_option_like_username_before_launch():
    with pytest.raises(AdapterInputError):
        await run_maigret("--help")


async def _run_module(monkeypatch, *, enabled: bool, observations=()):
    calls = []

    async def fake_run(username, executable):
        calls.append((username, executable))
        return MaigretRun(tuple(observations), "0.6.4")

    monkeypatch.setattr(maigret_module, "run_maigret", fake_run)
    findings, artifacts = [], []

    async def emit_finding(item):
        findings.append(item)

    async def emit_artifact(item):
        artifacts.append(item)

    context = ModuleContext(
        client=object(),
        query=Query(username="alice"),
        settings=dataclasses.replace(SETTINGS, maigret_enabled=enabled),
        in_scope=lambda _item: True,
        _emit_finding=emit_finding,
        _emit_artifact=emit_artifact,
    )
    await maigret_module.MODULE.run(
        Artifact.make(ArtifactType.USERNAME, "alice"),
        context,
    )
    return calls, findings, artifacts


@pytest.mark.asyncio
async def test_maigret_module_is_off_by_default(monkeypatch):
    calls, findings, artifacts = await _run_module(monkeypatch, enabled=False)

    assert calls == []
    assert findings == []
    assert artifacts == []


@pytest.mark.asyncio
async def test_maigret_module_emits_uncertain_url_not_account_profile(monkeypatch):
    observation = parse_maigret_report([
        _claimed("GitHub", "https://github.com/alice")
    ])[0]
    calls, findings, artifacts = await _run_module(
        monkeypatch,
        enabled=True,
        observations=(observation,),
    )

    assert calls == [("alice", None)]
    assert findings[0].verdict == Verdict.UNCERTAIN
    assert findings[0].source == "external:maigret:GitHub"
    assert [artifact.type for artifact in artifacts] == [ArtifactType.URL]
    assert artifacts[0].data["candidate_only"] is True
