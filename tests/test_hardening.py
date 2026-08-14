"""Cross-cutting regression tests for packaging, semantics, and failure safety."""

import dataclasses
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from recon import orchestrator
from recon.calibrate import metrics
from recon.calibrate.labels import labels_file
from recon.collectors.name import collect as collect_name
from recon.config import SETTINGS
from recon.http_client import RequestBudgetExceeded
from recon.keys import KeyVault, VAULT, redact
from recon.models import Finding, Query, Verdict
from recon.store import get_db
from recon.store import models_db as m


def test_only_found_is_a_confirmed_hit():
    found = Finding(source="s", category="c", label="found", verdict=Verdict.FOUND)
    uncertain = Finding(
        source="s", category="c", label="candidate", verdict=Verdict.UNCERTAIN
    )
    assert found.is_hit is True
    assert uncertain.is_hit is False
    assert uncertain.is_candidate is True
    assert uncertain.is_notable is True


def test_small_calibration_fixture_is_explicitly_advisory():
    report = metrics.summary(
        [metrics.Sample(0.9, True), metrics.Sample(0.1, False)], 0.75, 0.4
    )
    assert report["sample_quality"]["adequate"] is False
    assert report["sample_quality"]["warning"]
    assert report["suggestion"]["advisory_only"] is True


def test_packaged_dashboard_and_datasets_exist():
    package = Path(orchestrator.__file__).resolve().parent
    assert (package / "web" / "index.html").is_file()
    assert Path(SETTINGS.sites_data_file).is_file()
    assert labels_file().is_file()


def test_settings_reject_invalid_limits():
    with pytest.raises(ValueError, match="positive"):
        dataclasses.replace(SETTINGS, max_requests=0)
    with pytest.raises(ValueError, match="scope_mode"):
        dataclasses.replace(SETTINGS, scope_mode="everywhere")


def test_secret_redaction(monkeypatch):
    monkeypatch.setenv("RECON_KEY_SHODAN", "super-secret")
    VAULT.reload()
    assert redact("failed https://x/?key=super-secret") == "failed https://x/?key=[REDACTED]"


def test_keyring_backend_does_not_touch_plaintext_file(tmp_path, monkeypatch):
    values = {}
    monkeypatch.setenv("RECON_KEY_BACKEND", "keyring")
    monkeypatch.setattr(
        KeyVault, "_keyring_get", staticmethod(lambda name: values.get(name))
    )
    monkeypatch.setattr(
        KeyVault,
        "_keyring_write",
        staticmethod(lambda name, value: values.__setitem__(name, value)),
    )
    vault = KeyVault(tmp_path / "keys.toml")
    vault.set("shodan", "secret")
    assert vault.get("shodan") == "secret"
    assert vault.source("shodan") == "keyring"
    assert not vault.path.exists()
    vault.clear("shodan")
    assert vault.get("shodan") is None


@pytest.mark.asyncio
async def test_name_collector_uses_managed_client_and_propagates_budget():
    class StubClient:
        def __init__(self):
            self.calls = []

        async def fetch(self, url, **kwargs):
            self.calls.append((url, kwargs))
            if "orcid.org" in url:
                return httpx.Response(200, json={"expanded-result": []})
            return httpx.Response(200, json={"results": []})

    async def emit(_finding):
        pass

    client = StubClient()
    await collect_name(Query(name="Ada Lovelace"), client, emit)
    assert len(client.calls) == 2
    assert client.calls[0][1]["headers"] == {"Accept": "application/json"}

    async def exhausted(_url, **_kwargs):
        raise RequestBudgetExceeded("done")

    client.fetch = exhausted
    with pytest.raises(RequestBudgetExceeded):
        await collect_name(Query(name="Ada Lovelace"), client, emit)


@pytest.mark.asyncio
async def test_failed_scan_marks_durable_run_error(monkeypatch):
    async def broken_stream(_self):
        if False:
            yield None
        raise RuntimeError("unexpected engine failure")

    monkeypatch.setattr(orchestrator.GraphScanEngine, "stream", broken_stream)
    with pytest.raises(RuntimeError, match="unexpected engine failure"):
        await orchestrator.scan(Query(username="alice"))

    with get_db().session() as session:
        run = session.execute(select(m.Run).order_by(m.Run.id.desc())).scalars().first()
        assert run.status == "error"
        assert run.finished_at is not None
        assert run.stats["error"] == "unexpected engine failure"
