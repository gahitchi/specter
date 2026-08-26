import dataclasses
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from recon import cli, expansion, jobs, server
from recon.auth import create_user
from recon.config import Settings, env_value
from recon.jobs.base import LocalQueue
from recon.security import LoginRateLimiter
from recon.store import get_db
from recon.store.db import Database


ROOT = Path(__file__).resolve().parents[1]


def _login(client, username, password):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def test_platform_installers_create_and_remove_desktop_and_menu_launchers():
    windows_install = (ROOT / "install.ps1").read_text(encoding="utf-8")
    windows_uninstall = (ROOT / "uninstall.ps1").read_text(encoding="utf-8")
    linux_install = (ROOT / "install.sh").read_text(encoding="utf-8")
    linux_uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")

    assert "SpecialFolder]::Programs" in windows_install
    assert "SpecialFolder]::DesktopDirectory" in windows_install
    assert 'Join-Path $env:LOCALAPPDATA "Specter\\assets"' in windows_install
    assert "Copy-Item -LiteralPath $IconPath -Destination $StableIconPath" in windows_install
    assert "Remove-Item -LiteralPath $Path -Force" in windows_install
    assert '$Shortcut.IconLocation = "$StableIconPath,0"' in windows_install
    assert "SpecialFolder]::Programs" in windows_uninstall
    assert "SpecialFolder]::DesktopDirectory" in windows_uninstall
    assert 'Join-Path $env:LOCALAPPDATA "Specter\\assets"' in windows_uninstall
    assert '$applications_directory/specter.desktop' in linux_install
    assert '$desktop_directory/Specter.desktop' in linux_install
    assert '$data_directory/applications/specter.desktop' in linux_uninstall
    assert '$desktop_directory/Specter.desktop' in linux_uninstall


def test_health_metrics_and_request_body_limit(monkeypatch, tmp_path):
    token = "m" * 32
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "specter-data"))
    monkeypatch.setattr(server, "SETTINGS", dataclasses.replace(
        server.SETTINGS, metrics_enabled=True, metrics_token=token
    ))
    client = TestClient(server.app)

    assert client.get("/health/live").json()["status"] == "alive"
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["components"]["database"]["ready"] is True
    assert client.get("/metrics").status_code == 401
    metrics = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert metrics.status_code == 200
    assert "recon_http_requests_total" in metrics.text
    assert "path=" not in metrics.text

    too_large = client.post(
        "/api/keys", json={"name": "shodan", "value": "x" * 70_000}
    )
    assert too_large.status_code == 413
    review_import = client.post(
        "/api/evaluation-kit/finalize", json={"review_csv": "x" * 70_000}
    )
    assert review_import.status_code == 400


def test_production_defaults_and_secret_file(monkeypatch, tmp_path):
    secret = tmp_path / "metrics-token"
    secret.write_text("s" * 32 + "\n", encoding="utf-8")
    monkeypatch.setenv("RECON_ENV", "production")
    monkeypatch.setenv("RECON_METRICS_TOKEN_FILE", str(secret))
    settings = Settings()
    assert settings.production_mode is True
    assert settings.auto_migrate is False
    assert settings.allow_live_scans is False
    assert settings.allow_key_writes is False
    assert settings.log_format == "json"
    assert env_value("RECON_METRICS_TOKEN") == "s" * 32


def test_schema_check_fails_closed_without_explicit_upgrade(tmp_path):
    dsn = f"sqlite:///{tmp_path / 'empty.db'}"
    with Database(dsn) as db:
        with pytest.raises(RuntimeError, match="specter db-upgrade"):
            db.ensure_schema(auto_upgrade=False)
        db.create_all()
        db.ensure_schema(auto_upgrade=False)


def test_proxy_tls_mode_does_not_require_local_certificate(monkeypatch):
    monkeypatch.setattr(expansion, "require_ready", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "SETTINGS", dataclasses.replace(
        server.SETTINGS,
        auth_required=True,
        remote_mode=True,
        tls_termination="proxy",
        host="0.0.0.0",
        allowed_hosts=("recon.example.org",),
        forwarded_allow_ips=("172.30.0.0/24",),
    ))
    with get_db().session() as session:
        create_user(session, "administrator", "very strong admin password", role="admin")
    server._validate_service_mode()


def test_production_service_rejects_sqlite(monkeypatch):
    monkeypatch.setattr(server, "SETTINGS", dataclasses.replace(
        server.SETTINGS,
        environment="production",
        auth_required=True,
        remote_mode=True,
        auto_migrate=False,
        queue_backend="arq",
        allow_live_scans=False,
        allow_key_writes=False,
        metrics_token="m" * 32,
        host="0.0.0.0",
        allowed_hosts=("recon.example.org",),
        tls_termination="proxy",
        forwarded_allow_ips=("172.30.0.0/24",),
    ))
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        server._validate_service_mode()


def test_production_background_service_rejects_sqlite(monkeypatch):
    monkeypatch.setattr(
        cli,
        "SETTINGS",
        dataclasses.replace(
            server.SETTINGS,
            environment="production",
            auto_migrate=False,
            queue_backend="arq",
        ),
        raising=False,
    )
    monkeypatch.setattr("recon.config.SETTINGS", cli.SETTINGS)
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        cli._validate_background_mode()


def test_login_rate_limit_precedes_expensive_password_check(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(server, "LOGIN_LIMITER", LoginRateLimiter(1))
    monkeypatch.setattr(
        server, "SETTINGS", dataclasses.replace(server.SETTINGS, auth_required=True)
    )
    with TestClient(server.app) as client:
        first = client.post(
            "/api/auth/login", json={"username": "missing", "password": "wrong password"}
        )
        second = client.post(
            "/api/auth/login", json={"username": "another", "password": "wrong password"}
        )
    assert first.status_code == 401
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"


def test_queued_scan_and_job_status_are_tenant_owned(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(server, "SETTINGS", dataclasses.replace(
        server.SETTINGS, auth_required=True, queue_backend="arq"
    ))
    monkeypatch.setattr(jobs, "get_queue", lambda: LocalQueue())
    with get_db().session() as session:
        alice = create_user(session, "alice", "correct horse battery", role="analyst")
        create_user(session, "bob", "another correct horse", role="analyst")
        alice_id = alice.id

    with TestClient(server.app) as alice_client:
        csrf = _login(alice_client, "alice", "correct horse battery")
        queued = alice_client.post(
            "/api/scan",
            json={"username": "alice"},
            headers={"X-CSRF-Token": csrf},
        )
        assert queued.status_code == 202
        job_id = queued.json()["job_id"]
        assert alice_client.get(f"/api/jobs/{job_id}").status_code == 200
        with get_db().session() as session:
            server.repo.upsert_job_activity(session, job_id, [{
                "id": "request:1", "kind": "request", "sequence": 3,
                "outcome": "success",
            }])
        activity = alice_client.get(f"/api/jobs/{job_id}/activity")
        assert activity.status_code == 200
        assert activity.json()["cursor"] == 3
        assert activity.json()["activities"][0]["id"] == "request:1"
        assert alice_client.get(
            f"/api/jobs/{job_id}/activity?after=3"
        ).json()["activities"] == []

    with get_db().session() as session:
        row = session.get(server.repo.m.Job, job_id)
        assert row.owner_id == alice_id

    with TestClient(server.app) as bob_client:
        _login(bob_client, "bob", "another correct horse")
        assert bob_client.get(f"/api/jobs/{job_id}").status_code == 404
        assert bob_client.get(f"/api/jobs/{job_id}/activity").status_code == 404
