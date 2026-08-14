import dataclasses

from fastapi.testclient import TestClient

from recon import server
from recon.auth import create_user
from recon.models import Query
from recon.store import get_db, repo


def _login(client, username, password):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def test_authenticated_tenants_cannot_read_each_others_targets(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(
        server, "SETTINGS", dataclasses.replace(server.SETTINGS, auth_required=True)
    )
    with get_db().session() as session:
        alice = create_user(session, "alice", "correct horse battery", role="analyst")
        bob = create_user(session, "bob", "another correct horse", role="analyst")
        own = repo.get_or_create_target(session, Query(username="alice"), owner_id=alice.id)
        foreign = repo.get_or_create_target(session, Query(username="bob"), owner_id=bob.id)
        own_id, foreign_id = own.id, foreign.id

    with TestClient(server.app) as client:
        csrf = _login(client, "alice", "correct horse battery")
        targets = client.get("/api/targets")
        assert targets.status_code == 200
        assert [target["id"] for target in targets.json()] == [own_id]
        assert client.get(f"/api/targets/{foreign_id}/entities").status_code == 404
        assert client.request(
            "DELETE",
            f"/api/targets/{foreign_id}",
            json={"confirm": True, "actor": "spoofed"},
            headers={"X-CSRF-Token": csrf},
        ).status_code == 404


def test_session_mutations_require_csrf_and_last_admin_is_protected(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(
        server, "SETTINGS", dataclasses.replace(server.SETTINGS, auth_required=True)
    )
    with get_db().session() as session:
        admin = create_user(session, "administrator", "very strong admin password", role="admin")
        admin_id = admin.id

    with TestClient(server.app) as client:
        csrf = _login(client, "administrator", "very strong admin password")
        no_csrf = client.post(
            "/api/users",
            json={"username": "reviewer", "password": "strong reviewer password", "role": "reviewer"},
        )
        assert no_csrf.status_code == 403

        created = client.post(
            "/api/users",
            json={"username": "reviewer", "password": "strong reviewer password", "role": "reviewer"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 200
        demote = client.patch(
            f"/api/users/{admin_id}",
            json={"role": "analyst"},
            headers={"X-CSRF-Token": csrf},
        )
        assert demote.status_code == 400
        assert "last active administrator" in demote.json()["error"]


def test_invalid_login_is_generic_and_does_not_create_session(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(
        server, "SETTINGS", dataclasses.replace(server.SETTINGS, auth_required=True)
    )
    with TestClient(server.app) as client:
        response = client.post(
            "/api/auth/login", json={"username": "missing", "password": "not the password"}
        )
        assert response.status_code == 401
        assert response.json() == {"error": "invalid credentials"}
        assert "recon_session" not in response.cookies


def test_remote_mode_refuses_plain_http_before_serving_login(monkeypatch):
    monkeypatch.setattr(server, "_validate_service_mode", lambda: None)
    monkeypatch.setattr(
        server,
        "SETTINGS",
        dataclasses.replace(server.SETTINGS, auth_required=True, remote_mode=True),
    )
    with TestClient(server.app) as client:
        response = client.get("/")
        assert response.status_code == 426
        assert response.json() == {"error": "HTTPS is required in remote mode"}
