"""Phase-3 web API: key vault endpoints (no secret leakage), module catalogue,
and the discovery-graph endpoint."""

from datetime import datetime, timezone
import json

import pytest
from fastapi.testclient import TestClient

from recon.engine import _Edge
from recon.graph_models import Artifact, ArtifactType
from recon.keys import VAULT
from recon.models import Finding, Query, Verdict
from recon.server import app
from recon import server
from recon.store import get_db, repo

client = TestClient(app)


@pytest.fixture(autouse=True)
def _isolate_keys(tmp_path, monkeypatch):
    # Route the vault at a throwaway file; never touch the real ~/.config one.
    monkeypatch.setenv("RECON_KEYS_FILE", str(tmp_path / "keys.toml"))
    for k in ("SHODAN", "VIRUSTOTAL", "ABUSEIPDB", "GITHUB", "HIBP"):
        monkeypatch.delenv(f"RECON_KEY_{k}", raising=False)
    VAULT.reload()
    yield
    VAULT.reload()


def test_keys_status_never_leaks_values():
    rows = client.get("/api/keys").json()
    names = {r["name"] for r in rows}
    assert {"shodan", "virustotal", "abuseipdb", "github", "hibp"} <= names
    for r in rows:
        assert "value" not in r        # the secret is never serialized
        assert r["configured"] is False
        assert "modules" in r


def test_set_then_clear_key_roundtrip(tmp_path):
    r = client.post("/api/keys", json={"name": "shodan", "value": "s3cr3t"})
    body = r.json()
    assert body["configured"] is True and body["source"] == "file"
    assert "s3cr3t" not in r.text       # value not echoed back

    # Persisted, and reflected in status + module enablement.
    assert any(k["name"] == "shodan" and k["configured"] for k in client.get("/api/keys").json())
    mods = {m["name"]: m for m in client.get("/api/modules").json()}
    assert mods["shodan"]["enabled"] is True

    client.post("/api/keys", json={"name": "shodan", "value": ""})  # clear
    assert all(not k["configured"] for k in client.get("/api/keys").json() if k["name"] == "shodan")


def test_unknown_key_rejected():
    assert client.post("/api/keys", json={"name": "nope", "value": "x"}).status_code == 400


def test_local_api_rejects_cross_origin_and_non_json_writes():
    cross_origin = client.post(
        "/api/keys",
        json={"name": "shodan", "value": "x"},
        headers={"Origin": "https://evil.example"},
    )
    assert cross_origin.status_code == 403
    wrong_type = client.post(
        "/api/keys",
        content='{"name":"shodan","value":"x"}',
        headers={"Content-Type": "text/plain"},
    )
    assert wrong_type.status_code == 415


def test_local_api_validates_host_and_sets_security_headers():
    assert client.get("/api/keys", headers={"Host": "evil.example"}).status_code == 400
    response = client.get("/api/keys")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["cache-control"] == "no-store"


def test_application_icon_is_served_from_the_package():
    response = client.get("/icon.png")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content.startswith(b"\x89PNG\r\n\x1a\n")


def test_scan_rejects_empty_or_oversized_payload():
    assert client.post("/api/scan", json={}).status_code == 422
    assert client.post("/api/scan", json={"username": "x" * 321}).status_code == 422


def test_scan_accepts_one_auto_classified_subject(monkeypatch):
    monkeypatch.setattr(server, "_start_local_job", lambda _job_id: None)
    response = client.post("/api/scan", json={
        "subject": "@Alice",
        "authorized": True,
        "authorization_basis": "self_owned",
    })

    assert response.status_code == 202
    with get_db().session() as session:
        job = session.get(server.repo.m.Job, response.json()["job_id"])
        assert job.payload["query"]["username"] == "alice"
        assert job.payload["intake"]["kind"] == "username"


def test_scan_treats_typed_clues_as_one_query(monkeypatch):
    monkeypatch.setattr(server, "_start_local_job", lambda _job_id: None)
    response = client.post(
        "/api/scan",
        json={
            "name": "Alice Example",
            "username": "@Alice",
            "email": "Alice@Example.com",
            "authorized": True,
            "authorization_basis": "self_owned",
        },
    )

    assert response.status_code == 202
    with get_db().session() as session:
        job = session.get(server.repo.m.Job, response.json()["job_id"])
        assert Query(**job.payload["query"]) == Query(
            name="Alice Example", username="alice", email="alice@example.com"
        )
        assert job.payload["intake"]["kind"] == "multiple"
        assert set(job.payload["intake"]["query_fields"]) == {
            "name", "username", "email"
        }


def test_local_jobs_can_be_discovered_cancelled_and_retried(monkeypatch):
    monkeypatch.setattr(server, "_start_local_job", lambda _job_id: None)
    queued = client.post("/api/scan", json={
        "username": "alice",
        "authorized": True,
        "authorization_basis": "self_owned",
    })
    job_id = queued.json()["job_id"]

    active = client.get("/api/jobs?active=true").json()
    assert [job["id"] for job in active] == [job_id]
    cancelled = client.post(f"/api/jobs/{job_id}/cancel", json={})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    retried = client.post(f"/api/jobs/{job_id}/retry", json={})
    assert retried.status_code == 202
    assert retried.json()["status"] == "queued"

    with get_db().session() as session:
        terminal = server.repo.m.Job(kind="scan", payload={}, status="done")
        session.add(terminal)
        session.flush()
        terminal_id = terminal.id
    assert client.post(f"/api/jobs/{terminal_id}/cancel", json={}).status_code == 409


def test_monitoring_requires_fresh_authorization_and_can_be_disabled():
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        target_id = target.id

    rejected = client.post(
        f"/api/targets/{target_id}/monitor",
        json={"cadence": "daily"},
    )
    assert rejected.status_code == 422

    enabled = client.post(
        f"/api/targets/{target_id}/monitor",
        json={
            "cadence": "daily",
            "authorized": True,
            "authorization_basis": "self_owned",
        },
    )
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    target_row = next(row for row in client.get("/api/targets").json() if row["id"] == target_id)
    assert target_row["monitoring"]["cadence"] == "daily"
    assert target_row["watchlist"] is True

    disabled = client.post(
        f"/api/targets/{target_id}/monitor", json={"cadence": "off"}
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    target_row = next(row for row in client.get("/api/targets").json() if row["id"] == target_id)
    assert target_row["monitoring"]["cadence"] == "off"
    assert target_row["watchlist"] is False


def test_saved_run_reports_are_readable_and_keep_evidence_receipts():
    with get_db().session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        run = repo.create_run(session, target)
        repo.add_observation(
            session,
            run,
            Finding(
                source="username:example",
                category="username",
                label="Example profile",
                verdict=Verdict.FOUND,
                confidence=0.91,
                reasons=["public profile observed"],
                trace={
                    "request": {
                        "status": 200,
                        "content_sha256": "a" * 64,
                        "content_bytes": 120,
                    }
                },
            ),
        )
        repo.finish_run(session, run, "done", {"hits": 1, "total": 1})
        run_id = run.id

    report = client.get(f"/api/runs/{run_id}/report/html")
    assert report.status_code == 200
    assert "attachment" in report.headers["content-disposition"]
    assert "Executive assessment" in report.text
    assert "Example profile" in report.text
    assert "receipt aaaaaaaaaaaa" in report.text

    csv_report = client.get(f"/api/runs/{run_id}/report/csv")
    assert csv_report.status_code == 200
    assert "content_sha256" in csv_report.text
    assert "a" * 64 in csv_report.text


def test_live_search_serializes_temporal_datetimes(monkeypatch):
    observed_at = datetime(2026, 8, 26, 16, 30, tzinfo=timezone.utc)

    async def fake_run_stream(query, **_kwargs):
        assert query.username == "alice"
        yield {
            "type": "finding",
            "finding": {"temporal": {"observed_at": observed_at}},
        }

    monkeypatch.setattr(server, "run_stream", fake_run_stream)

    response = client.get(
        "/api/search?username=alice&authorized=true&authorization_basis=self_owned"
    )
    events = [
        json.loads(line.removeprefix("data: "))
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]

    assert response.status_code == 200
    assert events[1]["finding"]["temporal"]["observed_at"] == observed_at.isoformat()


def test_module_catalogue_marks_keyed_vs_keyless():
    mods = {m["name"]: m for m in client.get("/api/modules").json()}
    assert mods["ripestat"]["keyless"] is True and mods["ripestat"]["enabled"] is True
    assert mods["shodan"]["keyless"] is False
    assert mods["shodan"]["enabled"] is False   # no key set
    assert mods["ip_geo"]["enabled"] is False   # HTTP-only provider is not dispatched
    assert mods["github"]["contract"]["data_sent"] == ["username"]
    assert "ip_address" in mods["asn"]["consumes"]


def test_graph_endpoint_returns_nodes_and_edges():
    db = get_db()
    db.create_all()
    with db.session() as s:
        target = repo.get_or_create_target(s, Query(domain="example.com"))
        run = repo.create_run(s, target)
        a1 = Artifact.make(ArtifactType.DOMAIN, "example.com")
        a2 = Artifact.make(ArtifactType.IP_ADDRESS, "93.184.216.34",
                           parent=a1, source_module="domain")
        repo.persist_graph(s, run, [a1, a2], [_Edge(a1.key, a2.key, "domain", {})])
        run_id = run.id

    g = client.get(f"/api/runs/{run_id}/graph").json()
    assert g["run_id"] == run_id
    assert {n["type"] for n in g["nodes"]} == {"domain", "ip_address"}
    assert len(g["edges"]) == 1
    assert g["edges"][0]["module"] == "domain"
