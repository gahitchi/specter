"""Phase-3 web API: key vault endpoints (no secret leakage), module catalogue,
and the discovery-graph endpoint."""

import pytest
from fastapi.testclient import TestClient

from recon.engine import _Edge
from recon.graph_models import Artifact, ArtifactType
from recon.keys import VAULT
from recon.models import Query
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


def test_scan_rejects_empty_or_oversized_payload():
    assert client.post("/api/scan", json={}).status_code == 422
    assert client.post("/api/scan", json={"username": "x" * 321}).status_code == 422


def test_scan_accepts_one_auto_classified_subject(monkeypatch):
    seen = {}

    async def fake_scan(query, **kwargs):
        seen["query"] = query
        seen["intake"] = kwargs["intake"]
        profile = {"status": "unresolved", "title": query.username}
        return {
            "run_id": 12,
            "target_id": 4,
            "summary": {"identities": 0, "clusters": [], "profile": profile},
            "reasoning": {},
            "changes": [],
            "findings": [],
        }

    monkeypatch.setattr(server, "scan", fake_scan)
    response = client.post("/api/scan", json={"subject": "@Alice"})

    assert response.status_code == 200
    assert seen["query"].username == "alice"
    assert seen["intake"]["kind"] == "username"
    assert response.json()["profile"]["title"] == "alice"


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
