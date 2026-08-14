import pytest

from recon import expansion


def test_expansion_gate_allows_ready_capability(monkeypatch):
    result = {"expansion_ready": True, "checks": []}
    monkeypatch.setattr(expansion, "readiness", lambda _db: result)
    assert expansion.require_ready(object(), "source_pack") is result


def test_expansion_gate_reports_blockers(monkeypatch):
    monkeypatch.setattr(expansion, "readiness", lambda _db: {
        "expansion_ready": False,
        "checks": [
            {"name": "calibration", "passed": False},
            {"name": "migrations", "passed": True},
        ],
    })
    with pytest.raises(expansion.ExpansionBlocked, match="calibration"):
        expansion.require_ready(object(), "ml_identity")


def test_expansion_gate_rejects_unknown_capability():
    with pytest.raises(ValueError, match="unknown expansion capability"):
        expansion.require_ready(object(), "telepathy")
