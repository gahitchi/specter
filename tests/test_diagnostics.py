from pathlib import Path
from runpy import run_path

from recon import diagnostics


def test_diagnostics_are_ready_and_redacted(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(diagnostics, "data_root", lambda: tmp_path / "specter-data")
    monkeypatch.setenv("RECON_METRICS_TOKEN", "diagnostic-secret-must-not-leak")

    report = diagnostics.collect()

    assert report["status"] == "READY"
    assert report["runtime"]["schema_revision"] == report["runtime"]["schema_head"]
    assert report["required_failures"] == []
    serialized = str(report).casefold()
    assert "diagnostic-secret-must-not-leak" not in serialized
    assert str(tmp_path).casefold() not in serialized
    assert "privacy_note" in report


def test_operational_drill_is_local_and_non_destructive() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "operational_drill.py"
    drill = run_path(str(script))["run"]

    report = drill()

    assert report["status"] == "PASSED"
    assert {check["name"] for check in report["checks"]} == {
        "sqlite_backup_restore", "functional_replay",
    }


def test_staging_drill_requires_an_immutable_digest() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "operational_drill.py"
    drill = run_path(str(script))["run"]

    report = drill(staging_url="https://staging.example", container_digest="latest")

    assert report["status"] == "FAILED"
    assert "sha256" in report["checks"][-1]["detail"]
