import datetime as dt
import json

import pytest

from recon.maturity import assess
from recon.sources import Canary, load_canaries, run_canaries, validate_contracts
from recon.store import get_db


def test_every_module_has_a_complete_source_contract():
    assert validate_contracts() == []


def test_canary_file_validation(tmp_path):
    path = tmp_path / "canaries.json"
    path.write_text(json.dumps({"canaries": [{
        "name": "offline-phone",
        "module": "phone",
        "artifact": {"type": "phone", "value": "+14155552671"},
        "expect": {"source_prefix": "phone:", "verdicts": ["FOUND"]},
    }]}), encoding="utf-8")
    canaries = load_canaries(path)
    assert canaries[0].module == "phone"


@pytest.mark.asyncio
async def test_offline_canary_runs_and_persists_without_requests():
    canary = Canary.model_validate({
        "name": "offline-phone",
        "module": "phone",
        "artifact": {"type": "phone", "value": "+14155552671"},
        "expect": {"source_prefix": "phone:", "verdicts": ["FOUND"]},
    })
    result = (await run_canaries([canary]))[0]
    assert result["status"] == "passed"
    assert result["requests"] == 0


def test_maturity_gate_reports_external_evidence_blockers():
    result = assess(get_db(), now=dt.datetime.now(dt.timezone.utc))
    by_name = {check["name"]: check for check in result["checks"]}
    assert by_name["source contracts"]["passed"] is True
    assert by_name["database migration"]["passed"] is True
    assert by_name["representative calibration"]["passed"] is False
    assert by_name["live source canaries"]["passed"] is False
    assert result["expansion_ready"] is False


def test_optional_export_encryption_roundtrip():
    pytest.importorskip("cryptography")
    from recon.crypto import decrypt, encrypt

    ciphertext = encrypt(b"sensitive report", "correct horse battery")
    assert b"sensitive report" not in ciphertext
    assert decrypt(ciphertext, "correct horse battery") == b"sensitive report"
    with pytest.raises(ValueError):
        encrypt(b"x", "too-short")
