"""Report serialisation: JSON / CSV / HTML / save() and the entity report.

Pure over Finding/query/summary, so no network. Verifies provenance is embedded,
the verdict reason-trail survives serialisation, CSV/HTML render the right rows,
and save() actually writes a file to disk (real persistence).
"""

import json

import pytest

from recon import reporting
from recon.models import Finding, Query, Verdict


def _findings():
    return [
        Finding(source="github", category="account", label="GitHub torvalds",
                url="https://github.com/torvalds", verdict=Verdict.FOUND,
                confidence=0.95, reasons=["site rule matched", "status 200 vs baseline 404"]),
        Finding(source="pypi", category="account", label="PyPI torvalds",
                verdict=Verdict.NOT_FOUND, confidence=0.0, reasons=["soft-404 rejected"]),
        Finding(source="medium", category="account", label="Medium torvalds",
                verdict=Verdict.UNCERTAIN, confidence=0.4, reasons=["content differs weakly"]),
    ]


def test_to_json_embeds_provenance_and_reasons():
    q = Query(username="torvalds")
    payload = json.loads(reporting.to_json(q, _findings(), {"hits": 1}))

    assert payload["tool"] == "osint-recon"
    assert payload["query"] == {"username": "torvalds"}
    assert payload["summary"] == {"hits": 1}
    # provenance block is present and stamps the tool version.
    assert "provenance" in payload and payload["provenance"].get("tool_version")
    # the reason-trail survives serialisation on every finding.
    sources = {f["source"]: f["reasons"] for f in payload["findings"]}
    assert sources["github"] == ["site rule matched", "status 200 vs baseline 404"]
    assert "disclaimer" in payload


def test_to_csv_has_header_and_one_row_per_finding():
    csv_text = reporting.to_csv(_findings())
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    assert lines[0].startswith("verdict,confidence,category,source,label,url,reasons")
    assert len(lines) == 1 + 3  # header + 3 findings
    assert "site rule matched | status 200 vs baseline 404" in csv_text


def test_to_pdf_html_renders_notable_findings():
    html = reporting.to_pdf_html(Query(username="torvalds"), _findings(), {"hits": 1})
    # UNCERTAIN stays visible and clearly labeled, but is not counted as a hit.
    assert "GitHub torvalds" in html
    assert "Medium torvalds" in html
    assert "PyPI torvalds" not in html
    assert reporting.DISCLAIMER in html


def test_to_pdf_html_renders_profile_standing_and_gaps():
    summary = {
        "identities": 0,
        "profile": {
            "title": "alice",
            "status": "partial",
            "confidence": 0.72,
            "assessment": "Confirmed account; independent corroboration remains limited.",
            "identifiers": [{
                "type": "username", "value": "alice", "standing": "provided",
                "confidence": 1.0,
            }],
            "accounts": [],
            "gaps": ["No contact identifier was independently confirmed."],
            "completeness_note": "Evidence coverage is not proof of completeness.",
        },
    }

    html = reporting.to_pdf_html(Query(username="alice"), _findings(), summary)

    assert "Profile synthesis" in html
    assert "provided" in html
    assert "No contact identifier" in html


def test_html_and_csv_escape_untrusted_source_text():
    findings = [Finding(
        source="<script>alert(1)</script>", category="account", label="=CMD()",
        verdict=Verdict.FOUND, confidence=0.9, reasons=["<img src=x onerror=alert(1)>"],
    )]
    html = reporting.to_pdf_html(Query(username="<x>"), findings, {})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html and "&lt;img" in html
    csv_text = reporting.to_csv(findings)
    assert "'=CMD()" in csv_text


def test_save_json_writes_file(tmp_path):
    out = tmp_path / "report.json"
    path = reporting.save(Query(username="torvalds"), _findings(), {"hits": 1},
                          fmt="json", out=str(out))
    assert path == out
    payload = json.loads(out.read_text())
    assert payload["findings"][0]["source"] == "github"


def test_save_unknown_format_raises(tmp_path):
    with pytest.raises(ValueError):
        reporting.save(Query(), _findings(), {}, fmt="xml", out=str(tmp_path / "x.xml"))


def test_save_pdf_falls_back_to_html_when_weasyprint_missing(tmp_path, monkeypatch):
    # Force the optional weasyprint import to fail; save() must degrade to .html.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "weasyprint":
            raise ImportError("no weasyprint")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    path = reporting.save(Query(username="x"), _findings(), {}, fmt="pdf",
                          out=str(tmp_path / "r.pdf"))
    assert path.suffix == ".html"
    assert path.exists()


def test_entity_report_missing_run_raises():
    # conftest provides a fresh, empty DB; run 999 does not exist.
    with pytest.raises(ValueError):
        reporting.entity_report(999)
