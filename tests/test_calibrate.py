"""Phase-5c calibration tooling: the metrics are correct on synthetic samples,
the runner turns labels into a report via an injected evaluator, and reports
persist + serve."""

import pytest
from fastapi.testclient import TestClient

from recon.calibrate import metrics, run_calibration
from recon.calibrate.labels import load_labels
from recon.calibrate.metrics import Sample
from recon.server import app
from recon.store import get_db, repo

client = TestClient(app)


def test_label_loader_rejects_contradictory_ground_truth(tmp_path):
    path = tmp_path / "labels.json"
    path.write_text(
        '{"labels": ['
        '{"account":"same","site":"GitHub","present":true},'
        '{"account":"same","site":"GitHub","present":false}'
        ']}'
    )
    with pytest.raises(ValueError, match="contradictory"):
        load_labels(path)


def test_label_loader_deduplicates_identical_rows(tmp_path):
    path = tmp_path / "labels.json"
    row = '{"account":"same","site":"GitHub","present":true}'
    path.write_text('{"labels": [' + row + "," + row + "]}")
    assert len(load_labels(path)) == 1


def _samples(pairs):
    return [Sample(c, p) for c, p in pairs]


def test_perfectly_calibrated_has_low_ece():
    # In each bin the empirical present-rate matches the predicted confidence.
    s = _samples([(0.1, False)] * 9 + [(0.1, True)]
                 + [(0.9, True)] * 9 + [(0.9, False)])
    assert metrics.ece(s) < 0.05
    assert metrics.brier(s) < 0.15


def test_overconfident_set_is_flagged_miscalibrated():
    # Predicts 0.95 present, but only ~half are actually present.
    s = _samples([(0.95, True)] * 5 + [(0.95, False)] * 5)
    assert metrics.ece(s) > 0.4          # large gap between predicted and empirical
    assert metrics.brier(s) > 0.4


def test_confusion_and_fp_rate():
    s = _samples([(0.9, True), (0.8, True), (0.9, False), (0.3, False), (0.2, False)])
    c = metrics.confusion_at(s, 0.75)
    assert (c["tp"], c["fp"], c["tn"], c["fn"]) == (2, 1, 2, 0)
    assert c["fp_rate"] == pytest.approx(1 / 3, abs=1e-3)


def test_suggest_threshold_raises_to_cut_false_positives():
    # A false positive sits at 0.6; raising the threshold above it removes it.
    s = _samples([(0.9, True), (0.85, True), (0.6, False), (0.2, False)])
    sug = metrics.suggest_threshold(s, current=0.5, target_fp_rate=0.0)
    assert sug["suggested"] > 0.6
    assert sug["fp_rate"] == 0.0


def test_reliability_bins_partition_counts():
    s = _samples([(0.05, False), (0.15, True), (0.95, True)])
    bins = metrics.reliability_bins(s, n_bins=10)
    assert sum(b["count"] for b in bins) == 3
    assert bins[0]["count"] == 1 and bins[9]["count"] == 1


async def test_runner_with_injected_evaluator():
    labels = [
        {"category": "username", "account": "real", "site": "GitHub", "present": True},
        {"category": "username", "account": "ghost", "site": "GitHub", "present": False},
        {"category": "username", "account": "blocked", "site": "GitHub", "present": True},
    ]

    async def fake_eval(account, site, settings):
        return {"real": 0.9, "ghost": 0.1, "blocked": None}[account]  # None => skipped

    report = await run_calibration(evaluator=fake_eval, labels=labels)
    assert report["n"] == 2                      # the UNVERIFIABLE 'blocked' is excluded
    assert report["positives"] == 1 and report["negatives"] == 1
    assert "bins" in report and "confusion_found" in report


def test_calibration_persist_and_endpoint():
    db = get_db()
    db.create_all()
    report = {"n": 4, "positives": 2, "negatives": 2, "brier": 0.1, "ece": 0.05,
              "mce": 0.1, "bins": [], "found_threshold": 0.75,
              "confusion_found": {"fp_rate": 0.0}, "suggestion": {"rationale": "keep"}}
    with db.session() as s:
        repo.save_calibration(s, report)

    body = client.get("/api/calibration").json()
    assert body["latest"]["brier"] == 0.1
    assert body["history"] and body["history"][0]["n"] == 4
