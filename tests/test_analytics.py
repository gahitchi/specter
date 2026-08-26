"""Phase-5d confidence analytics: the pure aggregations are correct, and the
endpoint serves them over persisted observations."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from recon import analytics
from recon.models import Finding, Query, Verdict
from recon.server import app
from recon.store import get_db, repo

client = TestClient(app)


def _obs(verdict, confidence, source="username:GitHub", breakdown=None):
    return SimpleNamespace(verdict=verdict, confidence=confidence, source=source,
                           breakdown=breakdown, signals={"email": "shared@example.com"})


def test_confidence_histogram_skips_unscored_verdicts():
    rows = [_obs("FOUND", 0.95), _obs("NOT_FOUND", 0.05),
            _obs("UNVERIFIABLE", 0.0), _obs("ERROR", 0.0)]
    hist = analytics.confidence_histogram(rows)
    assert sum(b["count"] for b in hist) == 2     # UNVERIFIABLE/ERROR excluded
    assert hist[9]["count"] == 1 and hist[0]["count"] == 1


def test_verdict_mix_counts():
    rows = [_obs("FOUND", 0.9), _obs("FOUND", 0.8), _obs("NOT_FOUND", 0.1)]
    assert analytics.verdict_mix(rows) == {"FOUND": 2, "NOT_FOUND": 1}


def test_top_breakdown_terms_aggregates_delta():
    bd = {"contributions": [{"term": "status_vs_baseline", "delta": 0.2},
                            {"term": "query_in_body", "delta": 0.2}]}
    bd2 = {"contributions": [{"term": "status_vs_baseline", "delta": 0.2}]}
    rows = [_obs("FOUND", 0.9, breakdown=bd), _obs("FOUND", 0.85, breakdown=bd2)]
    terms = {t["term"]: t for t in analytics.top_breakdown_terms(rows)}
    assert terms["status_vs_baseline"]["count"] == 2
    assert terms["status_vs_baseline"]["mean_delta"] == 0.2


def test_independence_coverage_reports_inflation():
    # Three RIR-class sources collapse to one independent class.
    rows = [_obs("FOUND", 0.9, source="asn"), _obs("FOUND", 0.9, source="ripestat"),
            _obs("FOUND", 0.9, source="ip_geo")]
    ic = analytics.independence_coverage(rows)
    assert ic["distinct_sources"] == 3 and ic["distinct_classes"] == 1
    assert ic["inflation"] == 3.0


def test_source_health_sorted_by_reliability():
    srcs = [SimpleNamespace(name="a", kind="x", reliability=0.9, successes=5, failures=0, breaker_state="closed"),
            SimpleNamespace(name="b", kind="y", reliability=0.2, successes=1, failures=4, breaker_state="open")]
    out = analytics.source_health(srcs)
    assert out[0]["name"] == "b"      # lowest reliability first (needs attention)


def test_analytics_endpoint_over_persisted_run():
    db = get_db()
    db.create_all()
    with db.session() as s:
        target = repo.get_or_create_target(s, Query(username="torvalds"))
        run = repo.create_run(s, target)
        f = Finding(source="username:GitHub", category="username", label="GitHub",
                    verdict=Verdict.FOUND, confidence=0.9,
                    breakdown={"base": 0.5, "contributions": [
                        {"term": "status_vs_baseline", "delta": 0.2}], "total": 0.9})
        repo.add_observation(s, run, f, reliability=0.8)

    a = client.get("/api/analytics").json()
    assert a["n_observations"] >= 1
    assert "FOUND" in a["verdict_mix"]
    assert any(t["term"] == "status_vs_baseline" for t in a["top_terms"])
