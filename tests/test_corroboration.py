"""Phase 6c: cross-source corroboration made visible.

`trust.corroboration` turns a set of FOUND source names into an honest trust
assessment — distinguishing genuinely independent confirmation from several
sources that collapse to one independence class (inflation). Surfaced in both
summary paths (in-memory `score.summarize` and the entity summary used by the
CLI) without altering any official score.
"""

from recon.correlate.cluster import cluster
from recon.correlate.score import summarize
from recon.evidence import EvidenceClass, EvidenceOrigin
from recon.models import Finding, Verdict
from recon.trust import corroboration


def _found(source, **signals):
    return Finding(
        source=source,
        category="x",
        label=source,
        verdict=Verdict.FOUND,
        confidence=0.9,
        signals=signals,
    )


# ------------------------------------------------------------ the assessment


def test_two_independent_classes_is_corroborated():
    c = corroboration(["github", "ripestat"])  # github vs rir
    assert c["label"] == "corroborated"
    assert c["independent_classes"] == 2
    assert c["inflation"] == 1.0
    assert c["redundant"] == []


def test_redundant_sources_inflate_breadth():
    # Three distinct source names that ALL map to the 'rir' class: looks like
    # broad corroboration, is really a single independent class.
    c = corroboration(["ripestat", "asn", "ip_geo"])
    assert c["label"] == "single_source"
    assert c["independent_classes"] == 1
    assert c["distinct_sources"] == 3
    assert c["inflation"] == 3.0
    assert len(c["redundant"]) == 2


def test_username_sites_are_independent_per_platform():
    c = corroboration(["username:GitHub", "username:Twitter"])
    assert c["independent_classes"] == 2
    assert c["label"] == "corroborated"


def test_no_found_sources_is_uncorroborated():
    c = corroboration([])
    assert c["label"] == "uncorroborated"
    assert c["independent_classes"] == 0
    assert c["inflation"] == 0.0


def test_repeated_names_dedup_before_assessment():
    c = corroboration(["github", "github"])
    assert c["distinct_sources"] == 1
    assert c["label"] == "single_source"


def test_one_collector_can_corroborate_distinct_direct_origins_without_negative_inflation():
    findings = [
        Finding(
            source="phone:web",
            category="phone",
            label=host,
            verdict=Verdict.FOUND,
            confidence=0.8,
            origin=EvidenceOrigin(
                collector="phone_web",
                operator=host,
                origin=host,
                evidence_class=EvidenceClass.DIRECT,
                independence_key=f"site:{host}",
            ),
        )
        for host in ("one.example", "two.example")
    ]

    result = corroboration(findings)

    assert result["independent_classes"] == 2
    assert result["distinct_sources"] == 1
    assert result["inflation"] == 1.0


# --------------------------------------------------- surfaced in the summary


def test_summarize_attaches_corroboration_per_cluster():
    # Two FOUND findings sharing a strong signal (email) cluster into one
    # identity, corroborated by two independent classes.
    findings = [_found("github", email="a@b.com"), _found("ripestat", email="a@b.com")]
    out = summarize(cluster(findings))
    corro = out["clusters"][0]["corroboration"]
    assert corro["label"] == "corroborated"
    assert corro["independent_classes"] == 2
