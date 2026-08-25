from recon.evidence import EvidenceClass, EvidenceOrigin, TemporalEvidence, TemporalStatus
from recon.models import Finding, Query, Verdict
from recon.phone_intel import classify_phone_mention, summarize_phone_research


def _origin(host: str) -> EvidenceOrigin:
    return EvidenceOrigin(
        collector="phone_web",
        operator=host,
        origin=host,
        evidence_class=EvidenceClass.DIRECT,
        independence_key=f"web:{host}",
    )


def test_phone_context_flags_historical_reassignment_without_claiming_ownership() -> None:
    classification = classify_phone_mention(
        "This former number was reassigned to a new owner.",
        {"types": ["Person"], "name": "Example Name"},
    )

    assert classification["role"] == "person"
    assert classification["historical"] is True
    assert {"former_number", "reassigned"} <= set(classification["lifecycle_markers"])


def test_phone_summary_requires_independent_origins_for_identity_link() -> None:
    findings = [
        Finding(
            source="phone:web",
            category="phone",
            label=f"Mention {index}",
            url=f"https://{host}/contact",
            verdict=Verdict.FOUND,
            confidence=0.82,
            origin=_origin(host),
            data={
                "page_title": "Contact",
                "domain": host,
                "mention_role": "person",
                "structured": {"name": "Alice Example", "types": ["Person"]},
            },
            temporal=TemporalEvidence(status=TemporalStatus.CURRENT),
        )
        for index, host in enumerate(("one.example", "two.example"), start=1)
    ]

    summary = summarize_phone_research(Query(phone="+14155552671"), findings)

    assert summary is not None
    assert summary["identity_links"][0]["standing"] == "corroborated"
    assert summary["identity_links"][0]["independent_origins"] == 2
    assert summary["ownership_established"] is False


def test_phone_summary_surfaces_conflicting_names_as_possible_reuse_review() -> None:
    findings = [
        Finding(
            source="phone:web",
            category="phone",
            label=name,
            verdict=Verdict.FOUND,
            confidence=0.7,
            origin=_origin(host),
            data={"structured": {"name": name}, "lifecycle_markers": ["reassigned"]},
        )
        for name, host in (("Alice", "one.example"), ("Bob", "two.example"))
    ]

    summary = summarize_phone_research(Query(phone="+14155552671"), findings)

    assert summary["lifecycle"]["state"] == "possible_reuse"
    assert summary["lifecycle"]["conflicts"]
