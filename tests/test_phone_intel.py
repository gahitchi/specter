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


def test_phone_context_distinguishes_service_and_directory_records() -> None:
    service = classify_phone_mention(
        "Call reception for appointments.",
        {"types": ["Organization"], "name": "Example Clinic"},
        page_title="Contact us",
        page_url="https://clinic.example/contact",
    )
    directory = classify_phone_mention(
        "People search result",
        {"types": ["Person"], "name": "Alice Example"},
        page_title="Reverse phone lookup directory listing",
        page_url="https://lookup.example/result",
    )

    assert service["association"] == "service_contact"
    assert service["identity_candidate"] is False
    assert directory["association"] == "directory_listing"
    assert directory["independence_group"] == "phone-directory"
    assert directory["pivot_eligible"] is False


def test_phone_summary_keeps_repeated_names_as_candidates() -> None:
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
    assert summary["identity_links"][0]["standing"] == "candidate"
    assert summary["identity_links"][0]["independent_origins"] == 2
    assert summary["decision"]["status"] == "needs_corroboration"
    assert summary["decision"]["can_expand_automatically"] is False
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
    assert summary["decision"]["can_expand_automatically"] is False
