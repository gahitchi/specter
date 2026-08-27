import dataclasses

from recon.evidence import (
    Completeness,
    ConfidenceDimensions,
    EvidencePolicy,
    TemporalStatus,
    assess_promotion,
    confirmation_satisfied,
    evidence_claim_key,
    infer_origin,
    restrictive_policy,
)
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.models import Finding, Query, Verdict
from recon.store import repo


def test_origin_claim_and_confidence_dimensions_are_deterministic():
    origin = infer_origin("username:GitHub", "https://github.com/alice", collector="username")
    left = evidence_claim_key(
        "username", "https://github.com/alice/", "GitHub", {"username": "Alice"}
    )
    right = evidence_claim_key(
        "USERNAME", "https://github.com/alice", "ignored", {"username": "alice"}
    )
    dimensions = ConfidenceDimensions(
        match_quality=0.9,
        source_reliability=0.8,
        recency=1.0,
        independence=0.5,
        transformation_certainty=0.9,
        completeness=1.0,
    )

    assert origin.origin == "github.com"
    assert origin.independence_key == "github"
    assert left == right
    assert dimensions.aggregate() == 0.853


def test_promotion_policy_keeps_candidates_visible_but_ineligible():
    candidate = assess_promotion(EvidencePolicy.candidate(), independent_origins=3)
    guarded = EvidencePolicy(requires_corroboration=True, minimum_independent_origins=2)

    assert candidate.allowed is False
    assert candidate.status == "candidate"
    assert assess_promotion(guarded, independent_origins=1).allowed is False
    assert assess_promotion(guarded, independent_origins=2).allowed is True

    composed = restrictive_policy(guarded, EvidencePolicy())
    assert composed.requires_corroboration is True
    assert composed.minimum_independent_origins == 2


def test_identity_confirmation_requires_a_repeated_non_seed_unique_identifier():
    policy = EvidencePolicy.corroborated()
    query = Query(username="shared-handle")
    name_only = [
        Finding(
            source=f"site:{index}", category="username", label=f"site {index}",
            verdict=Verdict.FOUND, confidence=0.9,
            signals={"username": "shared-handle", "name": "Alex Smith"},
            policy=policy,
        )
        for index in range(3)
    ]
    assert not any(confirmation_satisfied(item, name_only, query) for item in name_only)

    linked = [
        Finding(
            source=f"profile:{index}", category="username", label=f"profile {index}",
            verdict=Verdict.FOUND, confidence=0.9,
            signals={"username": "shared-handle", "email": "alex@example.net"},
            policy=policy,
            origin=infer_origin(
                "profile:enrich", f"https://profile-{index}.example/alex"
            ),
        )
        for index in range(2)
    ]
    assert all(confirmation_satisfied(item, linked, query) for item in linked)

    infrastructure = Finding(
        source="domain:dns", category="domain", label="DNS",
        verdict=Verdict.FOUND, confidence=0.9, signals={"domain": "example.net"},
    )
    assert confirmation_satisfied(infrastructure, [infrastructure]) is False


def test_strict_scope_does_not_follow_another_mailbox_at_the_seed_domain():
    engine = GraphScanEngine(Query(email="alice@example.com"), SETTINGS)
    other = Artifact.make(ArtifactType.EMAIL, "bob@example.com", source_module="profile")
    exact = Artifact.make(ArtifactType.EMAIL, "alice@example.com", source_module="profile")

    assert engine.scope.in_scope(other) is False
    assert engine.scope.in_scope(exact) is True


def test_graph_requires_distinct_origins_before_guarded_expansion():
    engine = GraphScanEngine(
        Query(username="alice"), dataclasses.replace(SETTINGS, scope_mode="aggressive")
    )
    policy = EvidencePolicy(requires_corroboration=True, minimum_independent_origins=2)
    first = Artifact.make(
        ArtifactType.EMAIL,
        "alice@example.com",
        source_module="profile_links",
        origin=infer_origin("profile:first", "https://first.example/alice"),
        policy=policy,
    )
    second = first.model_copy(deep=True)
    second.source_module = "directory"
    second.origin = infer_origin("profile:second", "https://second.example/alice")

    engine._register_promotion_origin(first)
    assert engine._should_expand(first) is False
    engine._register_promotion_origin(second)
    assert engine._should_expand(first) is True


def test_strict_scope_allows_only_corroborated_same_subject_identity_bridge():
    engine = GraphScanEngine(Query(phone="+14155552671"), SETTINGS)
    phone = Artifact.make(ArtifactType.PHONE, "+14155552671")
    policy = EvidencePolicy(requires_corroboration=True, minimum_independent_origins=2)
    first = Artifact.make(
        ArtifactType.EMAIL,
        "alice@example.com",
        parent=phone,
        source_module="phone_web",
        origin=infer_origin("phone:web", "https://one.example/contact"),
        policy=policy,
        subject_relation="same_subject",
    )
    second = first.model_copy(deep=True)
    second.origin = infer_origin("phone:web", "https://two.example/contact")

    engine._register_promotion_origin(first)
    assert engine._should_expand(first) is False
    engine._register_promotion_origin(second)
    assert engine._should_expand(first) is True

    unrelated = first.model_copy(deep=True)
    unrelated.data.pop("subject_relation")
    assert engine.scope.in_scope(unrelated) is False


def test_store_tracks_temporal_transition_and_explicit_contradiction(fresh_db):
    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        first_run = repo.create_run(session, target)
        first = repo.add_observation(
            session,
            first_run,
            Finding(
                source="username:Example",
                category="username",
                label="Example",
                url="https://example.com/alice",
                verdict=Verdict.FOUND,
                confidence=0.9,
                signals={"username": "alice"},
                completeness=Completeness.COMPLETE,
            ),
        )
        first_id = first.id

    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        second_run = repo.create_run(session, target)
        second = repo.add_observation(
            session,
            second_run,
            Finding(
                source="username:Example",
                category="username",
                label="Example",
                url="https://example.com/alice/",
                verdict=Verdict.NOT_FOUND,
                confidence=0.0,
                signals={"username": "alice"},
                completeness=Completeness.COMPLETE,
            ),
        )
        contradictions = repo.contradictions_for_run(session, second_run.id)
        historical = session.get(repo.m.Observation, first_id)

        assert historical.temporal_status == TemporalStatus.HISTORICAL.value
        assert second.temporal_status == TemporalStatus.CURRENT.value
        assert second.first_seen_at == historical.first_seen_at
        assert len(contradictions) == 1
        assert contradictions[0].kind == "presence-changed"
        assert contradictions[0].earlier_observation_id == first_id


def test_store_flags_identity_reassignment_even_when_the_page_still_exists(fresh_db):
    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(url="https://example.com/profile"))
        first_run = repo.create_run(session, target)
        repo.add_observation(session, first_run, Finding(
            source="profile:enrich", category="profile", label="Profile",
            url="https://example.com/profile", verdict=Verdict.FOUND, confidence=0.9,
            signals={"email": "first@example.com"},
        ))

    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(url="https://example.com/profile"))
        second_run = repo.create_run(session, target)
        repo.add_observation(session, second_run, Finding(
            source="profile:enrich", category="profile", label="Profile",
            url="https://example.com/profile/", verdict=Verdict.FOUND, confidence=0.9,
            signals={"email": "second@example.com"},
        ))
        contradictions = repo.contradictions_for_run(session, second_run.id)

    assert len(contradictions) == 1
    assert contradictions[0].kind == "identity-signals-changed"
    assert contradictions[0].severity == "high"


def test_old_style_finding_receives_storage_level_evidence_defaults(fresh_db):
    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(domain="example.com"))
        run = repo.create_run(session, target)
        observation = repo.add_observation(
            session,
            run,
            Finding(
                source="domain:dns",
                category="domain",
                label="example.com",
                verdict=Verdict.FOUND,
                confidence=0.8,
            ),
            reliability=0.75,
        )

        assert observation.origin
        assert observation.independence_key == "dns"
        assert observation.observed_at is not None
        assert observation.confidence_dimensions["source_reliability"] == 0.75
