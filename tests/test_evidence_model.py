import dataclasses

from recon.evidence import (
    Completeness,
    ConfidenceDimensions,
    EvidencePolicy,
    TemporalStatus,
    assess_promotion,
    evidence_claim_key,
    infer_origin,
)
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.models import Finding, Query, Verdict
from recon.store import repo


def test_origin_claim_and_confidence_dimensions_are_deterministic():
    origin = infer_origin(
        "username:GitHub", "https://github.com/alice", collector="username"
    )
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
    assert origin.independence_key == "site:github"
    assert left == right
    assert dimensions.aggregate() == 0.853


def test_promotion_policy_keeps_candidates_visible_but_ineligible():
    candidate = assess_promotion(EvidencePolicy.candidate(), independent_origins=3)
    guarded = EvidencePolicy(requires_corroboration=True, minimum_independent_origins=2)

    assert candidate.allowed is False
    assert candidate.status == "candidate"
    assert assess_promotion(guarded, independent_origins=1).allowed is False
    assert assess_promotion(guarded, independent_origins=2).allowed is True


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


def test_store_tracks_temporal_transition_and_explicit_contradiction(fresh_db):
    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        first_run = repo.create_run(session, target)
        first = repo.add_observation(session, first_run, Finding(
            source="username:Example",
            category="username",
            label="Example",
            url="https://example.com/alice",
            verdict=Verdict.FOUND,
            confidence=0.9,
            signals={"username": "alice"},
            completeness=Completeness.COMPLETE,
        ))
        first_id = first.id

    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        second_run = repo.create_run(session, target)
        second = repo.add_observation(session, second_run, Finding(
            source="username:Example",
            category="username",
            label="Example",
            url="https://example.com/alice/",
            verdict=Verdict.NOT_FOUND,
            confidence=0.0,
            signals={"username": "alice"},
            completeness=Completeness.COMPLETE,
        ))
        contradictions = repo.contradictions_for_run(session, second_run.id)
        historical = session.get(repo.m.Observation, first_id)

        assert historical.temporal_status == TemporalStatus.HISTORICAL.value
        assert second.temporal_status == TemporalStatus.CURRENT.value
        assert second.first_seen_at == historical.first_seen_at
        assert len(contradictions) == 1
        assert contradictions[0].kind == "presence-changed"
        assert contradictions[0].earlier_observation_id == first_id


def test_old_style_finding_receives_storage_level_evidence_defaults(fresh_db):
    with fresh_db.session() as session:
        target = repo.get_or_create_target(session, Query(domain="example.com"))
        run = repo.create_run(session, target)
        observation = repo.add_observation(session, run, Finding(
            source="domain:dns",
            category="domain",
            label="example.com",
            verdict=Verdict.FOUND,
            confidence=0.8,
        ), reliability=0.75)

        assert observation.origin
        assert observation.independence_key == "dns"
        assert observation.observed_at is not None
        assert observation.confidence_dimensions["source_reliability"] == 0.75
