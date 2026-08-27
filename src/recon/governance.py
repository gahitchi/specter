"""Investigator review, data retention, deletion, and controlled exports."""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any

from sqlalchemy import delete, func, or_, select

from .store import models_db as m

_DECISIONS = {"accepted", "rejected", "unresolved"}


def add_audit_event(
    session,
    action: str,
    object_type: str,
    object_id: int | None,
    *,
    actor: str = "local",
    actor_user_id: int | None = None,
    detail: dict | None = None,
) -> m.AuditEvent:
    event = m.AuditEvent(
        action=action,
        actor=actor[:120] or "local",
        actor_user_id=actor_user_id,
        object_type=object_type[:40],
        object_id=object_id,
        detail=detail or {},
    )
    session.add(event)
    session.flush()
    return event


def review_observation(
    session,
    observation_id: int,
    decision: str,
    *,
    note: str = "",
    reviewer: str = "local",
    reviewer_user_id: int | None = None,
) -> m.ObservationReview:
    decision = decision.lower()
    if decision not in _DECISIONS:
        raise ValueError(f"decision must be one of: {', '.join(sorted(_DECISIONS))}")
    observation = session.get(m.Observation, observation_id)
    if observation is None:
        raise LookupError(f"observation {observation_id} not found")
    review = m.ObservationReview(
        observation_id=observation.id,
        run_id=observation.run_id,
        target_id=observation.target_id,
        decision=decision,
        note=note[:4000],
        reviewer=reviewer[:120] or "local",
        reviewer_user_id=reviewer_user_id,
    )
    session.add(review)
    session.flush()
    add_audit_event(
        session,
        "observation.reviewed",
        "observation",
        observation.id,
        actor=review.reviewer,
        actor_user_id=reviewer_user_id,
        detail={"review_id": review.id, "decision": decision},
    )
    # A profile snapshot was synthesized before this human decision existed.
    # Never continue presenting that snapshot as current; correlation is rebuilt
    # by the caller and a new scan can produce a fresh full profile.
    run = session.get(m.Run, observation.run_id)
    if run is not None:
        stats = copy.deepcopy(run.stats or {})
        profile = copy.deepcopy(stats.get("profile") or {})
        if profile:
            profile["status"] = "unresolved"
            profile["confidence"] = 0.0
            profile["assessment"] = (
                "A human review changed the evidence interpretation. Run the "
                "investigation again to synthesize a current profile."
            )
            profile["primary_identity"] = None
            profile["accounts"] = []
            profile["identifiers"] = [
                item
                for item in profile.get("identifiers", [])
                if item.get("standing") == "provided"
            ]
            profile["complete"] = False
            stats["profile"] = profile
        stats["interpretation_stale_after_review"] = True
        run.stats = stats
    return review


def latest_reviews(
    session, *, run_id: int | None = None, target_id: int | None = None
) -> dict[int, m.ObservationReview]:
    statement = select(m.ObservationReview).order_by(
        m.ObservationReview.observation_id,
        m.ObservationReview.created_at.desc(),
        m.ObservationReview.id.desc(),
    )
    if run_id is not None:
        statement = statement.where(m.ObservationReview.run_id == run_id)
    if target_id is not None:
        statement = statement.where(m.ObservationReview.target_id == target_id)
    latest: dict[int, m.ObservationReview] = {}
    for review in session.execute(statement).scalars():
        latest.setdefault(review.observation_id, review)
    return latest


def review_history(
    session, *, run_id: int | None = None, target_id: int | None = None, limit: int = 500
) -> list[m.ObservationReview]:
    statement = select(m.ObservationReview).order_by(
        m.ObservationReview.created_at.desc(), m.ObservationReview.id.desc()
    ).limit(limit)
    if run_id is not None:
        statement = statement.where(m.ObservationReview.run_id == run_id)
    if target_id is not None:
        statement = statement.where(m.ObservationReview.target_id == target_id)
    return list(session.execute(statement).scalars().all())


def reviewed_calibration_labels(session) -> list[dict]:
    """Export latest reviewed username-site outcomes as calibration labels."""
    latest = latest_reviews(session)
    rows = session.execute(
        select(m.Observation, m.Target)
        .join(m.Target, m.Target.id == m.Observation.target_id)
        .where(m.Observation.category == "username", m.Observation.source.like("username:%"))
        .order_by(m.Observation.id)
    ).all()
    labels: dict[tuple[str, str], tuple[dt.datetime, int, dict]] = {}
    for observation, target in rows:
        review = latest.get(observation.id)
        account = (target.query or {}).get("username")
        if review is None or review.decision == "unresolved" or not account:
            continue
        site = observation.source.split(":", 1)[1]
        exported = {
            "category": "username",
            "account": str(account),
            "site": site,
            "present": review.decision == "accepted",
            "review_id": review.id,
            "verified_by": review.reviewer,
            "verification_method": "manual investigator review",
            "verified_at": review.created_at.isoformat(),
        }
        key = (str(account), site)
        previous = labels.get(key)
        ordering = (_as_utc(review.created_at), review.id)
        if previous is None or ordering > previous[:2]:
            labels[key] = (*ordering, exported)
    return [item[2] for item in labels.values()]


def _delete_count(session, model, *conditions) -> int:
    result = session.execute(delete(model).where(*conditions))
    return int(result.rowcount or 0)


def purge_target(
    session, target_id: int, *, actor: str = "local", actor_user_id: int | None = None
) -> dict[str, int]:
    target = session.get(m.Target, target_id)
    if target is None:
        raise LookupError(f"target {target_id} not found")

    run_ids = list(session.execute(
        select(m.Run.id).where(m.Run.target_id == target_id)
    ).scalars())
    observation_ids = list(session.execute(
        select(m.Observation.id).where(m.Observation.target_id == target_id)
    ).scalars())
    entity_ids = list(session.execute(
        select(m.Observation.entity_id).where(
            m.Observation.target_id == target_id,
            m.Observation.entity_id.is_not(None),
        ).distinct()
    ).scalars())
    artifact_ids = list(session.execute(
        select(m.ArtifactNode.id).where(m.ArtifactNode.target_id == target_id)
    ).scalars())
    pair_review_ids = []
    if observation_ids:
        pair_review_ids = list(session.execute(
            select(m.EntityPairReview.id).where(or_(
                m.EntityPairReview.left_observation_id.in_(observation_ids),
                m.EntityPairReview.right_observation_id.in_(observation_ids),
            ))
        ).scalars())

    counts: dict[str, int] = {}
    audit_conditions = [
        (m.AuditEvent.object_type == "target") & (m.AuditEvent.object_id == target_id)
    ]
    if observation_ids:
        audit_conditions.append(
            (m.AuditEvent.object_type == "observation")
            & m.AuditEvent.object_id.in_(observation_ids)
        )
    if pair_review_ids:
        audit_conditions.append(
            (m.AuditEvent.object_type == "entity_pair_review")
            & m.AuditEvent.object_id.in_(pair_review_ids)
        )
    counts["audit_events"] = _delete_count(
        session, m.AuditEvent, or_(*audit_conditions)
    )
    if observation_ids:
        counts["contradictions"] = _delete_count(
            session,
            m.ObservationContradiction,
            or_(
                m.ObservationContradiction.earlier_observation_id.in_(observation_ids),
                m.ObservationContradiction.later_observation_id.in_(observation_ids),
            ),
        )
        counts["pair_reviews"] = _delete_count(
            session, m.EntityPairReview,
            or_(
                m.EntityPairReview.left_observation_id.in_(observation_ids),
                m.EntityPairReview.right_observation_id.in_(observation_ids),
            ),
        )
        counts["reviews"] = _delete_count(
            session, m.ObservationReview,
            m.ObservationReview.observation_id.in_(observation_ids),
        )
    if artifact_ids:
        counts["artifact_edges"] = _delete_count(
            session, m.ArtifactEdge,
            or_(
                m.ArtifactEdge.src_artifact_id.in_(artifact_ids),
                m.ArtifactEdge.dst_artifact_id.in_(artifact_ids),
            ),
        )
    counts["artifacts"] = _delete_count(
        session, m.ArtifactNode, m.ArtifactNode.target_id == target_id
    )
    counts["rules"] = _delete_count(
        session, m.RuleFinding, m.RuleFinding.target_id == target_id
    )
    counts["changes"] = _delete_count(
        session, m.ChangeEvent, m.ChangeEvent.target_id == target_id
    )
    counts["schedules"] = _delete_count(
        session, m.Schedule, m.Schedule.target_id == target_id
    )
    if run_ids:
        counts["jobs"] = _delete_count(
            session,
            m.Job,
            or_(m.Job.run_id.in_(run_ids), m.Job.target_id == target_id),
        )
    else:
        counts["jobs"] = _delete_count(session, m.Job, m.Job.target_id == target_id)
    counts["observations"] = _delete_count(
        session, m.Observation, m.Observation.target_id == target_id
    )
    counts["runs"] = _delete_count(session, m.Run, m.Run.target_id == target_id)
    counts["targets"] = _delete_count(session, m.Target, m.Target.id == target_id)

    if entity_ids:
        orphan_ids = list(session.execute(
            select(m.Entity.id).where(
                m.Entity.id.in_(entity_ids),
                ~select(m.Observation.id)
                .where(m.Observation.entity_id == m.Entity.id)
                .exists(),
            )
        ).scalars())
        if orphan_ids:
            counts["entity_edges"] = _delete_count(
                session, m.EntityEdge,
                or_(m.EntityEdge.src_id.in_(orphan_ids), m.EntityEdge.dst_id.in_(orphan_ids)),
            )
            counts["entities"] = _delete_count(session, m.Entity, m.Entity.id.in_(orphan_ids))

    add_audit_event(
        session,
        "target.purged",
        "target",
        target_id,
        actor=actor,
        actor_user_id=actor_user_id,
        detail={"deleted": counts},
    )
    return counts


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value


def expired_target_ids(
    session, days: int, *, now: dt.datetime | None = None
) -> list[int]:
    if days <= 0:
        raise ValueError("retention days must be positive")
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=days)
    activity = dict(session.execute(
        select(m.Run.target_id, func.max(m.Run.started_at)).group_by(m.Run.target_id)
    ).all())
    expired = []
    for target in session.execute(select(m.Target)).scalars():
        last_activity = activity.get(target.id) or target.created_at
        if _as_utc(last_activity) < cutoff:
            expired.append(target.id)
    return sorted(expired)


def apply_retention(
    session,
    days: int,
    *,
    dry_run: bool = True,
    actor: str = "local",
    actor_user_id: int | None = None,
    now: dt.datetime | None = None,
) -> dict:
    target_ids = expired_target_ids(session, days, now=now)
    result: dict[str, Any] = {"days": days, "dry_run": dry_run, "target_ids": target_ids}
    if dry_run:
        return result
    result["deleted"] = [
        purge_target(session, target_id, actor=actor, actor_user_id=actor_user_id)
        for target_id in target_ids
    ]
    if target_ids:
        add_audit_event(
            session,
            "retention.applied",
            "database",
            None,
            actor=actor,
            actor_user_id=actor_user_id,
            detail={"days": days, "targets_deleted": len(target_ids)},
        )
    return result


def target_export(session, target_id: int, *, redacted: bool = False) -> dict:
    target = session.get(m.Target, target_id)
    if target is None:
        raise LookupError(f"target {target_id} not found")
    runs = list(session.execute(
        select(m.Run).where(m.Run.target_id == target_id).order_by(m.Run.id)
    ).scalars())
    observations = list(session.execute(
        select(m.Observation).where(m.Observation.target_id == target_id)
        .order_by(m.Observation.id)
    ).scalars())
    reviews = review_history(session, target_id=target_id, limit=100_000)
    contradictions = list(session.execute(
        select(m.ObservationContradiction)
        .where(m.ObservationContradiction.target_id == target_id)
        .order_by(m.ObservationContradiction.id)
    ).scalars())

    exported_observations = []
    for observation in observations:
        row = {
            "id": observation.id,
            "run_id": observation.run_id,
            "source": observation.source,
            "category": observation.category,
            "verdict": observation.verdict,
            "confidence": observation.confidence,
            "reliability": observation.reliability,
            "collector": observation.collector,
            "origin": observation.origin,
            "evidence_class": observation.evidence_class,
            "independence_key": observation.independence_key,
            "temporal_status": observation.temporal_status,
            "observed_at": (
                observation.observed_at.isoformat() if observation.observed_at else None
            ),
            "first_seen_at": (
                observation.first_seen_at.isoformat() if observation.first_seen_at else None
            ),
            "last_seen_at": (
                observation.last_seen_at.isoformat() if observation.last_seen_at else None
            ),
            "completeness": observation.completeness,
            "created_at": observation.created_at.isoformat(),
        }
        if not redacted:
            row.update({
                "label": observation.label,
                "url": observation.url,
                "reasons": observation.reasons,
                "breakdown": observation.breakdown,
                "trace": observation.trace,
                "signals": observation.signals,
                "data": observation.data,
                "claim_key": observation.claim_key,
                "extractions": observation.extractions,
                "confidence_dimensions": observation.confidence_dimensions,
                "policy": observation.policy,
            })
        exported_observations.append(row)

    return {
        "format": "specter-target-export-v2",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "redacted": redacted,
        "target": {
            "id": target.id,
            "label": "[REDACTED]" if redacted else target.label,
            "query": {key: "[REDACTED]" for key in target.query} if redacted else target.query,
            "created_at": target.created_at.isoformat(),
        },
        "runs": [
            {
                "id": run.id,
                "status": run.status,
                "started_at": run.started_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "stats": run.stats,
                "provenance": run.provenance,
            }
            for run in runs
        ],
        "observations": exported_observations,
        "reviews": [
            {
                "id": review.id,
                "observation_id": review.observation_id,
                "decision": review.decision,
                "note": "[REDACTED]" if redacted and review.note else review.note,
                "reviewer": "[REDACTED]" if redacted else review.reviewer,
                "created_at": review.created_at.isoformat(),
            }
            for review in reviews
        ],
        "contradictions": [
            {
                "id": item.id,
                "claim_key": "[REDACTED]" if redacted else item.claim_key,
                "earlier_observation_id": item.earlier_observation_id,
                "later_observation_id": item.later_observation_id,
                "kind": item.kind,
                "severity": item.severity,
                "reasons": item.reasons,
                "created_at": item.created_at.isoformat(),
            }
            for item in contradictions
        ],
    }
