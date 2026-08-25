"""Typed repository helpers — the only place the rest of the app touches ORM.

All functions take an open Session so callers control the transaction boundary.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import cast, delete, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from ..evidence import (
    TemporalStatus,
    default_dimensions,
    evidence_claim_key,
    infer_origin,
    utc_now,
)
from ..models import Finding, Query
from . import models_db as m


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --- Targets ---------------------------------------------------------------

def _target_query_predicate(query: dict, dialect_name: str):
    column = cast(m.Target.query, JSONB) if dialect_name == "postgresql" else m.Target.query
    return column == query


def get_or_create_target(s: Session, query: Query, label: str | None = None,
                         watchlist: bool = False, owner_id: int | None = None) -> m.Target:
    q = query.normalized().model_dump(exclude_none=True)
    query_matches = _target_query_predicate(q, s.get_bind().dialect.name)
    existing = s.execute(
        select(m.Target).where(query_matches, m.Target.owner_id == owner_id)
    ).scalars().first()
    if existing:
        if watchlist and not existing.watchlist:
            existing.watchlist = True
        return existing
    t = m.Target(
        label=label or _label_for(q), query=q, watchlist=watchlist, owner_id=owner_id
    )
    s.add(t)
    s.flush()
    return t


def _label_for(q: dict) -> str:
    for k in ("username", "name", "email", "domain", "phone", "url", "ip_address"):
        if q.get(k):
            return str(q[k])
    return "target"


def list_targets(s: Session, watchlist_only: bool = False,
                 owner_id: int | None = None, include_all: bool = True) -> list[m.Target]:
    stmt = select(m.Target).order_by(m.Target.created_at.desc())
    if not include_all:
        stmt = stmt.where(m.Target.owner_id == owner_id)
    if watchlist_only:
        stmt = stmt.where(m.Target.watchlist.is_(True))
    return list(s.execute(stmt).scalars().all())


# --- Runs ------------------------------------------------------------------

def create_run(s: Session, target: m.Target) -> m.Run:
    r = m.Run(target_id=target.id, status="running")
    s.add(r)
    s.flush()
    return r


def finish_run(s: Session, run: m.Run, status: str, stats: dict) -> None:
    run.status = status
    run.finished_at = _now()
    run.stats = stats


def latest_finished_run(s: Session, target_id: int, before_run_id: int | None = None) -> Optional[m.Run]:
    stmt = (
        select(m.Run)
        .where(m.Run.target_id == target_id, m.Run.status == "done")
        .order_by(m.Run.started_at.desc())
    )
    if before_run_id is not None:
        stmt = stmt.where(m.Run.id < before_run_id)
    return s.execute(stmt).scalars().first()


def list_runs(s: Session, target_id: int | None = None, limit: int = 50,
              owner_id: int | None = None, include_all: bool = True) -> list[m.Run]:
    stmt = select(m.Run).order_by(m.Run.started_at.desc()).limit(limit)
    if target_id is not None:
        stmt = stmt.where(m.Run.target_id == target_id)
    if not include_all:
        stmt = stmt.join(m.Target, m.Target.id == m.Run.target_id).where(
            m.Target.owner_id == owner_id
        )
    return list(s.execute(stmt).scalars().all())


# --- Observations ----------------------------------------------------------

def add_observation(s: Session, run: m.Run, finding: Finding,
                    reliability: float = 0.5) -> m.Observation:
    origin = finding.origin or infer_origin(finding.source, finding.url)
    claim_key = evidence_claim_key(
        finding.category, finding.url, finding.label, finding.signals
    )
    observed_at = finding.temporal.observed_at or utc_now()
    complete = finding.completeness
    dimensions = finding.confidence_dimensions or default_dimensions(
        finding.confidence,
        reliability,
        complete,
        finding.extractions,
    )
    prior = s.execute(
        select(m.Observation)
        .where(
            m.Observation.target_id == run.target_id,
            m.Observation.claim_key == claim_key,
        )
        .order_by(m.Observation.observed_at.desc(), m.Observation.id.desc())
    ).scalars().first()
    first_seen = (
        prior.first_seen_at or prior.observed_at or prior.created_at
        if prior is not None else observed_at
    )
    temporal_status = (
        finding.temporal.status
        if finding.temporal.status != TemporalStatus.UNKNOWN
        else (
            TemporalStatus.CURRENT
            if finding.verdict.value in {"FOUND", "NOT_FOUND"}
            else TemporalStatus.UNKNOWN
        )
    )
    obs = m.Observation(
        run_id=run.id,
        target_id=run.target_id,
        source=finding.source,
        category=finding.category,
        label=finding.label,
        url=finding.url,
        verdict=finding.verdict.value,
        confidence=finding.confidence,
        reasons=list(finding.reasons),
        breakdown=finding.breakdown.model_dump() if finding.breakdown else None,
        trace=finding.trace,
        signals=dict(finding.signals),
        data=dict(finding.data),
        fingerprint=str(finding.data.get("fingerprint") or "") or None,
        reliability=reliability,
        collector=origin.collector,
        origin=origin.origin,
        evidence_class=origin.evidence_class.value,
        independence_key=origin.independence_key,
        claim_key=claim_key,
        extractions=[item.model_dump(mode="json") for item in finding.extractions],
        confidence_dimensions=dimensions.model_dump(mode="json"),
        policy=finding.policy.model_dump(mode="json"),
        completeness=complete.value,
        temporal_status=temporal_status.value,
        observed_at=observed_at,
        valid_from=finding.temporal.valid_from,
        valid_until=finding.temporal.valid_until,
        first_seen_at=finding.temporal.first_seen_at or first_seen,
        last_seen_at=finding.temporal.last_seen_at or observed_at,
    )
    s.add(obs)
    s.flush()
    _record_temporal_transition(s, run, prior, obs)
    return obs


def _record_temporal_transition(
    s: Session,
    run: m.Run,
    prior: m.Observation | None,
    current: m.Observation,
) -> None:
    if prior is None:
        return
    comparable = {"FOUND", "NOT_FOUND"}
    if prior.verdict not in comparable or current.verdict not in comparable:
        return
    prior.temporal_status = TemporalStatus.HISTORICAL.value
    if prior.verdict == current.verdict:
        return
    s.add(m.ObservationContradiction(
        run_id=run.id,
        target_id=run.target_id,
        claim_key=current.claim_key,
        earlier_observation_id=prior.id,
        later_observation_id=current.id,
        kind="presence-changed",
        severity="medium",
        reasons=[
            f"The claim changed from {prior.verdict} to {current.verdict}.",
            "Treat the earlier observation as historical; source changes and collection gaps "
            "can also explain this transition.",
        ],
    ))


def observations_for_run(s: Session, run_id: int, hits_only: bool = False) -> list[m.Observation]:
    stmt = select(m.Observation).where(m.Observation.run_id == run_id)
    if hits_only:
        stmt = stmt.where(m.Observation.verdict == "FOUND")
    return list(s.execute(stmt.order_by(m.Observation.id)).scalars().all())


def observations_for_target(s: Session, target_id: int, hits_only: bool = True) -> list[m.Observation]:
    stmt = select(m.Observation).where(m.Observation.target_id == target_id)
    if hits_only:
        stmt = stmt.where(m.Observation.verdict == "FOUND")
    return list(s.execute(stmt.order_by(m.Observation.id)).scalars().all())


def contradictions_for_run(s: Session, run_id: int) -> list[m.ObservationContradiction]:
    return list(s.execute(
        select(m.ObservationContradiction)
        .where(m.ObservationContradiction.run_id == run_id)
        .order_by(m.ObservationContradiction.id)
    ).scalars().all())


def contradictions_for_target(
    s: Session, target_id: int
) -> list[m.ObservationContradiction]:
    return list(s.execute(
        select(m.ObservationContradiction)
        .where(m.ObservationContradiction.target_id == target_id)
        .order_by(m.ObservationContradiction.id)
    ).scalars().all())


# --- Change events ---------------------------------------------------------

def add_change(s: Session, target_id: int, run_id: int, kind: str,
               source: str | None, label: str | None, detail: dict) -> m.ChangeEvent:
    ev = m.ChangeEvent(target_id=target_id, run_id=run_id, kind=kind,
                       source=source, label=label, detail=detail)
    s.add(ev)
    return ev


def list_changes(s: Session, target_id: int | None = None, limit: int = 100,
                 owner_id: int | None = None, include_all: bool = True) -> list[m.ChangeEvent]:
    stmt = select(m.ChangeEvent).order_by(m.ChangeEvent.created_at.desc()).limit(limit)
    if target_id is not None:
        stmt = stmt.where(m.ChangeEvent.target_id == target_id)
    if not include_all:
        stmt = stmt.join(m.Target, m.Target.id == m.ChangeEvent.target_id).where(
            m.Target.owner_id == owner_id
        )
    return list(s.execute(stmt).scalars().all())


# --- Schedules -------------------------------------------------------------

def create_schedule(s: Session, target_id: int, cron: str) -> m.Schedule:
    sc = m.Schedule(target_id=target_id, cron=cron, enabled=True)
    s.add(sc)
    s.flush()
    return sc


def list_schedules(s: Session, enabled_only: bool = True) -> list[m.Schedule]:
    stmt = select(m.Schedule)
    if enabled_only:
        stmt = stmt.where(m.Schedule.enabled.is_(True))
    return list(s.execute(stmt).scalars().all())


def touch_schedule(s: Session, schedule_id: int) -> None:
    sc = s.get(m.Schedule, schedule_id)
    if sc:
        sc.last_run_at = _now()


# --- Entities / graph (read helpers for API + reporting) -------------------

def list_entities(s: Session, target_id: int) -> list[m.Entity]:
    ent_ids = list(s.execute(
        select(m.Observation.entity_id).where(
            m.Observation.target_id == target_id,
            m.Observation.entity_id.is_not(None)).distinct()
    ).scalars().all())
    if not ent_ids:
        return []
    return list(s.execute(
        select(m.Entity).where(m.Entity.id.in_(ent_ids))
        .order_by(m.Entity.confidence.desc())
    ).scalars().all())


def list_sources(s: Session) -> list[m.Source]:
    return list(s.execute(select(m.Source).order_by(m.Source.name)).scalars().all())


# --- Durable job activity -------------------------------------------------

def clear_job_activity(s: Session, job_id: int) -> None:
    s.execute(delete(m.JobActivity).where(m.JobActivity.job_id == job_id))


def upsert_job_activity(s: Session, job_id: int, activities: list[dict]) -> None:
    """Store only the newest state for each graph node in a compact batch."""
    from hashlib import sha256

    latest: dict[str, dict] = {}
    for activity in activities:
        node_id = str(activity.get("id") or "")
        if node_id:
            latest[node_id] = activity
    for node_id, activity in latest.items():
        node_key = sha256(node_id.encode("utf-8")).hexdigest()
        row = s.execute(
            select(m.JobActivity).where(
                m.JobActivity.job_id == job_id,
                m.JobActivity.node_key == node_key,
            )
        ).scalars().first()
        sequence = int(activity.get("sequence") or 0)
        if row is None:
            s.add(m.JobActivity(
                job_id=job_id,
                node_key=node_key,
                sequence=sequence,
                payload=dict(activity),
            ))
        elif sequence >= row.sequence:
            row.sequence = sequence
            row.payload = dict(activity)
            row.updated_at = _now()


def list_job_activity(
    s: Session, job_id: int, *, after: int = 0, limit: int = 500
) -> list[m.JobActivity]:
    return list(s.execute(
        select(m.JobActivity)
        .where(m.JobActivity.job_id == job_id, m.JobActivity.sequence > after)
        .order_by(m.JobActivity.sequence, m.JobActivity.id)
        .limit(limit)
    ).scalars().all())


def save_source_health_check(s: Session, result: dict) -> m.SourceHealthCheck:
    row = m.SourceHealthCheck(
        module=result["module"],
        canary=result["name"],
        status=result["status"],
        duration_ms=result.get("duration_ms", 0),
        requests=result.get("requests", 0),
        detail=result.get("detail", {}),
    )
    s.add(row)
    s.flush()
    return row


def latest_source_health_checks(s: Session) -> dict[str, m.SourceHealthCheck]:
    rows = list(s.execute(
        select(m.SourceHealthCheck).order_by(
            m.SourceHealthCheck.module, m.SourceHealthCheck.created_at.desc(),
            m.SourceHealthCheck.id.desc()
        )
    ).scalars().all())
    latest: dict[str, m.SourceHealthCheck] = {}
    for row in rows:
        latest.setdefault(row.module, row)
    return latest


# --- Discovery graph (artifacts + edges) -----------------------------------

def persist_graph(s: Session, run: m.Run, artifacts: list, edges: list) -> None:
    """Persist the recursive scan's artifact nodes and provenance edges.

    `artifacts` are graph_models.Artifact; `edges` are engine._Edge
    (src_key/dst_key/module/detail). Edges whose endpoints weren't admitted as
    nodes (e.g. dropped on a budget ceiling) are skipped."""
    key_to_id: dict[str, int] = {}
    for a in artifacts:
        node = m.ArtifactNode(
            run_id=run.id, target_id=run.target_id, type=a.type.value,
            value=a.value, normalized=a.normalized, depth=a.depth,
            source_module=a.source_module,
            confidence=a.confidence,
            data={
                **dict(a.data),
                "evidence_policy": a.policy.model_dump(mode="json"),
                "origin": a.origin.model_dump(mode="json") if a.origin else None,
            },
        )
        s.add(node)
        s.flush()
        key_to_id[a.key] = node.id
    for e in edges:
        src, dst = key_to_id.get(e.src_key), key_to_id.get(e.dst_key)
        if src is None or dst is None:
            continue
        s.add(m.ArtifactEdge(run_id=run.id, src_artifact_id=src,
                             dst_artifact_id=dst, module=e.module, detail=dict(e.detail)))


def list_artifacts(s: Session, run_id: int) -> list[m.ArtifactNode]:
    return list(s.execute(
        select(m.ArtifactNode).where(m.ArtifactNode.run_id == run_id)
        .order_by(m.ArtifactNode.depth, m.ArtifactNode.id)
    ).scalars().all())


def list_artifact_edges(s: Session, run_id: int) -> list[m.ArtifactEdge]:
    return list(s.execute(
        select(m.ArtifactEdge).where(m.ArtifactEdge.run_id == run_id)
    ).scalars().all())


def persist_rule_findings(s: Session, run: m.Run, hits: list) -> None:
    """Persist fired correlation rules (rules.RuleHit) for a run."""
    for h in hits:
        s.add(m.RuleFinding(
            run_id=run.id, target_id=run.target_id, rule_id=h.rule_id,
            title=h.title, severity=h.severity, description=h.description,
            key=h.key[:400], evidence=list(h.evidence), detail=dict(h.detail),
        ))


def list_rule_findings(s: Session, run_id: int) -> list[m.RuleFinding]:
    return list(s.execute(
        select(m.RuleFinding).where(m.RuleFinding.run_id == run_id)
        .order_by(m.RuleFinding.id)
    ).scalars().all())


def save_calibration(s: Session, report: dict) -> m.CalibrationRun:
    row = m.CalibrationRun(
        n=report.get("n", 0), positives=report.get("positives", 0),
        negatives=report.get("negatives", 0), brier=report.get("brier", 0.0),
        ece=report.get("ece", 0.0),
        found_threshold=report.get("found_threshold", 0.0), report=report,
    )
    s.add(row)
    s.flush()
    return row


def list_calibration(s: Session, limit: int = 20) -> list[m.CalibrationRun]:
    return list(s.execute(
        select(m.CalibrationRun).order_by(m.CalibrationRun.id.desc()).limit(limit)
    ).scalars().all())


def save_evaluation(s: Session, report: dict) -> m.EvaluationRun:
    dataset = report.get("dataset") or {}
    metrics = report.get("metrics") or {}
    gate = report.get("gate") or {}
    row = m.EvaluationRun(
        dataset_name=dataset.get("name", "evaluation"),
        dataset_sha256=dataset.get("sha256", ""),
        provenance=dataset.get("provenance", "unknown"),
        cases=len(report.get("cases") or []),
        claims=metrics.get("claims", 0),
        precision=metrics.get("precision", 0.0),
        recall=metrics.get("recall", 0.0),
        gate_status=gate.get("status", "NEEDS_EVIDENCE"),
        report=report,
    )
    s.add(row)
    s.flush()
    return row


def list_evaluations(s: Session, limit: int = 20) -> list[m.EvaluationRun]:
    return list(s.execute(
        select(m.EvaluationRun).order_by(m.EvaluationRun.id.desc()).limit(limit)
    ).scalars().all())
