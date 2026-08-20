"""SQLAlchemy 2.0 ORM tables. JSON columns keep the schema portable across
SQLite (default) and Postgres while still storing rich structured payloads.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Target(Base):
    """An investigation subject: a set of identifiers, optionally watch-listed."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    label: Mapped[Optional[str]] = mapped_column(String(200))
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    watchlist: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    runs: Mapped[list["Run"]] = relationship(back_populates="target")


class Run(Base):
    """One execution of a scan against a Target."""

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|running|done|error
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=None)

    target: Mapped[Target] = relationship(back_populates="runs")
    observations: Mapped[list["Observation"]] = relationship(back_populates="run")


class Observation(Base):
    """A persisted, provenance-tagged Finding. The temporal record of evidence."""

    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    entity_id: Mapped[Optional[int]] = mapped_column(ForeignKey("entities.id"), index=True)

    source: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    label: Mapped[str] = mapped_column(String(200))
    url: Mapped[Optional[str]] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    breakdown: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=None)
    trace: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=None)
    signals: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    reliability: Mapped[float] = mapped_column(Float, default=0.5)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    run: Mapped[Run] = relationship(back_populates="observations")
    entity: Mapped[Optional["Entity"]] = relationship(back_populates="observations")
    reviews: Mapped[list["ObservationReview"]] = relationship(
        back_populates="observation", order_by="ObservationReview.id"
    )


class ObservationReview(Base):
    """Immutable investigator decision attached to an observation.

    New rows supersede older rows. Keeping the history makes manual decisions
    auditable without mutating the automated verdict that produced the finding.
    """

    __tablename__ = "observation_reviews"

    id: Mapped[int] = mapped_column(primary_key=True)
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id"), index=True
    )
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    decision: Mapped[str] = mapped_column(String(20), index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    reviewer: Mapped[str] = mapped_column(String(120), default="local")
    reviewer_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    observation: Mapped[Observation] = relationship(back_populates="reviews")


class Entity(Base):
    """A resolved identity node in the correlation graph."""

    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[Optional[str]] = mapped_column(String(200))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # canonical signals
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    breakdown: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=None)
    flags: Mapped[list[str]] = mapped_column(JSON, default=list)  # contradictions, review, etc.
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    observations: Mapped[list[Observation]] = relationship(back_populates="entity")


class EntityEdge(Base):
    """A weighted relationship between two entities (or merge provenance)."""

    __tablename__ = "entity_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))  # shares-email | same-handle | co-occurs ...
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Source(Base):
    """Per-connector reliability and circuit-breaker state."""

    __tablename__ = "sources"

    name: Mapped[str] = mapped_column(String(120), primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), default="")
    enabled: Mapped[bool] = mapped_column(default=True)
    reliability: Mapped[float] = mapped_column(Float, default=0.5)
    successes: Mapped[int] = mapped_column(Integer, default=0)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    breaker_state: Mapped[str] = mapped_column(String(12), default="closed")  # closed|open|half_open
    breaker_until: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(Text)


class SourceHealthCheck(Base):
    """Result of an explicit, designated source canary."""

    __tablename__ = "source_health_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    module: Mapped[str] = mapped_column(String(120), index=True)
    canary: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditEvent(Base):
    """Security-conscious local audit trail for human and governance actions."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str] = mapped_column(String(120), default="local")
    actor_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(40), index=True)
    object_id: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class User(Base):
    """Account used when authenticated or remote mode is enabled."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="analyst", index=True)
    active: Mapped[bool] = mapped_column(default=True, index=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class UserSession(Base):
    """Server-side session; only a hash of the opaque browser token is stored."""

    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)

    user: Mapped[User] = relationship()


class EntityPairReview(Base):
    """Independent label for a candidate observation pair used by ML training."""

    __tablename__ = "entity_pair_reviews"

    id: Mapped[int] = mapped_column(primary_key=True)
    left_observation_id: Mapped[int] = mapped_column(ForeignKey("observations.id"), index=True)
    right_observation_id: Mapped[int] = mapped_column(ForeignKey("observations.id"), index=True)
    same_identity: Mapped[bool] = mapped_column(index=True)
    reviewer_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    reviewer: Mapped[str] = mapped_column(String(120))
    verification_method: Mapped[str] = mapped_column(String(200))
    note: Mapped[str] = mapped_column(Text, default="")
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CacheEntry(Base):
    """Store-backed response cache so re-runs don't depend on live sources."""

    __tablename__ = "cache_entries"

    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)


class Job(Base):
    """Durable unit of work in the queue (survives restarts; resumable)."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    target_id: Mapped[Optional[int]] = mapped_column(ForeignKey("targets.id"), index=True)
    run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("runs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)  # queued|leased|done|error
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    leased_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    error: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class JobActivity(Base):
    """Latest graph state for one durable job activity node."""

    __tablename__ = "job_activity_nodes"
    __table_args__ = (
        UniqueConstraint("job_id", "node_key", name="uq_job_activity_node"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), index=True
    )
    node_key: Mapped[str] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )


class Schedule(Base):
    """Recurring re-scan of a Target (long-term monitoring)."""

    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    cron: Mapped[str] = mapped_column(String(80))  # e.g. "0 */6 * * *"
    enabled: Mapped[bool] = mapped_column(default=True)
    last_run_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChangeEvent(Base):
    """A detected change between consecutive runs (timeline entry / alert)."""

    __tablename__ = "change_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))  # appeared|disappeared|changed
    source: Mapped[Optional[str]] = mapped_column(String(120))
    label: Mapped[Optional[str]] = mapped_column(String(200))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ArtifactNode(Base):
    """A typed data point discovered during a recursive scan (a node in the
    discovery graph). Distinct from `Entity`: this records *what was found and
    how we got there* during a run, not a resolved identity cluster."""

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(String(400), index=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    source_module: Mapped[str] = mapped_column(String(60), default="seed")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ArtifactEdge(Base):
    """A discovery-provenance edge: artifact `src` led to artifact `dst` via a
    module (parent -> child in the traversal)."""

    __tablename__ = "artifact_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    src_artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), index=True)
    dst_artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), index=True)
    module: Mapped[str] = mapped_column(String(60))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CalibrationRun(Base):
    """One execution of `specter calibrate`: the calibration metrics of the verify
    engine against ground-truth labels at a point in time (Phase 5c)."""

    __tablename__ = "calibration_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    n: Mapped[int] = mapped_column(Integer, default=0)
    positives: Mapped[int] = mapped_column(Integer, default=0)
    negatives: Mapped[int] = mapped_column(Integer, default=0)
    brier: Mapped[float] = mapped_column(Float, default=0.0)
    ece: Mapped[float] = mapped_column(Float, default=0.0)
    found_threshold: Mapped[float] = mapped_column(Float, default=0.0)
    report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RuleFinding(Base):
    """An insight: a declarative correlation rule that fired on a run's
    discovery graph (Phase 4). Distinct from `Entity` (identity cluster) and
    `ArtifactNode` (raw discovery) — this is the *interpreted* signal."""

    __tablename__ = "rule_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    key: Mapped[str] = mapped_column(String(400), default="")
    evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
