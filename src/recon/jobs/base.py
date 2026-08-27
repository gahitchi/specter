"""Durable job queue interface and SQL-backed local implementation."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from typing import Any, Optional

from sqlalchemy import and_, delete, or_, select, update

from ..config import SETTINGS, Settings
from ..store import get_db
from ..store import models_db as m


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _job_dict(job: m.Job) -> dict:
    return {
        "id": job.id,
        "kind": job.kind,
        "payload": dict(job.payload),
        "owner_id": job.owner_id,
        "target_id": job.target_id,
        "run_id": job.run_id,
        "attempts": job.attempts,
    }


class JobQueue(ABC):
    @abstractmethod
    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        run_id: int | None = None,
        *,
        owner_id: int | None = None,
        target_id: int | None = None,
    ) -> int: ...

    @abstractmethod
    def lease(self) -> Optional[dict]: ...

    @abstractmethod
    def complete(self, job_id: int, run_id: int | None = None) -> None: ...

    @abstractmethod
    def fail(self, job_id: int, error: str) -> None: ...

    @abstractmethod
    def status(self, job_id: int) -> Optional[str]: ...

    @abstractmethod
    def request_cancel(self, job_id: int) -> Optional[str]: ...

    @abstractmethod
    def cancellation_requested(self, job_id: int) -> bool: ...

    @abstractmethod
    def mark_cancelled(self, job_id: int) -> None: ...

    @abstractmethod
    def retry(self, job_id: int) -> Optional[str]: ...

    @abstractmethod
    def release(self, job_id: int) -> None: ...


class LocalQueue(JobQueue):
    def __init__(self, settings: Settings = SETTINGS) -> None:
        self.settings = settings

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        run_id: int | None = None,
        *,
        owner_id: int | None = None,
        target_id: int | None = None,
    ) -> int:
        if not kind.strip():
            raise ValueError("job kind cannot be empty")
        with get_db().session() as session:
            job = m.Job(
                kind=kind,
                payload=payload,
                owner_id=owner_id,
                target_id=target_id,
                run_id=run_id,
                status="queued",
            )
            session.add(job)
            session.flush()
            return job.id

    def _eligible(self, stale_before: dt.datetime):
        return and_(
            m.Job.attempts < self.settings.job_max_attempts,
            or_(
                m.Job.status == "queued",
                and_(m.Job.status == "leased", m.Job.leased_at < stale_before),
            ),
        )

    def _cancel_orphaned_requests(self, session, stale_before: dt.datetime) -> None:
        session.execute(
            update(m.Job)
            .where(
                m.Job.status == "cancel_requested",
                m.Job.leased_at < stale_before,
            )
            .values(status="cancelled", leased_at=None, error=None)
        )

    def _expire_exhausted(self, session, stale_before: dt.datetime) -> None:
        session.execute(
            update(m.Job)
            .where(
                m.Job.status == "leased",
                m.Job.leased_at < stale_before,
                m.Job.attempts >= self.settings.job_max_attempts,
            )
            .values(status="error", leased_at=None, error="worker lease expired")
        )

    def _prune_finished(self, session, now: dt.datetime) -> None:
        cutoff = now - dt.timedelta(days=self.settings.job_retention_days)
        session.execute(
            delete(m.Job).where(
                m.Job.status.in_(("done", "error", "cancelled")),
                m.Job.created_at < cutoff,
            )
        )

    def lease(self) -> Optional[dict]:
        now = _now()
        stale_before = now - dt.timedelta(seconds=self.settings.job_lease_seconds)
        with get_db().session() as session:
            self._prune_finished(session, now)
            self._expire_exhausted(session, stale_before)
            self._cancel_orphaned_requests(session, stale_before)
            if session.bind.dialect.name == "postgresql":
                job = session.execute(
                    select(m.Job)
                    .where(self._eligible(stale_before))
                    .order_by(m.Job.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).scalars().first()
                if job is None:
                    return None
                job.status = "leased"
                job.leased_at = now
                job.attempts += 1
                job.error = None
                return _job_dict(job)

            candidate = (
                select(m.Job.id)
                .where(self._eligible(stale_before))
                .order_by(m.Job.id)
                .limit(1)
                .scalar_subquery()
            )
            job = session.execute(
                update(m.Job)
                .where(m.Job.id == candidate)
                .values(
                    status="leased",
                    leased_at=now,
                    attempts=m.Job.attempts + 1,
                    error=None,
                )
                .returning(m.Job)
            ).scalars().first()
            return _job_dict(job) if job is not None else None

    def claim(self, job_id: int) -> Optional[dict]:
        """Atomically lease one known durable row (used by Redis/arq workers)."""
        now = _now()
        stale_before = now - dt.timedelta(seconds=self.settings.job_lease_seconds)
        with get_db().session() as session:
            job = session.execute(
                update(m.Job)
                .where(m.Job.id == job_id, self._eligible(stale_before))
                .values(
                    status="leased",
                    leased_at=now,
                    attempts=m.Job.attempts + 1,
                    error=None,
                )
                .returning(m.Job)
            ).scalars().first()
            return _job_dict(job) if job is not None else None

    def complete(self, job_id: int, run_id: int | None = None) -> None:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is not None:
                job.status = "done"
                job.leased_at = None
                job.error = None
                if run_id is not None:
                    job.run_id = run_id

    def fail(self, job_id: int, error: str) -> None:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is not None:
                job.status = (
                    "queued" if job.attempts < self.settings.job_max_attempts else "error"
                )
                job.leased_at = None
                job.error = str(error)[:500]

    def dispatch_failed(self, job_id: int, error: str) -> None:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is not None:
                job.status = "error"
                job.leased_at = None
                job.error = str(error)[:500]

    def status(self, job_id: int) -> Optional[str]:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            return job.status if job is not None else None

    def request_cancel(self, job_id: int) -> Optional[str]:
        """Cancel queued work or ask a leased worker to stop cooperatively."""
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is None:
                return None
            if job.status == "queued":
                job.status = "cancelled"
                job.error = None
            elif job.status == "leased":
                job.status = "cancel_requested"
                job.error = None
            return job.status

    def cancellation_requested(self, job_id: int) -> bool:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            return job is not None and job.status in {"cancel_requested", "cancelled"}

    def mark_cancelled(self, job_id: int) -> None:
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is not None:
                job.status = "cancelled"
                job.leased_at = None
                job.error = None

    def retry(self, job_id: int) -> Optional[str]:
        """Requeue terminal work while preserving its earlier run for audit."""
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is None:
                return None
            if job.status in {"queued", "leased", "cancel_requested"}:
                return job.status
            job.status = "queued"
            job.attempts = 0
            job.leased_at = None
            job.error = None
            job.run_id = None
            return job.status

    def release(self, job_id: int) -> None:
        """Return interrupted leased work to the queue for restart recovery."""
        with get_db().session() as session:
            job = session.get(m.Job, job_id)
            if job is not None and job.status == "leased":
                job.status = "queued"
                job.leased_at = None
                job.error = "application stopped; queued to resume"

    def recoverable_ids(self) -> list[int]:
        """Queued job identifiers in stable order for local startup recovery."""
        with get_db().session() as session:
            return list(session.execute(
                select(m.Job.id)
                .where(m.Job.status == "queued")
                .order_by(m.Job.id)
            ).scalars())


def get_queue() -> JobQueue:
    if SETTINGS.queue_backend == "local":
        return LocalQueue()
    if SETTINGS.queue_backend == "arq":
        try:
            from .arq_queue import ArqQueue
        except ImportError as exc:
            raise RuntimeError(
                "ARQ queue selected but distributed dependencies are not installed"
            ) from exc
        return ArqQueue()
    raise ValueError(f"unsupported queue backend: {SETTINGS.queue_backend}")
