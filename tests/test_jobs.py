"""Durable job queue + worker loop (no network: scan is stubbed)."""

import dataclasses
import datetime as dt

import pytest

from recon.config import SETTINGS
from recon.jobs.base import LocalQueue
from recon.jobs import worker as worker_mod
from recon.jobs.activity import DurableActivityWriter
from recon import server


@pytest.mark.asyncio
async def test_enqueue_lease_complete_roundtrip():
    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "alice"}})
    assert q.status(jid) == "queued"

    leased = q.lease()
    assert leased["id"] == jid and leased["kind"] == "scan"
    assert q.status(jid) == "leased"
    assert q.lease() is None  # nothing else queued

    q.complete(jid)
    assert q.status(jid) == "done"


@pytest.mark.asyncio
async def test_worker_processes_job(monkeypatch):
    seen = []

    from recon.auth import create_user
    from recon.models import Query
    from recon.store import get_db, repo

    with get_db().session() as session:
        owner = create_user(session, "job-owner", "a strong job owner password")
        target = repo.get_or_create_target(session, Query(username="bob"), owner_id=owner.id)
        run = repo.create_run(session, target)
        owner_id, run_id = owner.id, run.id

    async def fake_scan(query, **kw):
        seen.append((query.username, kw["owner_id"]))
        return {"run_id": run_id}

    monkeypatch.setattr(worker_mod, "scan", fake_scan)

    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "bob"}}, owner_id=owner_id)
    processed = await worker_mod.run_worker(q, once=True, max_jobs=1)

    assert processed == 1
    assert seen == [("bob", owner_id)]
    from recon.store import models_db as m

    with get_db().session() as session:
        row = session.get(m.Job, jid)
        assert row.status == "done" and row.run_id == run_id and row.owner_id == owner_id


@pytest.mark.asyncio
async def test_failed_job_is_retried_then_errored(monkeypatch):
    async def boom(query, **kw):
        raise RuntimeError("down")

    monkeypatch.setattr(worker_mod, "scan", boom)
    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "z"}})

    # attempts 1,2,3 -> requeued; on the 3rd failure it errors out.
    for _ in range(3):
        job = q.lease()
        assert job is not None
        try:
            await worker_mod.process(job)
        except Exception as e:  # noqa: BLE001
            q.fail(job["id"], str(e))
    assert q.status(jid) == "error"


def test_stale_lease_is_reclaimed():
    from recon.store import get_db
    from recon.store import models_db as m

    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "alice"}})
    assert q.lease()["id"] == jid
    with get_db().session() as session:
        row = session.get(m.Job, jid)
        row.leased_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)

    reclaimed = q.lease()
    assert reclaimed["id"] == jid
    assert reclaimed["attempts"] == 2


def test_finished_jobs_are_pruned_after_retention_period():
    from recon.store import get_db
    from recon.store import models_db as m

    queue = LocalQueue(dataclasses.replace(SETTINGS, job_retention_days=1))
    job_id = queue.enqueue("scan", {"query": {"username": "old"}})
    queue.complete(job_id)
    with get_db().session() as session:
        job = session.get(m.Job, job_id)
        job.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)

    assert queue.lease() is None
    with get_db().session() as session:
        assert session.get(m.Job, job_id) is None


def test_jobs_can_be_cancelled_retried_and_released():
    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "alice"}})

    assert queue.request_cancel(job_id) == "cancelled"
    assert queue.cancellation_requested(job_id) is True
    assert queue.retry(job_id) == "queued"
    assert queue.recoverable_ids() == [job_id]

    assert queue.claim(job_id)["id"] == job_id
    assert queue.request_cancel(job_id) == "cancel_requested"
    queue.mark_cancelled(job_id)
    assert queue.status(job_id) == "cancelled"

    assert queue.retry(job_id) == "queued"
    assert queue.claim(job_id)["id"] == job_id
    queue.release(job_id)
    assert queue.status(job_id) == "queued"


@pytest.mark.asyncio
async def test_local_application_retries_a_failed_background_job(monkeypatch):
    from recon.store import get_db
    from recon.store import models_db as m

    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "alice"}})
    calls = 0

    async def flaky_scan(_query, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary source failure")
        return {"run_id": None}

    monkeypatch.setattr(server, "_queue", lambda: queue)
    monkeypatch.setattr(server, "scan", flaky_scan)

    await server._run_local_job(job_id)

    with get_db().session() as session:
        job = session.get(m.Job, job_id)
        assert job.status == "done"
        assert job.attempts == 2
    assert calls == 2


@pytest.mark.asyncio
async def test_durable_activity_keeps_latest_node_state():
    from recon.store import get_db, repo

    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "alice"}})
    writer = DurableActivityWriter(job_id, batch_size=10, flush_interval=60)
    await writer.start()
    await writer.record({
        "id": "request:1", "kind": "request", "sequence": 1,
        "phase": "started", "status": "running",
    })
    await writer.record({
        "id": "request:1", "kind": "request", "sequence": 2,
        "phase": "finished", "status": "finished", "outcome": "success",
    })
    await writer.close()

    with get_db().session() as session:
        rows = repo.list_job_activity(session, job_id)
        assert len(rows) == 1
        assert rows[0].sequence == 2
        assert rows[0].payload["outcome"] == "success"


@pytest.mark.asyncio
async def test_activity_writer_resets_a_retried_job():
    from recon.store import get_db, repo

    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "alice"}})
    first = DurableActivityWriter(job_id)
    await first.start()
    await first.record({"id": "old", "kind": "process", "sequence": 9})
    await first.close()

    retry = DurableActivityWriter(job_id)
    await retry.start()
    await retry.record({"id": "new", "kind": "process", "sequence": 1})
    await retry.close()

    with get_db().session() as session:
        rows = repo.list_job_activity(session, job_id)
        assert [row.payload["id"] for row in rows] == ["new"]
