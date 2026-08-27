"""Optional Redis/arq dispatch path, exercised without a live Redis server."""

import pytest

pytest.importorskip("arq")

from recon.jobs import arq_queue
from recon.jobs.base import LocalQueue
from recon.jobs import worker as worker_mod
from recon.ratelimit import RedisHostLimiter
from recon.store import get_db
from recon.store import models_db as m


class _FakePool:
    def __init__(self):
        self.calls = []
        self.closed = False

    async def enqueue_job(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return object()

    async def aclose(self):
        self.closed = True


@pytest.mark.asyncio
async def test_arq_enqueue_works_inside_running_event_loop(monkeypatch):
    pool = _FakePool()

    async def fake_create_pool(*_args, **_kwargs):
        return pool

    monkeypatch.setattr(arq_queue, "create_pool", fake_create_pool)
    queue = arq_queue.ArqQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "alice"}})

    assert queue.status(job_id) == "queued"
    assert pool.calls[0][0] == ("run_scan_job", job_id)
    assert pool.calls[0][1]["_job_id"] == f"recon-{job_id}"
    assert pool.closed is True


@pytest.mark.asyncio
async def test_arq_dispatch_failure_marks_durable_job_error(monkeypatch):
    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("redis password=do-not-persist")

    monkeypatch.setattr(arq_queue, "create_pool", unavailable)
    queue = arq_queue.ArqQueue()

    with pytest.raises(RuntimeError, match="Redis dispatch failed"):
        queue.enqueue("scan", {"query": {"username": "alice"}})

    with get_db().session() as session:
        job = session.query(m.Job).order_by(m.Job.id.desc()).first()
        assert job.status == "error"
        assert "do-not-persist" not in job.error
        assert "Redis dispatch failed" in job.error


@pytest.mark.asyncio
async def test_arq_worker_updates_durable_status(monkeypatch):
    seen = []

    async def fake_process(job, _queue=None):
        seen.append(job["payload"]["query"]["username"])

    monkeypatch.setattr(worker_mod, "process", fake_process)
    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "bob"}})

    result = await arq_queue.run_scan_job({}, job_id)
    assert result["status"] == "done"
    assert queue.status(job_id) == "done"
    assert seen == ["bob"]


@pytest.mark.asyncio
async def test_arq_worker_requeues_failed_attempt(monkeypatch):
    async def fail(_job, _queue=None):
        raise RuntimeError("source unavailable")

    monkeypatch.setattr(worker_mod, "process", fail)
    queue = LocalQueue()
    job_id = queue.enqueue("scan", {"query": {"username": "bob"}})

    with pytest.raises(RuntimeError, match="source unavailable"):
        await arq_queue.run_scan_job({}, job_id)
    assert queue.status(job_id) == "queued"


@pytest.mark.asyncio
async def test_redis_host_limiter_uses_atomic_expiring_lease():
    class FakeRedis:
        def __init__(self):
            self.attempts = 0
            self.closed = False

        async def set(self, key, value, *, nx, px):
            assert key == "recon:rl:example.com"
            assert value == "1" and nx is True and px == 1
            self.attempts += 1
            return self.attempts > 1

        async def pttl(self, _key):
            return 1

        async def aclose(self):
            self.closed = True

    limiter = object.__new__(RedisHostLimiter)
    limiter._r = FakeRedis()
    limiter._min = 0.001
    await limiter.acquire("example.com")
    assert limiter._r.attempts == 2
    await limiter.aclose()
    assert limiter._r.closed is True
