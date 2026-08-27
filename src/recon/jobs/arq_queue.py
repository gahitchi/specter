"""Redis/arq queue adapter with durable SQL bookkeeping."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable, Coroutine
from typing import Any, Optional, TypeVar

from arq import create_pool
from arq.connections import RedisSettings

from ..config import SETTINGS, env_value
from ..keys import redact
from .base import JobQueue, LocalQueue

T = TypeVar("T")


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(
        env_value("RECON_REDIS_DSN", "redis://localhost:6379") or "redis://localhost:6379"
    )


def _serialize(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _deserialize(value: bytes) -> dict:
    return json.loads(value.decode("utf-8"))


def _run_sync(factory: Callable[[], Coroutine[Any, Any, T]]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="recon-arq") as executor:
        return executor.submit(lambda: asyncio.run(factory())).result()


class ArqQueue(JobQueue):
    def __init__(self) -> None:
        self._redis_settings = _redis_settings()
        self._local = LocalQueue()

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        run_id: int | None = None,
        *,
        owner_id: int | None = None,
        target_id: int | None = None,
    ) -> int:
        job_id = self._local.enqueue(
            kind, payload, run_id, owner_id=owner_id, target_id=target_id
        )

        self._dispatch(job_id)
        return job_id

    def _dispatch(self, job_id: int) -> None:
        async def push() -> None:
            pool = await create_pool(
                self._redis_settings,
                job_serializer=_serialize,
                job_deserializer=_deserialize,
            )
            try:
                await pool.enqueue_job(
                    "run_scan_job", job_id, _job_id=f"recon-{job_id}"
                )
            finally:
                await pool.aclose()

        try:
            _run_sync(push)
        except Exception as exc:
            message = f"Redis dispatch failed ({type(exc).__name__})"
            self._local.dispatch_failed(job_id, message)
            raise RuntimeError(message) from exc

    def lease(self) -> Optional[dict]:
        return self._local.lease()

    def complete(self, job_id: int, run_id: int | None = None) -> None:
        self._local.complete(job_id, run_id)

    def fail(self, job_id: int, error: str) -> None:
        self._local.fail(job_id, error)

    def status(self, job_id: int) -> Optional[str]:
        return self._local.status(job_id)

    def request_cancel(self, job_id: int) -> Optional[str]:
        return self._local.request_cancel(job_id)

    def cancellation_requested(self, job_id: int) -> bool:
        return self._local.cancellation_requested(job_id)

    def mark_cancelled(self, job_id: int) -> None:
        self._local.mark_cancelled(job_id)

    def retry(self, job_id: int) -> Optional[str]:
        previous = self._local.status(job_id)
        status = self._local.retry(job_id)
        if status == "queued" and previous not in {"queued", "leased", "cancel_requested"}:
            self._dispatch(job_id)
        return status

    def release(self, job_id: int) -> None:
        self._local.release(job_id)


async def run_scan_job(_ctx: dict, durable_job_id: int) -> dict:
    """ARQ entrypoint: claim, execute, and update the durable SQL job row."""
    from ..engine import ScanCancelled
    from .worker import process

    queue = LocalQueue()
    job = await asyncio.to_thread(queue.claim, durable_job_id)
    if job is None:
        status = await asyncio.to_thread(queue.status, durable_job_id)
        if status == "done":
            return {"job_id": durable_job_id, "status": "already_done"}
        raise RuntimeError(f"durable job {durable_job_id} is not claimable ({status})")
    try:
        run_id = await process(job, queue)
    except ScanCancelled:
        await asyncio.to_thread(queue.mark_cancelled, durable_job_id)
        return {"job_id": durable_job_id, "status": "cancelled"}
    except Exception as exc:
        await asyncio.to_thread(queue.fail, durable_job_id, redact(str(exc)))
        raise
    await asyncio.to_thread(queue.complete, durable_job_id, run_id)
    return {"job_id": durable_job_id, "status": "done"}


class WorkerSettings:
    functions = [run_scan_job]
    redis_settings = _redis_settings()
    job_serializer = _serialize
    job_deserializer = _deserialize
    max_tries = SETTINGS.job_max_attempts
