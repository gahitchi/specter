"""Worker loop: lease durable jobs and run them end-to-end.

Run one or many of these (locally or on separate machines pointed at a shared
Postgres/Redis) to scale throughput. Jobs are durable, so a crashed worker
loses nothing — the job is retried.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from ..models import Query
from ..orchestrator import scan
from ..engine import ScanCancelled
from .base import JobQueue, get_queue

logger = logging.getLogger(__name__)


async def process(
    job: dict,
    queue: JobQueue | None = None,
    scan_fn: Callable[..., Coroutine[Any, Any, dict]] | None = None,
) -> int | None:
    if job["kind"] == "scan":
        from .activity import DurableActivityWriter

        p = job["payload"]
        activity = DurableActivityWriter(job["id"])
        await activity.start()
        try:
            async def cancellation_requested() -> bool:
                return bool(
                    queue
                    and await asyncio.to_thread(
                        queue.cancellation_requested, job["id"]
                    )
                )

            result = await (scan_fn or scan)(
                Query(**p.get("query", {})),
                label=p.get("label"),
                watchlist=p.get("watchlist", False),
                owner_id=job.get("owner_id"),
                activity_callback=activity.record,
                intake=p.get("intake"),
                cancellation_requested=cancellation_requested,
            )
        finally:
            try:
                await activity.close()
            except Exception:
                logger.exception("failed to flush activity for job %s", job["id"])
        return result["run_id"]
    else:
        raise ValueError(f"unknown job kind: {job['kind']}")


async def run_worker(queue: JobQueue | None = None, poll_interval: float = 1.0,
                     once: bool = False, max_jobs: int | None = None) -> int:
    queue = queue or get_queue()
    done = 0
    while True:
        job = await asyncio.to_thread(queue.lease)
        if job is None:
            if once:
                break
            await asyncio.sleep(poll_interval)
            continue
        try:
            run_id = await process(job, queue)
            await asyncio.to_thread(queue.complete, job["id"], run_id)
        except ScanCancelled:
            await asyncio.to_thread(queue.mark_cancelled, job["id"])
        except Exception as e:  # noqa: BLE001
            from ..keys import redact

            await asyncio.to_thread(queue.fail, job["id"], redact(str(e)))
        done += 1
        if max_jobs and done >= max_jobs:
            break
    return done


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
