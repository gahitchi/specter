"""Batched persistence for graph activity emitted by durable scan workers."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from ..store import get_db, repo


class DurableActivityWriter:
    def __init__(
        self,
        job_id: int,
        *,
        batch_size: int = 20,
        flush_interval: float = 0.2,
    ) -> None:
        self.job_id = job_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._pending: list[dict] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None

    async def start(self) -> None:
        def clear() -> None:
            with get_db().session() as session:
                repo.clear_job_activity(session, self.job_id)

        await asyncio.to_thread(clear)

    async def record(self, activity: dict) -> None:
        async with self._lock:
            self._pending.append(dict(activity))
            should_flush = len(self._pending) >= self.batch_size
            if not should_flush and self._flush_task is None:
                self._flush_task = asyncio.create_task(self._flush_after_delay())
        if should_flush:
            await self.flush()

    async def _flush_after_delay(self) -> None:
        try:
            await asyncio.sleep(self.flush_interval)
            self._flush_task = None
            await self.flush()
        except asyncio.CancelledError:
            raise

    async def flush(self) -> None:
        current = asyncio.current_task()
        timer = self._flush_task
        if timer is not None and timer is not current:
            self._flush_task = None
            timer.cancel()
            with suppress(asyncio.CancelledError):
                await timer
        async with self._lock:
            batch, self._pending = self._pending, []
        if not batch:
            return

        def save() -> None:
            with get_db().session() as session:
                repo.upsert_job_activity(session, self.job_id, batch)

        await asyncio.to_thread(save)

    async def close(self) -> None:
        await self.flush()
