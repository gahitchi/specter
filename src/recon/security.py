"""Small ASGI and authentication abuse controls."""

from __future__ import annotations

import asyncio
import collections
import time

from starlette.responses import JSONResponse


class _BodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = self.max_bytes + 1
        if content_length > self.max_bytes:
            await JSONResponse(
                {"error": "request body is too large"}, status_code=413
            )(scope, receive, send)
            return

        consumed = 0

        async def limited_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await JSONResponse(
                {"error": "request body is too large"}, status_code=413
            )(scope, receive, send)


class LoginRateLimiter:
    def __init__(self, attempts: int, window_seconds: float = 60.0) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._entries: dict[str, collections.deque[float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        async with self._lock:
            entries = self._entries.setdefault(key, collections.deque())
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= self.attempts:
                return False
            entries.append(now)
            if len(self._entries) > 10_000:
                for name, rows in list(self._entries.items()):
                    while rows and rows[0] <= cutoff:
                        rows.popleft()
                    if not rows:
                        self._entries.pop(name, None)
            return True
