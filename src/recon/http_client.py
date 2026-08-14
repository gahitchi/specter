"""Shared asynchronous HTTP client with enforceable traffic limits.

Every collector and module uses :meth:`RateLimitedClient.fetch`, so the user
agent, robots policy, per-host delay, redirect handling, body cap, and request
budget apply to every outbound request from the scan engine.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
import urllib.robotparser as robotparser
from collections.abc import Mapping
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from .activity import ACTIVE_PROCESS_ID, ActivityCallback, safe_display_url
from .config import SETTINGS, Settings
from .keys import redact

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


class RequestBudgetExceeded(RuntimeError):
    """Raised before an outbound request would exceed the configured ceiling."""


class RateLimitedClient:
    def __init__(
        self,
        settings: Settings = SETTINGS,
        limiter=None,
        activity_callback: ActivityCallback | None = None,
    ) -> None:
        self.s = settings
        self._client: Optional[httpx.AsyncClient] = None
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._host_last: dict[str, float] = {}
        self._robots: dict[str, Optional[robotparser.RobotFileParser]] = {}
        self._robots_locks: dict[str, asyncio.Lock] = {}
        self._budget_lock = asyncio.Lock()
        self._limiter = limiter
        self._activity_callback = activity_callback
        self.request_count = 0
        self.budget_exhausted = False

    async def __aenter__(self) -> "RateLimitedClient":
        self._client = httpx.AsyncClient(
            http2=True,
            follow_redirects=False,
            timeout=self.s.request_timeout,
            headers={"User-Agent": self.s.user_agent},
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        close_limiter = getattr(self._limiter, "aclose", None)
        if close_limiter is not None:
            await close_limiter()

    def _active_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("RateLimitedClient must be used as an async context manager")
        return self._client

    @staticmethod
    def _validated_url(url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError(f"only absolute HTTP(S) URLs are allowed: {url!r}")
        if parts.username is not None or parts.password is not None:
            raise ValueError("credentials embedded in URLs are not allowed")
        host = parts.hostname.rstrip(".").casefold()
        if host == "localhost" or host.endswith((".localhost", ".local")):
            raise ValueError("local network hosts are not allowed")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("non-public IP address URLs are not allowed")
        return url

    def _host_lock(self, host: str) -> asyncio.Lock:
        if host not in self._host_locks:
            self._host_locks[host] = asyncio.Lock()
        return self._host_locks[host]

    def _robots_lock(self, origin: str) -> asyncio.Lock:
        if origin not in self._robots_locks:
            self._robots_locks[origin] = asyncio.Lock()
        return self._robots_locks[origin]

    async def _reserve_request(self) -> int:
        async with self._budget_lock:
            if self.request_count >= self.s.max_requests:
                self.budget_exhausted = True
                raise RequestBudgetExceeded(
                    f"outbound request budget exhausted ({self.s.max_requests})"
                )
            self.request_count += 1
            return self.request_count

    async def _emit_activity(self, activity: dict[str, Any]) -> None:
        """Activity reporting must never be able to break collection."""
        if self._activity_callback is None:
            return
        try:
            await self._activity_callback(activity)
        except Exception:  # noqa: BLE001 - telemetry is deliberately best effort
            return

    @staticmethod
    def _request_outcome(status_code: int) -> str:
        if 200 <= status_code < 400:
            return "success"
        if status_code in {401, 403, 407, 409, 423, 425, 429}:
            return "uncertain"
        if status_code in {404, 410}:
            return "not_found"
        return "error"

    async def _request_once(
        self,
        url: str,
        method: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        client = self._active_client()
        host = urlsplit(url).netloc.lower()

        async with self._sem:
            async with self._host_lock(host):
                wait = self.s.per_host_min_interval - (
                    time.monotonic() - self._host_last.get(host, 0.0)
                )
                if wait > 0:
                    await asyncio.sleep(wait)
                self._host_last[host] = time.monotonic()

            if self._limiter is not None:
                await self._limiter.acquire(host)
            request_index = await self._reserve_request()
            request_id = f"request:{request_index}"
            display_url = safe_display_url(url, params)
            started_at = time.monotonic()
            base_activity = {
                "kind": "request",
                "id": request_id,
                "parent_id": ACTIVE_PROCESS_ID.get(),
                "method": method,
                "host": urlsplit(url).hostname or host,
                "url": display_url,
                "request_index": request_index,
            }
            await self._emit_activity(
                {**base_activity, "phase": "started", "status": "running"}
            )

            try:
                async with client.stream(
                    method, url, headers=headers, params=params
                ) as response:
                    body = bytearray()
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        remaining = self.s.max_body_bytes - len(body)
                        if remaining <= 0:
                            truncated = True
                            break
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break

                    response_headers = response.headers.copy()
                    response_headers.pop("content-encoding", None)
                    response_headers.pop("content-length", None)
                    if truncated:
                        response_headers["x-recon-body-truncated"] = "1"
                    result = httpx.Response(
                        response.status_code,
                        headers=response_headers,
                        content=bytes(body),
                        request=response.request,
                        extensions=response.extensions,
                    )
            except Exception as exc:
                await self._emit_activity(
                    {
                        **base_activity,
                        "phase": "failed",
                        "status": "finished",
                        "outcome": "error",
                        "elapsed_ms": round((time.monotonic() - started_at) * 1000),
                        "error": redact(str(exc))[:300],
                    }
                )
                raise

            await self._emit_activity(
                {
                    **base_activity,
                    "phase": "finished",
                    "status": "finished",
                    "outcome": self._request_outcome(result.status_code),
                    "status_code": result.status_code,
                    "url": safe_display_url(str(result.request.url)),
                    "elapsed_ms": round((time.monotonic() - started_at) * 1000),
                    "truncated": truncated,
                }
            )
            return result

    async def _request_with_redirects(
        self,
        url: str,
        method: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        check_robots: bool,
    ) -> httpx.Response:
        current = self._validated_url(url)
        history: list[httpx.Response] = []
        redirect_headers = headers

        for redirect_count in range(self.s.max_redirects + 1):
            if check_robots and not await self._allowed_by_robots(current):
                raise PermissionError(f"blocked by robots.txt: {current}")

            response = await self._request_once(
                current,
                method,
                headers=redirect_headers,
                params=params if not history else None,
            )
            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_STATUSES or not location:
                response.history = history
                return response
            if redirect_count >= self.s.max_redirects:
                raise httpx.TooManyRedirects(
                    f"exceeded {self.s.max_redirects} redirects", request=response.request
                )

            history.append(response)
            next_url = self._validated_url(urljoin(str(response.url), location))
            current_parts = urlsplit(current)
            next_parts = urlsplit(next_url)
            current_origin = (current_parts.scheme.lower(), current_parts.netloc.lower())
            next_origin = (next_parts.scheme.lower(), next_parts.netloc.lower())
            if current_origin != next_origin:
                # Caller-supplied headers may contain API keys. Never forward
                # them to a different authority, even when the redirect is valid.
                redirect_headers = None
            current = next_url
            if response.status_code == 303 or (
                response.status_code in {301, 302} and method not in {"GET", "HEAD"}
            ):
                method = "GET"

        raise RuntimeError("unreachable redirect state")

    async def _allowed_by_robots(self, url: str) -> bool:
        if not self.s.respect_robots:
            return True
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"

        async with self._robots_lock(origin):
            if origin not in self._robots:
                rp: Optional[robotparser.RobotFileParser] = robotparser.RobotFileParser()
                try:
                    response = await self._request_with_redirects(
                        f"{origin}/robots.txt", "GET", check_robots=False
                    )
                    if response.status_code == 200:
                        rp.parse(response.text.splitlines())
                    else:
                        rp = None
                except RequestBudgetExceeded:
                    raise
                except (httpx.HTTPError, OSError, ValueError):
                    rp = None
                self._robots[origin] = rp

        rp = self._robots[origin]
        return True if rp is None else rp.can_fetch(self.s.user_agent, url)

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Fetch one URL under all traffic, safety, and body-size policies."""
        method = method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported HTTP method: {method}")
        self._active_client()
        return await self._request_with_redirects(
            url, method, headers=headers, params=params, check_robots=True
        )
