"""Shared context and sanitizers for the live investigation activity stream."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

Activity = dict[str, Any]
ActivityCallback = Callable[[Activity], Awaitable[None]]

# Each concurrently running module receives an isolated context value. Outbound
# requests can therefore attach themselves to the process that caused them.
ACTIVE_PROCESS_ID: ContextVar[str | None] = ContextVar(
    "recon_active_process_id", default=None
)

_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api-key",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "credential",
    "key",
    "oauth_code",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
    "x-api-key",
}


def artifact_activity_id(key: str) -> str:
    """Return the graph identifier used for an artifact."""
    return f"artifact:{key}"


def safe_display_url(
    url: str,
    params: Mapping[str, Any] | None = None,
    *,
    max_length: int = 900,
) -> str:
    """Build a display-only URL with credential-like query values redacted."""
    try:
        display_url = httpx.URL(url)
        if params:
            display_url = display_url.copy_merge_params(params)
        parts = urlsplit(str(display_url))
    except (TypeError, ValueError):
        return ""

    query = urlencode(
        [
            (key, "<redacted>" if key.casefold() in _SENSITIVE_QUERY_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    sanitized = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    if len(sanitized) <= max_length:
        return sanitized
    return sanitized[: max_length - 3] + "..."
