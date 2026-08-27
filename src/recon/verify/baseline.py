"""Layer 0: control-probe baseline.

For each host we request a *known-absent* random account and remember how the
site answers "no such user": status, final URL, body length, fingerprint.
Later we diff the real response against this — the single most effective way to
kill soft-404 false positives, because it adapts to each site automatically.
"""

from __future__ import annotations

import secrets
import string
import hashlib
from typing import Optional

from ..config import SETTINGS, Settings
from ..http_client import RateLimitedClient
from ..models import Evidence, SiteRule
from . import defenses, similarity


def random_absent_account(
    length: int | None = None,
    key: str | None = None,
    settings: Settings | None = None,
) -> str:
    """A username extremely unlikely to belong to anyone (for baseline probing).

    Deterministic mode derives it from probe_seed + `key` so baselines — and
    therefore verdicts — are reproducible across runs (#8). Otherwise it is
    cryptographically random.
    """
    settings = settings or SETTINGS
    n = length or settings.control_probe_len
    alphabet = string.ascii_lowercase + string.digits
    if settings.deterministic:
        import hashlib

        seed = f"{settings.probe_seed}:{key or ''}".encode()
        digest = hashlib.shake_256(seed).hexdigest(n)[:n]
        return "zz" + digest
    return "zz" + "".join(secrets.choice(alphabet) for _ in range(n))


async def evidence_from_response(
    url: str,
    resp,
    elapsed_ms: int = 0,
    query_term: Optional[str] = None,
    settings: Settings | None = None,
) -> Evidence:
    settings = settings or SETTINGS
    body = resp.text[: settings.max_body_bytes]
    title = similarity.extract_title(body)
    contains = bool(query_term) and query_term.lower() in body.lower()
    blocked = defenses.detect(resp.status_code, resp.headers, body)
    return Evidence(
        url=url,
        status=resp.status_code,
        final_url=str(resp.url),
        body_len=len(body),
        content_sha256=hashlib.sha256(
            resp.content[: settings.max_body_bytes]
        ).hexdigest(),
        fingerprint=similarity.fingerprint_hex(body),
        title=title,
        contains_query=contains,
        elapsed_ms=elapsed_ms,
        blocked=blocked,
    )


class BaselineCache:
    """Per-(host) cache of absent-account evidence, computed at most once."""

    def __init__(self, client: RateLimitedClient) -> None:
        self._client = client
        self._cache: dict[str, Optional[Evidence]] = {}

    async def get(self, rule: SiteRule) -> Optional[Evidence]:
        key = rule.name
        if key in self._cache:
            return self._cache[key]
        probe = random_absent_account(key=rule.name, settings=self._client.s)
        url = rule.url_for(probe)
        try:
            resp = await self._client.fetch(url)
            ev = await evidence_from_response(
                url, resp, query_term=probe, settings=self._client.s
            )
        except Exception as e:  # noqa: BLE001 - baseline is best-effort
            ev = Evidence(
                url=url, status=0, final_url=url, body_len=0,
                fingerprint="", error=str(e),
            )
        self._cache[key] = ev
        return ev
