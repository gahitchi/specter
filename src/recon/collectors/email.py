"""Email collector: deterministic existence signals only (no guessing).

- Gravatar: an MD5 of the email either resolves to an avatar/profile or 404s.
  This is a strong, low-FP identity signal (the hash also feeds clustering).
- MX lookup: tells us the domain can receive mail (deliverability context).
We never claim an inbox "exists" from SMTP probing (unreliable + intrusive).
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Awaitable, Callable

import dns.resolver

from ..evidence import EvidencePolicy
from ..http_client import RateLimitedClient, RequestBudgetExceeded
from ..keys import redact
from ..models import Finding, Query, Verdict

EmitFn = Callable[[Finding], Awaitable[None]]


def gravatar_hash(email: str) -> str:
    # Gravatar's public protocol requires MD5; this is an identifier, not a
    # cryptographic integrity primitive.
    return hashlib.md5(
        email.strip().lower().encode("utf-8"), usedforsecurity=False
    ).hexdigest()


async def _mx(domain: str) -> tuple[list[str], str | None]:
    def lookup() -> tuple[list[str], str | None]:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            exchanges = sorted(
                value
                for record in answers
                if (value := str(record.exchange).rstrip("."))
            )
            return exchanges, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], None
        except Exception as exc:
            return [], type(exc).__name__

    return await asyncio.to_thread(lookup)


async def collect(query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
    email = query.email
    if not email or "@" not in email:
        return
    local, _, domain = email.partition("@")
    h = gravatar_hash(email)

    # --- Gravatar existence (d=404 => 404 when no avatar set) ---
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        resp = await client.fetch(url)
        if resp.status_code == 200:
            await emit(Finding(
                source="email:gravatar", category="email", label="Gravatar",
                url=f"https://gravatar.com/{h}", verdict=Verdict.FOUND, confidence=0.9,
                reasons=["gravatar avatar exists for this email (200)"],
                signals={"gravatar_hash": h, "email": email},
                policy=EvidencePolicy.corroborated(),
            ))
        elif resp.status_code == 404:
            await emit(Finding(
                source="email:gravatar", category="email", label="Gravatar",
                url=None, verdict=Verdict.NOT_FOUND, confidence=0.0,
                reasons=["Gravatar returned its explicit no-avatar status (404)."],
            ))
        else:
            await emit(Finding(
                source="email:gravatar", category="email", label="Gravatar",
                url=None, verdict=Verdict.UNVERIFIABLE, confidence=0.0,
                reasons=[
                    f"Gravatar returned HTTP {resp.status_code}; avatar presence was not determinable."
                ],
            ))
    except RequestBudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        await emit(Finding(
            source="email:gravatar", category="email", label="Gravatar",
            url=None, verdict=Verdict.ERROR,
            reasons=[f"request failed: {redact(str(e))}"],
        ))

    # --- MX / deliverability context ---
    mx, mx_error = await _mx(domain)
    mx_verdict = (
        Verdict.UNVERIFIABLE
        if mx_error
        else Verdict.FOUND
        if mx
        else Verdict.NOT_FOUND
    )
    await emit(Finding(
        source="email:mx", category="email", label=f"MX for {domain}",
        url=None,
        verdict=mx_verdict,
        confidence=0.6 if mx else 0.0,
        reasons=[
            f"{len(mx)} MX record(s) exist for the domain; this does not verify the mailbox."
            if mx
            else f"MX lookup was inconclusive ({mx_error}); no mailbox conclusion was made."
            if mx_error
            else "The domain has no MX record; this does not prove whether the mailbox existed historically."
        ],
        data={"mx": mx, "local_part": local, "domain": domain, "lookup_error": mx_error},
        policy=EvidencePolicy(confirmation_allowed=False, pivot_allowed=False),
    ))

    # --- Pivot suggestion: local-part as a username to fan out on ---
    await emit(Finding(
        source="email:pivot", category="email", label="Username pivot",
        url=None, verdict=Verdict.UNCERTAIN, confidence=0.4,
        reasons=[f"local-part '{local}' is a candidate username (re-run with --username {local})"],
        data={"candidate_username": local},
        policy=EvidencePolicy.candidate(),
    ))
