"""Domain collector: DNS records, RDAP registration data, and subdomains via
certificate transparency (crt.sh). All sources are authoritative/structured,
so false positives are inherently low — a record either exists or it doesn't.
"""

from __future__ import annotations

import asyncio
import json
from typing import Awaitable, Callable

import dns.resolver

from ..http_client import RateLimitedClient, RequestBudgetExceeded
from ..keys import redact
from ..models import Finding, Query, Verdict

EmitFn = Callable[[Finding], Awaitable[None]]


async def _records(domain: str, rtype: str) -> list[str]:
    def lookup() -> list[str]:
        try:
            return sorted(str(r).rstrip(".") for r in dns.resolver.resolve(domain, rtype))
        except Exception:
            return []

    return await asyncio.to_thread(lookup)


async def collect(query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
    domain = query.domain
    if not domain:
        return

    # --- DNS records ---
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        records[rtype] = await _records(domain, rtype)
    resolvable = any(records[t] for t in ("A", "AAAA", "NS"))
    await emit(Finding(
        source="domain:dns", category="domain", label=f"DNS {domain}",
        url=f"https://{domain}",
        verdict=Verdict.FOUND if resolvable else Verdict.NOT_FOUND,
        confidence=0.9 if resolvable else 0.0,
        reasons=["domain resolves" if resolvable else "no A/AAAA/NS records (does not resolve)"],
        signals={"domain": domain} if resolvable else {},
        data=records,
    ))
    if not resolvable:
        return

    # --- RDAP registration ---
    try:
        resp = await client.fetch(f"https://rdap.org/domain/{domain}")
        if resp.status_code == 200:
            d = resp.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
            registrar = next(
                (e.get("vcardArray", [None, []])[1] for e in d.get("entities", [])
                 if "registrar" in e.get("roles", [])),
                None,
            )
            await emit(Finding(
                source="domain:rdap", category="domain", label="RDAP registration",
                url=None, verdict=Verdict.FOUND, confidence=0.9,
                reasons=["RDAP record found"],
                data={
                    "registered": events.get("registration"),
                    "expires": events.get("expiration"),
                    "last_changed": events.get("last changed"),
                    "registrar_vcard": registrar,
                    "status": d.get("status"),
                },
            ))
        else:
            await emit(Finding(
                source="domain:rdap", category="domain", label="RDAP registration",
                verdict=Verdict.NOT_FOUND, reasons=[f"no RDAP record (status {resp.status_code})"],
            ))
    except RequestBudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        await emit(Finding(
            source="domain:rdap", category="domain", label="RDAP registration",
            verdict=Verdict.ERROR, reasons=[f"RDAP lookup failed: {redact(str(e))}"],
        ))

    # --- Subdomains via certificate transparency (crt.sh) ---
    try:
        resp = await client.fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
        subs: set[str] = set()
        if resp.status_code == 200 and resp.text.strip():
            try:
                for row in json.loads(resp.text):
                    for name in str(row.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            subs.add(name)
            except json.JSONDecodeError:
                pass
        subs.discard(domain)
        await emit(Finding(
            source="domain:crtsh", category="domain", label="Subdomains (crt.sh)",
            url=f"https://crt.sh/?q=%25.{domain}",
            verdict=Verdict.FOUND if subs else Verdict.NOT_FOUND,
            confidence=0.8 if subs else 0.0,
            reasons=[f"{len(subs)} subdomain(s) in CT logs" if subs else "no CT subdomains found"],
            data={"subdomains": sorted(subs)[:200]},
        ))
    except RequestBudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        await emit(Finding(
            source="domain:crtsh", category="domain", label="Subdomains (crt.sh)",
            verdict=Verdict.ERROR, reasons=[f"crt.sh lookup failed: {redact(str(e))}"],
        ))
