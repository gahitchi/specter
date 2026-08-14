"""Name collector: scholarly/identity databases that expose structured public
records (ORCID, OpenAlex). Structured APIs keep false positives low; we still
fuzzy-gate matches and mark weak ones UNCERTAIN rather than FOUND.
"""

from __future__ import annotations

from typing import Awaitable, Callable
from urllib.parse import quote

from ..http_client import RateLimitedClient, RequestBudgetExceeded
from ..keys import redact
from ..models import Finding, Query, Verdict

EmitFn = Callable[[Finding], Awaitable[None]]


def _tokens(s: str) -> set[str]:
    return {t for t in s.lower().replace(".", " ").split() if t}


def _name_overlap(query_name: str, candidate: str) -> float:
    a, b = _tokens(query_name), _tokens(candidate)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a)


async def collect(query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
    name = query.name
    if not name:
        return

    # --- ORCID expanded search ---
    try:
        url = f"https://pub.orcid.org/v3.0/expanded-search/?q={quote(name)}&rows=5"
        resp = await client.fetch(url, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            results = resp.json().get("expanded-result") or []
            for r in results[:5]:
                cand = f"{r.get('given-names', '')} {r.get('family-names', '')}".strip()
                overlap = _name_overlap(name, cand)
                if overlap < 0.5:
                    continue
                orcid = r.get("orcid-id")
                verdict = Verdict.FOUND if overlap >= 0.99 else Verdict.UNCERTAIN
                await emit(Finding(
                    source="name:orcid", category="name", label=f"ORCID: {cand}",
                    url=f"https://orcid.org/{orcid}" if orcid else None,
                    verdict=verdict, confidence=round(0.5 + 0.4 * overlap, 3),
                    reasons=[f"ORCID name match overlap {overlap:.2f}"],
                    signals={"orcid": orcid} if orcid and verdict == Verdict.FOUND else {},
                    data={"institutions": r.get("institution-name", [])},
                ))
    except RequestBudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        await emit(Finding(
            source="name:orcid", category="name", label="ORCID",
            verdict=Verdict.ERROR, reasons=[f"ORCID search failed: {redact(str(e))}"],
        ))

    # --- OpenAlex authors ---
    try:
        url = f"https://api.openalex.org/authors?search={quote(name)}&per-page=5"
        resp = await client.fetch(url)
        if resp.status_code == 200:
            for a in resp.json().get("results", [])[:5]:
                cand = a.get("display_name", "")
                overlap = _name_overlap(name, cand)
                if overlap < 0.5:
                    continue
                verdict = Verdict.FOUND if overlap >= 0.99 else Verdict.UNCERTAIN
                await emit(Finding(
                    source="name:openalex", category="name", label=f"OpenAlex: {cand}",
                    url=a.get("id"), verdict=verdict,
                    confidence=round(0.45 + 0.4 * overlap, 3),
                    reasons=[f"OpenAlex name match overlap {overlap:.2f}, "
                             f"{a.get('works_count', 0)} works"],
                    data={
                        "works_count": a.get("works_count"),
                        "orcid": a.get("orcid"),
                        "last_institution": (a.get("last_known_institution") or {}).get("display_name"),
                    },
                    signals={"orcid": (a.get("orcid") or "").rsplit("/", 1)[-1]}
                    if a.get("orcid") and verdict == Verdict.FOUND else {},
                ))
    except RequestBudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        await emit(Finding(
            source="name:openalex", category="name", label="OpenAlex",
            verdict=Verdict.ERROR, reasons=[f"OpenAlex search failed: {redact(str(e))}"],
        ))
