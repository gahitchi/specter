"""Breach-exposure module: EMAIL -> BREACH records.

Keyless via XposedOrNot (no API key). If an `hibp` key is present in the vault,
HaveIBeenPwned is additionally queried for richer coverage — keyless-first, with
the commercial source as an optional enhancement. Reports honestly: a rate-limit
or API error becomes UNVERIFIABLE, never a false 'clean'."""

from __future__ import annotations

import json
from urllib.parse import quote

from ..graph_models import Artifact, ArtifactType
from ..keys import VAULT
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _xposedornot(ctx: ModuleContext, email: str) -> tuple[list[str], str | None]:
    """Returns (breach_names, error). error is set when existence couldn't be told."""
    resp = await ctx.client.fetch(
        f"https://api.xposedornot.com/v1/check-email/{quote(email)}")
    if resp.status_code == 404:
        return [], None  # definitively not found
    if resp.status_code != 200:
        return [], f"status {resp.status_code}"
    try:
        d = json.loads(resp.text)
    except json.JSONDecodeError:
        return [], "bad response"
    nested = d.get("breaches") or []
    names = nested[0] if nested and isinstance(nested[0], list) else []
    return [str(n) for n in names], None


async def _hibp(ctx: ModuleContext, email: str, key: str) -> list[str]:
    resp = await ctx.client.fetch(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=true",
        headers={"hibp-api-key": key, "User-Agent": ctx.settings.user_agent})
    if resp.status_code != 200:
        return []
    try:
        return [b.get("Name", "") for b in resp.json()]
    except Exception:  # noqa: BLE001
        return []


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    email = art.normalized
    names, error = await _xposedornot(ctx, email)

    hibp_key = VAULT.get("hibp")
    if hibp_key:
        names = sorted(set(names) | set(n for n in await _hibp(ctx, email, hibp_key) if n))

    if error and not names:
        await ctx.emit_finding(Finding(
            source="breach:check", category="email", label=f"Breaches {email}",
            url=None, verdict=Verdict.UNVERIFIABLE,
            reasons=[f"breach lookup inconclusive ({error})"]))
        return

    await ctx.emit_finding(Finding(
        source="breach:check", category="email", label=f"Breaches {email}", url=None,
        verdict=Verdict.FOUND if names else Verdict.NOT_FOUND,
        confidence=0.75 if names else 0.0,
        reasons=[f"exposed in {len(names)} breach(es): {', '.join(names[:5])}"
                 if names else "no known breaches"],
        signals={"email": email} if names else {},
        data={"breaches": names},
    ))
    for name in names:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.BREACH, name, parent=art, source_module="breach", email=email))


MODULE = Module(
    name="breach",
    consumes={ArtifactType.EMAIL},
    produces={ArtifactType.BREACH},
    run=_run,
    reliability_prior=0.75,
)
