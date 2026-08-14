"""GitHub module: USERNAME -> profile enrichment + the strong handle->email pivot.

Public GitHub API, keyless (60 req/hr). If a `github` token is present in the key
vault it is used to lift the limit to 5000/hr — keyless-*first*, not key-required.
The high-value pivot is harvesting commit-author emails from a user's public
events, which links a handle to real email addresses for correlation."""

from __future__ import annotations

import json

from ..graph_models import Artifact, ArtifactType
from ..keys import VAULT
from ..models import Finding, Verdict
from ..normalize import norm_domain
from .base import Module, ModuleContext

_API = "https://api.github.com"
_MAX_EMAILS = 10


def _headers(ctx: ModuleContext) -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": ctx.settings.user_agent}
    token = VAULT.get("github")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _get(ctx: ModuleContext, path: str):
    return await ctx.client.fetch(f"{_API}{path}", headers=_headers(ctx))


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    user = art.normalized
    resp = await _get(ctx, f"/users/{user}")
    if resp.status_code == 404:
        await ctx.emit_finding(Finding(
            source="github:user", category="username", label=f"GitHub {user}",
            url=None, verdict=Verdict.NOT_FOUND, reasons=["no such GitHub user"]))
        return
    if resp.status_code != 200:
        await ctx.emit_finding(Finding(
            source="github:user", category="username", label=f"GitHub {user}",
            url=None, verdict=Verdict.UNVERIFIABLE,
            reasons=[f"GitHub API status {resp.status_code} (rate-limited?)"]))
        return

    u = resp.json()
    profile = u.get("html_url")
    await ctx.emit_finding(Finding(
        source="github:user", category="username", label=f"GitHub: {u.get('login')}",
        url=profile, verdict=Verdict.FOUND, confidence=0.85,
        reasons=[f"{u.get('public_repos', 0)} repos, {u.get('followers', 0)} followers"
                 + (f", {u.get('name')}" if u.get("name") else "")],
        signals={"username:github": user, **({"email": u["email"]} if u.get("email") else {})},
        data={k: u.get(k) for k in ("name", "company", "blog", "location", "bio",
                                    "twitter_username", "created_at")},
    ))
    if profile:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.ACCOUNT_PROFILE, profile, parent=art, source_module="github"))
    if u.get("email"):
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.EMAIL, u["email"], parent=art, source_module="github"))
    blog = (u.get("blog") or "").strip()
    if blog:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.LINK, blog, parent=art, source_module="github"))
        dom = norm_domain(blog)
        if dom:
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.DOMAIN, dom, parent=art, source_module="github"))

    # --- Commit-author email harvest (handle -> email pivot) ---
    ev = await _get(ctx, f"/users/{user}/events/public")
    if ev.status_code != 200:
        return
    try:
        events = json.loads(ev.text)
    except json.JSONDecodeError:
        return
    emails: set[str] = set()
    for event in events:
        for commit in (event.get("payload", {}) or {}).get("commits", []) or []:
            email = (commit.get("author") or {}).get("email", "")
            if email and "noreply.github.com" not in email:
                emails.add(email.lower())
    emails = sorted(emails)[:_MAX_EMAILS]
    if emails:
        await ctx.emit_finding(Finding(
            source="github:commits", category="email",
            label=f"Commit emails for {user}", url=None,
            verdict=Verdict.FOUND, confidence=0.7,
            reasons=[f"{len(emails)} email(s) from public commit metadata"],
            data={"emails": sorted(emails)},
        ))
        for email in emails:
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.EMAIL, email, parent=art, source_module="github"))


MODULE = Module(
    name="github",
    consumes={ArtifactType.USERNAME},
    produces={ArtifactType.ACCOUNT_PROFILE, ArtifactType.EMAIL,
              ArtifactType.LINK, ArtifactType.DOMAIN},
    run=_run,
    reliability_prior=0.70,
)
