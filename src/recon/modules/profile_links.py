"""PROFILE-LINKS module: ACCOUNT_PROFILE -> EMAIL / LINK / USERNAME.

When a username scan confirms a profile, fetch that public page and harvest
contact emails, outbound links, and cross-linked handles on other platforms.
This is the social-graph pivot — but it is the noisiest source here, so its
reliability prior is deliberately low (it must never outvote DNS/Cymru facts),
and discovered handles only *expand* when the scope policy says they belong to
the target. Scope is also checked up front to avoid fetching out-of-scope pages."""

from __future__ import annotations

import re

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
# host -> capture group for the handle in the first path segment
_SOCIAL = {
    "github.com": r"github\.com/([A-Za-z0-9\-]+)",
    "gitlab.com": r"gitlab\.com/([A-Za-z0-9\-_.]+)",
    "twitter.com": r"twitter\.com/([A-Za-z0-9_]+)",
    "x.com": r"x\.com/([A-Za-z0-9_]+)",
    "instagram.com": r"instagram\.com/([A-Za-z0-9_.]+)",
    "keybase.io": r"keybase\.io/([A-Za-z0-9_]+)",
    "mastodon.social": r"mastodon\.social/@([A-Za-z0-9_]+)",
}


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    try:
        resp = await ctx.client.fetch(art.value)
    except Exception as e:  # noqa: BLE001
        await ctx.emit_finding(Finding(
            source="profile:enrich", category="profile", label="Profile enrich",
            url=art.value, verdict=Verdict.ERROR, reasons=[f"fetch failed: {e}"]))
        return
    if resp.status_code != 200:
        return
    body = resp.text[: ctx.settings.max_body_bytes]

    emails = sorted({e.lower() for e in _EMAIL_RE.findall(body)})[:10]
    hrefs = _HREF_RE.findall(body)
    handles: dict[str, str] = {}
    for href in hrefs:
        for host, pat in _SOCIAL.items():
            mobj = re.search(pat, href, re.IGNORECASE)
            if mobj:
                handles.setdefault(mobj.group(1).lower(), host)

    await ctx.emit_finding(Finding(
        source="profile:enrich", category="profile",
        label=f"Profile enrich: {art.data.get('site', art.value)}",
        url=art.value, verdict=Verdict.FOUND if (emails or handles) else Verdict.NOT_FOUND,
        confidence=0.4 if (emails or handles) else 0.0,
        reasons=[f"{len(emails)} email(s), {len(handles)} cross-linked handle(s)"],
        data={"emails": emails, "handles": handles},
    ))

    for em in emails:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.EMAIL, em, parent=art, source_module="profile_links"))
    for handle in handles:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.USERNAME, handle, parent=art, source_module="profile_links"))
    # External links: recorded for the graph (capped), not expanded.
    external = [h for h in hrefs if h.startswith("http")][:25]
    for href in external:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.LINK, href, parent=art, source_module="profile_links"))


MODULE = Module(
    name="profile_links",
    consumes={ArtifactType.ACCOUNT_PROFILE},
    produces={ArtifactType.EMAIL, ArtifactType.USERNAME, ArtifactType.LINK},
    run=_run,
    reliability_prior=0.40,
)
