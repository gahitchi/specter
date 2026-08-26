"""Candidate-email pivot (keyless): USERNAME / NAME + a seed DOMAIN -> candidate
email addresses, each tested against a *deterministic* existence signal (Gravatar)
before it is retained as a candidate.

This is the classic "is jane.doe@acme.com a thing?" pivot, but kept honest: we
generate candidates from common local-part patterns, then only emit a FOUND
EMAIL artifact (which the engine will pivot on) when Gravatar confirms an avatar
exists for that exact address. Candidates with no Gravatar are reported once as a
single UNCERTAIN lead and are NOT fed back into the frontier. Even a Gravatar hit
only proves that the generated address has an avatar; it does not prove that the
address belongs to the researched subject, so it cannot pivot automatically.

Domains come from the seed query (the investigation's own domain / email domain),
so a username-only scan with no domain context produces nothing.
"""

from __future__ import annotations

from .. import normalize
from ..collectors.email import gravatar_hash
from ..evidence import EvidencePolicy
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

# Hard cap on candidates per artifact — politeness + budget hygiene.
_MAX_CANDIDATES = 12


def _seed_domains(ctx: ModuleContext) -> list[str]:
    domains: set[str] = set()
    if ctx.query.domain:
        d = normalize.norm_domain(ctx.query.domain)
        if d:
            domains.add(d)
    if ctx.query.email and "@" in ctx.query.email:
        d = normalize.norm_domain(ctx.query.email.rsplit("@", 1)[-1])
        if d:
            domains.add(d)
    return sorted(domains)


def _clean_local(s: str) -> str:
    """Lowercase, keep alnum + dot, collapse repeats — a plausible local-part."""
    out = "".join(c for c in s.lower() if c.isalnum() or c == ".")
    while ".." in out:
        out = out.replace("..", ".")
    return out.strip(".")


def _locals_for(art: Artifact) -> list[str]:
    if art.type == ArtifactType.USERNAME:
        h = _clean_local(art.normalized)
        return [h] if h else []
    # NAME -> common corporate/personal local-part patterns.
    tokens = [t for t in art.normalized.replace(".", " ").split() if t]
    if not tokens:
        return []
    if len(tokens) == 1:
        return [_clean_local(tokens[0])]
    first, last = tokens[0], tokens[-1]
    raw = [
        f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}",
        f"{first}.{last[0]}", f"{first}_{last}", first, last,
        f"{last}.{first}", f"{last}{first[0]}",
    ]
    seen: list[str] = []
    for cand in raw:
        c = _clean_local(cand)
        if c and c not in seen:
            seen.append(c)
    return seen


async def _gravatar_exists(email: str, ctx: ModuleContext) -> bool:
    url = f"https://www.gravatar.com/avatar/{gravatar_hash(email)}?d=404"
    try:
        resp = await ctx.client.fetch(url)
    except Exception:
        return False
    return resp.status_code == 200


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    domains = _seed_domains(ctx)
    if not domains:
        return  # no domain context -> nothing to permute against

    candidates: list[str] = []
    for local in _locals_for(art):
        for domain in domains:
            candidates.append(f"{local}@{domain}")
            if len(candidates) >= _MAX_CANDIDATES:
                break
        if len(candidates) >= _MAX_CANDIDATES:
            break

    unverified: list[str] = []
    for email in candidates:
        if await _gravatar_exists(email, ctx):
            await ctx.emit_finding(Finding(
                source="permute:email", category="email", label=email,
                url=f"https://gravatar.com/{gravatar_hash(email)}",
                verdict=Verdict.FOUND, confidence=0.85,
                reasons=[f"Gravatar confirms '{email}' (candidate from {art.type.value} "
                         f"'{art.normalized}' + seed domain)"],
                signals={"email": email, "gravatar_hash": gravatar_hash(email)},
                data={"phase": "verified"},
                policy=EvidencePolicy.candidate(),
            ))
            # Retain the exact address as a graph lead without researching it.
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.EMAIL, email, parent=art, source_module="permute",
                confidence=0.85,
                policy=EvidencePolicy.candidate(),
            ))
        else:
            unverified.append(email)

    # Surface the speculative candidates once, honestly, without recursing.
    if unverified:
        await ctx.emit_finding(Finding(
            source="permute:email", category="email", label="Unverified candidates",
            url=None, verdict=Verdict.UNCERTAIN, confidence=0.2,
            reasons=[f"generated but NOT Gravatar-confirmed: {', '.join(unverified)}"],
            data={"phase": "discovery", "candidates": unverified},
        ))


MODULE = Module(
    name="permute",
    consumes={ArtifactType.USERNAME, ArtifactType.NAME},
    produces={ArtifactType.EMAIL},
    run=_run,
    reliability_prior=0.6,
    expansion=True,
    evidence_policy=EvidencePolicy.candidate(),
)
