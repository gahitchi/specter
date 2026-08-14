"""Module registry: the catalogue the engine dispatches against.

Mirrors `connectors/registry.py`. Reliability priors reflect how trustworthy a
module's raw output is before runtime history adjusts it: deterministic/
authoritative sources (DNS resolution, Team Cymru ASN) rank high; scraped
sources (profile-link harvesting) rank low so they can't outvote hard evidence
during correlation."""

from __future__ import annotations

from ..graph_models import Artifact
from . import (
    abuseipdb,
    asn,
    breach,
    bluesky,
    commoncrawl,
    dns_intel,
    domain,
    email,
    github,
    gitlab,
    hackernews,
    ip_geo,
    name,
    permute,
    phone,
    profile_links,
    resolve,
    ripestat,
    shodan,
    username,
    virustotal,
    wayback,
    wikidata,
)
from .base import Module

MODULES: list[Module] = [
    # Phase 1 — core collectors + recursive engine
    username.MODULE,
    email.MODULE,
    phone.MODULE,
    name.MODULE,
    domain.MODULE,
    resolve.MODULE,
    asn.MODULE,
    profile_links.MODULE,
    wayback.MODULE,
    # Phase 2 — network/infra (keyless)
    ripestat.MODULE,
    ip_geo.MODULE,
    dns_intel.MODULE,
    commoncrawl.MODULE,
    # Phase 2 — identity pivots (keyless)
    github.MODULE,
    breach.MODULE,
    # Phase 6b — candidate-email pivot (keyless)
    permute.MODULE,
    # Phase 2 — keyed, optional (auto-skipped without vault keys)
    shodan.MODULE,
    virustotal.MODULE,
    abuseipdb.MODULE,
    # Optional expansion pack: dispatched only after the maturity gate passes.
    gitlab.MODULE,
    bluesky.MODULE,
    hackernews.MODULE,
    wikidata.MODULE,
]


def get_modules() -> list[Module]:
    return MODULES


def applicable_modules(art: Artifact, *, expansion_enabled: bool = False) -> list[Module]:
    return [m for m in MODULES if m.accepts(art, expansion_enabled=expansion_enabled)]
