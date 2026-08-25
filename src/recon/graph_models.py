"""Artifacts: the typed data points discovered during a recursive scan.

This is the substrate of the event-driven engine (`engine.py`). A scan is no
longer a single pass over the seed identifiers; it is a graph traversal where
each *artifact* (a domain, a discovered subdomain, an IP, an ASN, a profile URL,
a harvested email...) is dispatched to every module that consumes its type, and
modules emit *new* artifacts that are fed back into the frontier.

`Artifact` is deliberately distinct from the `Entity` ORM model
(`store/models_db.py`): an Entity is a *resolved identity cluster* produced by
correlation **after** a run; an Artifact is a *discovery-graph node* produced
**during** a run. Keeping them separate means the recursive engine and the
identity-resolution layer evolve independently.
"""

from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from . import normalize
from .evidence import EvidenceOrigin, EvidencePolicy


class ArtifactType(str, enum.Enum):
    # --- Seed types (map 1:1 to Query fields) ---
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    NAME = "name"
    # --- Discovered types (only reachable via recursion) ---
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    ASN = "asn"
    NETBLOCK = "netblock"
    HOSTNAME = "hostname"
    URL = "url"
    LINK = "link"
    HASH = "hash"  # gravatar / avatar hash, etc.
    ACCOUNT_PROFILE = "account_profile"  # a verified profile page to enrich
    MX_HOST = "mx_host"
    NAMESERVER = "nameserver"
    BREACH = "breach"


# Per-type canonicalization, reusing the single normalization layer so the
# engine's dedup set agrees with collectors and correlation about identity.
_NORMALIZERS = {
    ArtifactType.USERNAME: normalize.norm_username,
    ArtifactType.EMAIL: normalize.norm_email,
    ArtifactType.DOMAIN: normalize.norm_domain,
    ArtifactType.SUBDOMAIN: normalize.norm_domain,
    ArtifactType.HOSTNAME: normalize.norm_domain,
    ArtifactType.MX_HOST: normalize.norm_domain,
    ArtifactType.NAMESERVER: normalize.norm_domain,
    ArtifactType.URL: normalize.norm_url,
    ArtifactType.LINK: normalize.norm_url,
    ArtifactType.ACCOUNT_PROFILE: normalize.norm_url,
    ArtifactType.NAME: normalize.norm_text,
    ArtifactType.PHONE: normalize.norm_phone,
    ArtifactType.IP_ADDRESS: normalize.norm_ip,
}


def _normalize(atype: ArtifactType, value: str) -> str:
    fn = _NORMALIZERS.get(atype)
    if fn is not None:
        return fn(value) or value.strip().lower()
    # IP / ASN / NETBLOCK / HASH / PHONE / BREACH: just trim + casefold.
    return value.strip().lower()


class Artifact(BaseModel):
    """One typed node in the discovery graph."""

    type: ArtifactType
    value: str
    normalized: str = ""
    depth: int = 0
    source_module: str = "seed"  # module that produced this artifact
    parent_key: Optional[str] = None  # key of the artifact that led here
    confidence: float = 1.0
    origin: EvidenceOrigin | None = None
    policy: EvidencePolicy = Field(default_factory=EvidencePolicy)
    data: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.normalized:
            self.normalized = _normalize(self.type, self.value)

    @property
    def key(self) -> str:
        """Stable identity used for frontier dedup and edge endpoints."""
        return f"{self.type.value}:{self.normalized}"

    @classmethod
    def make(cls, atype: ArtifactType, value: str, *, parent: "Artifact | None" = None,
             source_module: str = "seed", confidence: float = 1.0,
             origin: EvidenceOrigin | None = None,
             policy: EvidencePolicy | None = None,
             **data: Any) -> "Artifact":
        """Convenience constructor that wires depth + provenance from a parent."""
        return cls(
            type=atype,
            value=value,
            depth=(parent.depth + 1) if parent is not None else 0,
            source_module=source_module,
            parent_key=parent.key if parent is not None else None,
            confidence=confidence,
            origin=origin,
            policy=policy or EvidencePolicy(),
            data=data,
        )
