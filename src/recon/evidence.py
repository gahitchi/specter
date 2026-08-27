"""First-class evidence semantics shared by collection, storage, and reasoning.

The models in this module describe facts about an observation without deciding
whether two observations identify the same person. They keep provenance,
source lineage, temporal validity, completeness, and pivot permissions separate
so a visible lead cannot silently become a trusted conclusion or search pivot.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

EVIDENCE_MODEL_VERSION = "2.0"

_IDENTITY_SIGNAL_TYPES = {
    "account_profile",
    "bluesky_did",
    "email",
    "gravatar_hash",
    "name",
    "orcid",
    "phone",
    "phone_e164",
    "profile_url",
    "username",
}
_SIGNAL_ALIASES = {"phone": "phone_e164"}


class EvidenceClass(str, enum.Enum):
    DIRECT = "direct"
    DERIVED = "derived"
    AGGREGATED = "aggregated"
    EXTERNAL_TOOL = "external_tool"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class TemporalStatus(str, enum.Enum):
    CURRENT = "current"
    HISTORICAL = "historical"
    UNKNOWN = "unknown"


class Completeness(str, enum.Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class EvidenceOrigin(BaseModel):
    """Lineage of an observation, independent from its display source name."""

    model_config = ConfigDict(extra="forbid")

    collector: str = Field(min_length=1, max_length=120)
    operator: str = Field(min_length=1, max_length=200)
    origin: str = Field(min_length=1, max_length=240)
    evidence_class: EvidenceClass = EvidenceClass.UNKNOWN
    independence_key: str = Field(min_length=1, max_length=200)


class ExtractionProvenance(BaseModel):
    """Where one value came from and which transformations produced it."""

    model_config = ConfigDict(extra="forbid")

    input_artifact_key: str | None = Field(default=None, max_length=520)
    method: str = Field(min_length=1, max_length=160)
    location: str = Field(min_length=1, max_length=160)
    document_url: str | None = Field(default=None, max_length=2048)
    original_url: str | None = Field(default=None, max_length=2048)
    final_url: str | None = Field(default=None, max_length=2048)
    selector: str | None = Field(default=None, max_length=300)
    context: str | None = Field(default=None, max_length=500)
    extracted_value: str | None = Field(default=None, max_length=2048)
    retrieved_at: datetime | None = None
    extractor: str = Field(default="specter", min_length=1, max_length=120)
    extractor_version: str | None = Field(default=None, max_length=80)
    direct: bool = True
    transformation_chain: list[str] = Field(default_factory=list, max_length=12)
    transformation_certainty: float = Field(default=1.0, ge=0.0, le=1.0)


class TemporalEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    status: TemporalStatus = TemporalStatus.UNKNOWN


class ConfidenceDimensions(BaseModel):
    """Auditable confidence inputs; the calibrated verdict remains authoritative."""

    model_config = ConfigDict(extra="forbid")

    match_quality: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    recency: float = Field(default=0.5, ge=0.0, le=1.0)
    independence: float = Field(default=0.5, ge=0.0, le=1.0)
    transformation_certainty: float = Field(default=1.0, ge=0.0, le=1.0)
    completeness: float = Field(default=0.5, ge=0.0, le=1.0)

    def aggregate(self) -> float:
        weights = {
            "match_quality": 0.35,
            "source_reliability": 0.25,
            "recency": 0.10,
            "independence": 0.10,
            "transformation_certainty": 0.12,
            "completeness": 0.08,
        }
        return round(sum(getattr(self, key) * weight for key, weight in weights.items()), 3)


class EvidencePolicy(BaseModel):
    """Permissions attached to evidence and artifacts, not inferred from score."""

    model_config = ConfigDict(extra="forbid")

    candidate_only: bool = False
    confirmation_allowed: bool = True
    pivot_allowed: bool = True
    requires_corroboration: bool = False
    minimum_independent_origins: int = Field(default=1, ge=1, le=5)

    @classmethod
    def candidate(cls) -> "EvidencePolicy":
        return cls(
            candidate_only=True,
            confirmation_allowed=False,
            pivot_allowed=False,
            requires_corroboration=True,
            minimum_independent_origins=2,
        )

    @classmethod
    def corroborated(cls, minimum_origins: int = 2) -> "EvidencePolicy":
        """Evidence may support identity only after independent corroboration."""
        return cls(
            requires_corroboration=True,
            minimum_independent_origins=minimum_origins,
        )


def restrictive_policy(*policies: EvidencePolicy) -> EvidencePolicy:
    """Compose policies so downstream code can only make evidence more restrictive."""
    available = [policy for policy in policies if policy is not None]
    if not available:
        return EvidencePolicy()
    return EvidencePolicy(
        candidate_only=any(policy.candidate_only for policy in available),
        confirmation_allowed=all(policy.confirmation_allowed for policy in available),
        pivot_allowed=all(policy.pivot_allowed for policy in available),
        requires_corroboration=any(policy.requires_corroboration for policy in available),
        minimum_independent_origins=max(
            policy.minimum_independent_origins for policy in available
        ),
    )


class PromotionAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    status: str
    independent_origins: int = 0
    reasons: list[str] = Field(default_factory=list)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def infer_origin(
    source: str,
    url: str | None = None,
    *,
    collector: str | None = None,
    operator: str | None = None,
    evidence_class: EvidenceClass | None = None,
    independence_key: str | None = None,
) -> EvidenceOrigin:
    """Build explicit lineage from the best metadata currently available."""
    from .trust.independence import class_of

    source = (source or "unknown").strip()
    host = ""
    if url:
        try:
            host = (urlsplit(url).hostname or "").casefold()
        except ValueError:
            host = ""
    external = source.casefold().startswith("external:")
    offline = source.casefold().startswith("phone") and not url
    klass = evidence_class or (
        EvidenceClass.EXTERNAL_TOOL
        if external
        else EvidenceClass.OFFLINE
        if offline
        else EvidenceClass.DIRECT
        if url
        else EvidenceClass.UNKNOWN
    )
    direct_page = source.casefold().startswith(("profile:", "phone:web"))
    host_class = class_of(host) if host else ""
    lineage = independence_key or (
        (
            host_class
            if host_class != host
            else f"site:{host.removeprefix('www.')}"
        )
        if host and direct_page
        else class_of(source)
    )
    return EvidenceOrigin(
        collector=collector or source.split(":", 1)[0] or "unknown",
        operator=operator or host or source,
        origin=host or lineage,
        evidence_class=klass,
        independence_key=lineage,
    )


def evidence_claim_key(
    category: str,
    url: str | None,
    label: str,
    signals: dict[str, str] | None = None,
) -> str:
    """Stable key for temporal comparison and explicit contradiction records."""
    normalized_url = (url or "").strip().casefold().rstrip("/")
    strong = {
        key: str(value).strip().casefold()
        for key, value in sorted((signals or {}).items())
        if value
    }
    payload = {
        "category": (category or "unknown").strip().casefold(),
        "url": normalized_url,
        "label": "" if normalized_url or strong else (label or "").strip().casefold(),
        # A directly retrieved page remains the same temporal claim when its
        # identity fields change. Keeping those fields out of the key lets the
        # store record reassignment and conflicting-attribution transitions.
        "signals": {} if normalized_url else strong,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def assess_promotion(
    policy: EvidencePolicy,
    independent_origins: int,
) -> PromotionAssessment:
    reasons: list[str] = []
    if policy.candidate_only:
        reasons.append("candidate-only evidence cannot steer automatic research")
    if not policy.pivot_allowed:
        reasons.append("the evidence policy does not permit automatic pivoting")
    if policy.requires_corroboration and independent_origins < policy.minimum_independent_origins:
        reasons.append(
            f"requires {policy.minimum_independent_origins} independent origins; "
            f"observed {independent_origins}"
        )
    allowed = not reasons
    if allowed:
        status = "eligible"
    elif policy.candidate_only:
        status = "candidate"
    elif policy.requires_corroboration:
        status = "awaiting_corroboration"
    else:
        status = "blocked"
    return PromotionAssessment(
        allowed=allowed,
        status=status,
        independent_origins=independent_origins,
        reasons=reasons,
    )


def confirmation_eligible(observation: Any) -> bool:
    """Whether an observation may participate in identity corroboration.

    A FOUND verdict can confirm many narrower facts, such as numbering-plan
    validity or a historical page mention.  Those facts remain visible, but
    their evidence policy, review state, and temporal status keep them out of
    current-identity synthesis. A corroboration requirement is evaluated by
    :func:`confirmation_satisfied`, not by this per-observation predicate.
    """
    verdict = getattr(observation, "verdict", "")
    verdict_value = getattr(verdict, "value", verdict)
    if str(verdict_value).upper() != "FOUND":
        return False

    temporal = getattr(observation, "temporal", None)
    temporal_status = getattr(temporal, "status", None)
    if temporal_status is None:
        temporal_status = getattr(observation, "temporal_status", None)
    temporal_value = getattr(temporal_status, "value", temporal_status)
    if str(temporal_value or "").casefold() == TemporalStatus.HISTORICAL.value:
        return False

    reviews = getattr(observation, "reviews", None)
    if reviews:
        latest = max(reviews, key=lambda review: getattr(review, "id", 0))
        if str(getattr(latest, "decision", "")).casefold() != "accepted":
            return False

    policy = getattr(observation, "policy", None)
    if isinstance(policy, dict):
        candidate_only = bool(policy.get("candidate_only", False))
        confirmation_allowed = bool(policy.get("confirmation_allowed", True))
    else:
        candidate_only = bool(getattr(policy, "candidate_only", False))
        confirmation_allowed = bool(getattr(policy, "confirmation_allowed", True))
    return confirmation_allowed and not candidate_only


def identity_signal_keys(observation: Any) -> set[tuple[str, str]]:
    """Normalized identity assertions carried by an observation."""
    signals = getattr(observation, "signals", None) or {}
    keys: set[tuple[str, str]] = set()
    for raw_key, raw_value in signals.items():
        if raw_value in (None, ""):
            continue
        signal_type = str(raw_key).split(":", 1)[0].strip().casefold()
        signal_type = _SIGNAL_ALIASES.get(signal_type, signal_type)
        if signal_type not in _IDENTITY_SIGNAL_TYPES:
            continue
        value = " ".join(str(raw_value).strip().casefold().split())
        if value:
            keys.add((signal_type, value))
    return keys


def _query_signal_keys(query: Any | None) -> set[tuple[str, str]]:
    if query is None:
        return set()
    fields = query if isinstance(query, dict) else {
        name: getattr(query, name, None)
        for name in ("username", "email", "phone", "name", "url")
    }
    keys: set[tuple[str, str]] = set()
    for raw_key, raw_value in fields.items():
        if raw_value in (None, ""):
            continue
        signal_type = _SIGNAL_ALIASES.get(str(raw_key).casefold(), str(raw_key).casefold())
        if signal_type == "url":
            signal_type = "account_profile"
        if signal_type not in _IDENTITY_SIGNAL_TYPES:
            continue
        value = " ".join(str(raw_value).strip().casefold().split())
        if value:
            keys.add((signal_type, value))
    return keys


def _observation_policy(observation: Any) -> EvidencePolicy:
    policy = getattr(observation, "policy", None)
    if isinstance(policy, EvidencePolicy):
        return policy
    if isinstance(policy, dict):
        if not policy:
            # Rows predating evidence policies must fail conservatively.
            return EvidencePolicy.corroborated()
        return EvidencePolicy.model_validate(policy)
    return EvidencePolicy()


def _origin_key(observation: Any) -> str:
    from .trust.independence import class_of_observation

    return class_of_observation(observation).casefold()


def confirmation_satisfied(
    observation: Any,
    observations: list[Any] | tuple[Any, ...],
    query: Any | None = None,
) -> bool:
    """Whether the observation can currently support an identity conclusion.

    Restricted evidence needs the configured number of independent origins that
    assert the same non-seed identity value. Merely repeating the supplied phone,
    email, username, name, or profile URL does not corroborate its association to
    a person.
    """
    if not confirmation_eligible(observation):
        return False
    if not identity_signal_keys(observation):
        return False
    policy = _observation_policy(observation)
    if not policy.requires_corroboration:
        return True

    association_keys = identity_signal_keys(observation) - _query_signal_keys(query)
    if not association_keys:
        return False
    for association_key in association_keys:
        # Names can support review and conflict checks, but cannot by themselves
        # establish identity. Directories frequently copy the same stale record.
        if association_key[0] == "name":
            continue
        origins = {
            _origin_key(peer)
            for peer in observations
            if confirmation_eligible(peer)
            and association_key in identity_signal_keys(peer)
        }
        required = max(policy.minimum_independent_origins, 2)
        if len(origins) >= required:
            return True
    return False


def default_dimensions(
    confidence: float,
    reliability: float,
    completeness: Completeness,
    extractions: list[ExtractionProvenance],
) -> ConfidenceDimensions:
    certainty = min(
        (item.transformation_certainty for item in extractions),
        default=0.5,
    )
    completeness_score = {
        Completeness.COMPLETE: 1.0,
        Completeness.PARTIAL: 0.4,
        Completeness.UNKNOWN: 0.5,
    }[completeness]
    return ConfidenceDimensions(
        match_quality=max(0.0, min(1.0, confidence)),
        source_reliability=max(0.0, min(1.0, reliability)),
        transformation_certainty=certainty,
        completeness=completeness_score,
    )


def model_json(value: BaseModel | None) -> dict[str, Any] | None:
    return value.model_dump(mode="json") if value is not None else None
