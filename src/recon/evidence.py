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
        EvidenceClass.EXTERNAL_TOOL if external
        else EvidenceClass.OFFLINE if offline
        else EvidenceClass.DIRECT if url
        else EvidenceClass.UNKNOWN
    )
    direct_page = source.casefold().startswith(("profile:", "phone:web"))
    lineage = independence_key or (
        f"site:{host.removeprefix('www.')}" if host and direct_page else class_of(source)
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
        "signals": strong,
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
    if (
        policy.requires_corroboration
        and independent_origins < policy.minimum_independent_origins
    ):
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
