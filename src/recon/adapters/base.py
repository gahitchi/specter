"""Versioned contract between external tools and Specter's evidence engine."""

from __future__ import annotations

import enum
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..evidence import (
    Completeness,
    EvidenceClass,
    EvidenceOrigin,
    EvidencePolicy,
    ExtractionProvenance,
)
from ..graph_models import ArtifactType

OBSERVATION_SCHEMA_VERSION = "1.0"
_MAX_ATTRIBUTES_BYTES = 32_768


class ObservationDisposition(str, enum.Enum):
    """What an adapter actually observed, before Specter interprets it."""

    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    ABSENT = "absent"
    UNVERIFIABLE = "unverifiable"
    ERROR = "error"


class ObservationProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: str = Field(min_length=1, max_length=160)
    interaction: str = Field(min_length=1, max_length=80)
    method: str = Field(min_length=1, max_length=240)
    independence_class: str = Field(min_length=1, max_length=160)
    data_sent: list[str] = Field(default_factory=list, max_length=20)
    tool_version: str | None = Field(default=None, max_length=80)
    origin: str | None = Field(default=None, max_length=240)
    evidence_class: EvidenceClass = EvidenceClass.EXTERNAL_TOOL
    extraction: ExtractionProvenance | None = None

    def as_origin(self, collector: str) -> EvidenceOrigin:
        return EvidenceOrigin(
            collector=collector,
            operator=self.operator,
            origin=self.origin or self.independence_class,
            evidence_class=self.evidence_class,
            independence_key=self.independence_class,
        )


class ExternalObservation(BaseModel):
    """A bounded, serializable observation that cannot silently become truth."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = OBSERVATION_SCHEMA_VERSION
    adapter: str = Field(min_length=1, max_length=80)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifact_type: ArtifactType
    value: str = Field(min_length=1, max_length=2048)
    url: str | None = Field(default=None, max_length=2048)
    label: str = Field(min_length=1, max_length=200)
    disposition: ObservationDisposition
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(min_length=1, max_length=10)
    provenance: ObservationProvenance
    completeness: Completeness = Completeness.UNKNOWN
    policy: EvidencePolicy = Field(default_factory=EvidencePolicy.candidate)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("attributes")
    @classmethod
    def _bounded_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("observation attributes must be JSON-serializable") from exc
        if len(encoded.encode("utf-8")) > _MAX_ATTRIBUTES_BYTES:
            raise ValueError("observation attributes exceed 32 KiB")
        return value

    @model_validator(mode="after")
    def _candidate_contract_is_conservative(self) -> "ExternalObservation":
        if self.disposition == ObservationDisposition.CANDIDATE:
            if self.policy.confirmation_allowed or self.policy.pivot_allowed:
                raise ValueError(
                    "candidate observations cannot confirm identity or pivot automatically"
                )
        return self


class AdapterManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    contract_version: Literal["1.0"] = OBSERVATION_SCHEMA_VERSION
    consumes: tuple[ArtifactType, ...]
    candidate_only: bool = True
    external_network: bool = True
    interaction: str = Field(min_length=1, max_length=80)
    capabilities: tuple[str, ...] = ()
    supported_tool_versions: str | None = Field(default=None, max_length=120)
