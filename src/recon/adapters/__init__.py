"""Optional external-tool adapters with a candidate-only evidence boundary."""

from .base import (
    AdapterManifest,
    ExternalObservation,
    ObservationDisposition,
    ObservationProvenance,
)
from .conformance import assert_conformant, conformance_errors

__all__ = [
    "AdapterManifest",
    "ExternalObservation",
    "ObservationDisposition",
    "ObservationProvenance",
    "assert_conformant",
    "conformance_errors",
]
