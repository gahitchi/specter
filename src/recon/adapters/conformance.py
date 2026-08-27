"""Reusable conformance checks for bounded external-tool adapters."""

from __future__ import annotations

from .base import AdapterManifest, ExternalObservation, ObservationDisposition


def conformance_errors(
    manifest: AdapterManifest,
    observations: list[ExternalObservation] | tuple[ExternalObservation, ...],
) -> list[str]:
    errors: list[str] = []
    for index, observation in enumerate(observations):
        prefix = f"observation {index}"
        if observation.adapter != manifest.adapter:
            errors.append(f"{prefix}: adapter does not match manifest")
        if observation.artifact_type not in manifest.consumes and not manifest.candidate_only:
            errors.append(f"{prefix}: artifact type is not declared")
        if manifest.candidate_only:
            if observation.disposition != ObservationDisposition.CANDIDATE:
                errors.append(f"{prefix}: candidate-only adapter emitted a final disposition")
            if observation.policy.pivot_allowed or observation.policy.confirmation_allowed:
                errors.append(f"{prefix}: candidate-only output has unsafe permissions")
        if not observation.provenance.independence_class.strip():
            errors.append(f"{prefix}: independence class is missing")
        if manifest.external_network and not observation.provenance.data_sent:
            errors.append(f"{prefix}: network adapter did not declare data sent")
    return errors


def assert_conformant(
    manifest: AdapterManifest,
    observations: list[ExternalObservation] | tuple[ExternalObservation, ...],
) -> None:
    errors = conformance_errors(manifest, observations)
    if errors:
        raise ValueError("adapter conformance failed: " + "; ".join(errors))
