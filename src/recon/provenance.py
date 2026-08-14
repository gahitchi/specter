"""Run provenance for reproducibility (#8).

Stamps every report with the tool version, the exact detection-dataset hash, key
dependency versions, and whether the run was deterministic — so a result can be
traced to the precise inputs that produced it.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path

from . import __version__
from .config import SETTINGS

_TRACKED = ("httpx", "sqlalchemy", "jellyfish", "phonenumbers", "dnspython", "fastapi")


def sha256_file(path: str | Path) -> str:
    """Hash an input file for provenance without embedding its path or content."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@lru_cache(maxsize=16)
def sites_dataset_hash(path: str | None = None) -> str:
    p = Path(path or SETTINGS.sites_data_file).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        return "unknown"


def _ver(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except Exception:
        return "unknown"


def _thresholds(settings) -> dict:
    return {
        "baseline_similarity_reject": settings.baseline_similarity_reject,
        "found_confidence": settings.found_confidence,
        "uncertain_confidence": settings.uncertain_confidence,
        "er_merge_threshold": settings.er_merge_threshold,
        "er_review_threshold": settings.er_review_threshold,
    }


def provenance(settings=SETTINGS) -> dict:
    """Run-level reproducibility stamp: the exact tool/dataset/thresholds/engine
    settings a run was produced under."""
    return {
        "tool_version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "deterministic": settings.deterministic,
        "probe_seed": settings.probe_seed if settings.deterministic else None,
        "sites_dataset_sha256": sites_dataset_hash(settings.sites_data_file),
        "thresholds": _thresholds(settings),
        "engine": {
            "scope_mode": settings.scope_mode,
            "max_depth": settings.max_depth,
            "max_artifacts": settings.max_artifacts,
            "max_requests": settings.max_requests,
            "passive_only": settings.passive_only,
            "confidence_independence": settings.confidence_independence,
        },
        "reasoning": {
            "version": 1,
            "adaptive_dispatch": True,
            "evidence_bound": True,
        },
        "dependencies": {pkg: _ver(pkg) for pkg in _TRACKED},
        "argv": " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "",
    }


def finding_trace(*, module: str, source: str, rule=None, ev=None,
                  baseline=None, settings=SETTINGS) -> dict:
    """Compact, per-finding provenance: enough to trace a single confidence value
    back to the exact inputs (dataset rule, baseline, thresholds, request) that
    produced it. Deterministic given the same inputs (no wall-clock here — the run
    carries `started_at` and the run-level provenance stamp)."""
    tr: dict = {
        "tool_version": __version__,
        "module": module,
        "source": source,
        "deterministic": settings.deterministic,
        "dataset_sha256": sites_dataset_hash(settings.sites_data_file),
        "thresholds": _thresholds(settings),
    }
    if rule is not None:
        tr["site_rule"] = {"name": getattr(rule, "name", None),
                           "error_type": getattr(rule, "error_type", None)}
    if ev is not None:
        tr["request"] = {"status": ev.status, "final_url": ev.final_url,
                         "elapsed_ms": ev.elapsed_ms, "blocked": ev.blocked}
    tr["baseline"] = None if baseline is None else {
        "status": baseline.status, "fingerprint": baseline.fingerprint,
        "blocked": baseline.blocked,
    }
    return tr
