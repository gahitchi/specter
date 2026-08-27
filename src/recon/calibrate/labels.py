"""Ground-truth labels for calibration.

A small curated set of known-present / known-absent (account, site) pairs ships
inside the package; point `RECON_CALIBRATION_FILE` at your own dataset to extend
it. The shipped rows are a functional fixture only; representative labels must
come from independent verification rather than the engine's own verdicts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_DEFAULT = Path(__file__).resolve().parents[1] / "data" / "calibration_labels.json"


class CalibrationLabel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    category: Literal["username"] = "username"
    account: str = Field(min_length=1, max_length=320)
    site: str = Field(min_length=1, max_length=200)
    present: bool
    verified_by: str | None = Field(default=None, max_length=120)
    verification_method: str | None = Field(default=None, max_length=200)
    verified_at: str | None = Field(default=None, max_length=80)


def labels_file(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    env = os.environ.get("RECON_CALIBRATION_FILE")
    if env:
        return Path(env)
    return _DEFAULT


def load_labels(path: str | Path | None = None) -> list[dict]:
    """Each row: {category, account, site, present}. Returns [] if the file is
    missing (calibration then has nothing to do, which the runner reports)."""
    p = labels_file(path)
    if not p.exists():
        return []
    if p.stat().st_size > 5_000_000:
        raise ValueError("calibration label file is too large")
    raw = json.loads(p.read_text(encoding="utf-8"))
    rows = raw.get("labels") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError("calibration file must contain a 'labels' list")

    labels: dict[tuple[str, str, str], dict] = {}
    outcomes: dict[tuple[str, str, str], bool] = {}
    for index, row in enumerate(rows):
        try:
            label = CalibrationLabel.model_validate(row)
        except ValidationError as exc:
            raise ValueError(f"invalid calibration label #{index}: {exc}") from exc
        key = (label.category, label.account.casefold(), label.site.casefold())
        if key in outcomes and outcomes[key] != label.present:
            raise ValueError(
                f"contradictory calibration labels for {label.account!r} at {label.site!r}"
            )
        outcomes[key] = label.present
        labels[key] = label.model_dump(exclude_none=True)
    return list(labels.values())
