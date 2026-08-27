"""Structured score explainability.

Confidence numbers in this project are *additive*: a prior plus signed
contributions from each verification layer (verdict) or each corroborating
source (entity). Historically those deltas were only described in prose
(`Finding.reasons`). A `ScoreBreakdown` captures them as data, so any score can
be audited term by term — `0.85 = 0.50 prior +0.20 status-vs-baseline
+0.20 content-differs -0.05 …` — and so downstream tooling (calibration,
analytics) can reason about *which signals* drive confidence.

`shadow_total` carries the alternative connector-name breadth calculation for
audit comparison. The official score uses independent upstream classes.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Contribution(BaseModel):
    term: str                 # stable machine id, e.g. "status_vs_baseline"
    delta: float              # signed contribution to the score
    reason: str = ""          # human-readable explanation
    layer: str = "verdict"    # "verdict" | "entity" | "identity"


class ScoreBreakdown(BaseModel):
    base: float = 0.0
    contributions: list[Contribution] = Field(default_factory=list)
    total: float = 0.0
    shadow_total: Optional[float] = None
    shadow_note: Optional[str] = None
    dimensions: dict[str, float] = Field(default_factory=dict)

    def add(self, term: str, delta: float, reason: str = "",
            layer: str = "verdict") -> "ScoreBreakdown":
        self.contributions.append(
            Contribution(term=term, delta=round(delta, 3), reason=reason, layer=layer))
        return self

    def summed(self, lo: float = 0.0, hi: float = 1.0) -> float:
        """Clamp of base + Σ contributions — the canonical way to derive `total`."""
        return max(lo, min(hi, self.base + sum(c.delta for c in self.contributions)))

    def finalize(self, lo: float = 0.0, hi: float = 1.0) -> "ScoreBreakdown":
        self.total = round(self.summed(lo, hi), 3)
        return self
