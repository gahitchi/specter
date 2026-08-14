"""Calibration metrics — pure, deterministic, no I/O.

A confidence score is *calibrated* if, among candidates it scores ~p, a fraction
~p are actually present. These functions turn a set of (confidence, outcome)
samples into the standard calibration diagnostics — a reliability diagram, the
Brier score, and Expected Calibration Error — plus the confusion at a decision
threshold and a non-binding threshold suggestion.

Everything here is side-effect-free so it is fully unit-testable with synthetic
samples; the live runner (`runner.py`) only supplies the samples.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    confidence: float        # predicted P(present), 0..1
    present: bool            # ground-truth outcome
    source: str = ""
    category: str = ""


def reliability_bins(samples: list[Sample], n_bins: int = 10) -> list[dict]:
    """Partition [0,1] into n_bins; per bin report mean predicted vs empirical
    (fraction actually present) and the gap between them."""
    bins: list[dict] = [
        {"lo": i / n_bins, "hi": (i + 1) / n_bins, "count": 0,
         "mean_pred": 0.0, "empirical": 0.0, "gap": 0.0}
        for i in range(n_bins)
    ]
    acc = [{"sum_pred": 0.0, "present": 0} for _ in range(n_bins)]
    for s in samples:
        idx = min(n_bins - 1, max(0, int(s.confidence * n_bins)))
        bins[idx]["count"] += 1
        acc[idx]["sum_pred"] += s.confidence
        acc[idx]["present"] += 1 if s.present else 0
    for b, a in zip(bins, acc):
        if b["count"]:
            b["mean_pred"] = round(a["sum_pred"] / b["count"], 4)
            b["empirical"] = round(a["present"] / b["count"], 4)
            b["gap"] = round(b["empirical"] - b["mean_pred"], 4)
    return bins


def brier(samples: list[Sample]) -> float:
    """Mean squared error between confidence and outcome (lower is better, 0..1)."""
    if not samples:
        return 0.0
    return round(sum((s.confidence - (1.0 if s.present else 0.0)) ** 2
                     for s in samples) / len(samples), 4)


def ece(samples: list[Sample], n_bins: int = 10) -> float:
    """Expected Calibration Error: count-weighted mean |empirical - predicted|."""
    if not samples:
        return 0.0
    n = len(samples)
    return round(sum((b["count"] / n) * abs(b["gap"])
                     for b in reliability_bins(samples, n_bins) if b["count"]), 4)


def mce(samples: list[Sample], n_bins: int = 10) -> float:
    """Maximum Calibration Error: the worst bin gap."""
    gaps = [abs(b["gap"]) for b in reliability_bins(samples, n_bins) if b["count"]]
    return round(max(gaps), 4) if gaps else 0.0


def confusion_at(samples: list[Sample], threshold: float) -> dict:
    """Treat confidence >= threshold as a predicted 'present'."""
    tp = fp = tn = fn = 0
    for s in samples:
        pred = s.confidence >= threshold
        if pred and s.present:
            tp += 1
        elif pred and not s.present:
            fp += 1
        elif not pred and not s.present:
            tn += 1
        else:
            fn += 1
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"threshold": round(threshold, 3), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "fp_rate": round(fp_rate, 4), "precision": round(precision, 4),
            "recall": round(recall, 4)}


def suggest_threshold(samples: list[Sample], current: float,
                      target_fp_rate: float = 0.05) -> dict:
    """Lowest threshold whose false-positive rate is within budget, maximizing
    recall. Advisory only — never applied automatically."""
    candidates = sorted({round(s.confidence, 2) for s in samples} | {current})
    best = None
    for t in candidates:
        c = confusion_at(samples, t)
        if c["fp_rate"] <= target_fp_rate:
            if best is None or c["recall"] > best["recall"]:
                best = c
    cur = confusion_at(samples, current)
    if best is None:
        rationale = (f"no threshold reaches FP-rate ≤ {target_fp_rate:.0%}; "
                     f"current {current} has FP-rate {cur['fp_rate']:.0%}")
        return {"current": current, "suggested": current, "fp_rate": cur["fp_rate"],
                "rationale": rationale}
    move = "raise" if best["threshold"] > current else ("lower" if best["threshold"] < current else "keep")
    return {"current": current, "suggested": best["threshold"],
            "fp_rate": best["fp_rate"], "recall": best["recall"],
            "rationale": f"{move} FOUND threshold to {best['threshold']} for "
                         f"FP-rate {best['fp_rate']:.0%} at recall {best['recall']:.0%}"}


def summary(samples: list[Sample], found_threshold: float,
            uncertain_threshold: float, n_bins: int = 10) -> dict:
    positives = sum(1 for s in samples if s.present)
    negatives = len(samples) - positives
    adequate = len(samples) >= 100 and positives >= 20 and negatives >= 20
    report = {
        "n": len(samples),
        "positives": positives,
        "negatives": negatives,
        "brier": brier(samples),
        "ece": ece(samples, n_bins),
        "mce": mce(samples, n_bins),
        "bins": reliability_bins(samples, n_bins),
        "confusion_found": confusion_at(samples, found_threshold),
        "confusion_uncertain": confusion_at(samples, uncertain_threshold),
        "suggestion": suggest_threshold(samples, found_threshold),
        "sample_quality": {
            "adequate": adequate,
            "minimum": {"total": 100, "positives": 20, "negatives": 20},
            "warning": None if adequate else (
                "sample is too small or imbalanced to validate calibration or tune thresholds"
            ),
        },
    }
    if not adequate:
        report["suggestion"]["advisory_only"] = True
    return report
