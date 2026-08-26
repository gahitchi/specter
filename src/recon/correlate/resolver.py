"""Probabilistic entity resolution (Fellegi–Sunter-style).

Each observation becomes a Record of typed attributes. Pairs of records get a
summed match weight from per-attribute comparators; strong identifiers carry
large positive weight, conflicts carry negative weight. Thresholds (config)
yield MERGE / REVIEW / DISTINCT — ambiguous pairs are never silently merged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import jellyfish

from ..config import SETTINGS

# Signal keys we treat as strong, unique identifiers.
STRONG = {"email", "gravatar_hash", "orcid", "phone_e164", "bluesky_did"}


@dataclass
class Record:
    obs_id: int
    emails: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    strong: dict[str, set[str]] = field(default_factory=dict)  # key -> {values}

    def add_strong(self, key: str, value: str) -> None:
        self.strong.setdefault(key, set()).add(value.lower())


def _norm_handle(h: str) -> str:
    return "".join(ch for ch in h.lower() if ch.isalnum())


def record_from(obs_id: int, category: str, label: str,
                signals: dict[str, str]) -> Record:
    rec = Record(obs_id=obs_id)
    for k, v in (signals or {}).items():
        if not v:
            continue
        base = k.split(":", 1)[0]
        if base == "username":
            rec.usernames.add(_norm_handle(v))
        elif base == "name":
            rec.names.add(" ".join(v.casefold().split()))
        elif base == "email":
            rec.emails.add(v.lower())
            rec.add_strong("email", v.lower())
        elif base in STRONG:
            rec.add_strong(base, v)
    if category == "name" and label:
        # label like "ORCID: Ada Lovelace" / "OpenAlex: Ada Lovelace"
        rec.names.add(label.split(":", 1)[-1].strip().lower())
    return rec


# Per-attribute weights (log-likelihood-ish; tuned, not learned).
_W = {
    "gravatar_hash": 9.0, "orcid": 9.0, "bluesky_did": 9.0, "email": 8.0,
    "phone_e164": 8.0,
}


def score(a: Record, b: Record) -> tuple[float, list[str]]:
    """Return (match_weight, reasons). Higher = more likely same identity."""
    w = 0.0
    reasons: list[str] = []

    for key, weight in _W.items():
        sa, sb = a.strong.get(key, set()), b.strong.get(key, set())
        if not sa or not sb:
            continue
        if sa & sb:
            w += weight
            reasons.append(f"shared {key}")
        else:
            # Both have this strong id but they differ -> contradiction.
            w -= weight * 0.6
            reasons.append(f"conflicting {key}")

    # Handle reuse across sites: suggestive, not proof.
    if a.usernames & b.usernames:
        w += 2.0
        reasons.append("same username handle")

    # Name similarity via Jaro-Winkler (mirrors Specter's >=0.92).
    if a.names and b.names:
        best = max(jellyfish.jaro_winkler_similarity(x, y)
                   for x in a.names for y in b.names)
        if best >= SETTINGS.name_match_threshold:
            w += 3.0 * best
            reasons.append(f"name match (JW {best:.2f})")
        elif best < 0.7:
            w -= 3.0
            reasons.append(f"name mismatch (JW {best:.2f})")

    return round(w, 3), reasons


def classify(weight: float) -> str:
    if weight >= SETTINGS.er_merge_threshold:
        return "MERGE"
    if weight >= SETTINGS.er_review_threshold:
        return "REVIEW"
    return "DISTINCT"
