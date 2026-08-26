"""Conservative union-find clustering over verified identity signals.

Shared strong values can propose a merge, but the resolver score and aggregate
coherence checks must both permit it. This prevents one shared phone or hash
from transitively joining records that disagree on another strong identifier.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..evidence import confirmation_satisfied
from ..models import Finding

# Signal keys treated as strong enough to merge identities on their own.
STRONG_KEYS = {"gravatar_hash", "orcid", "phone_e164", "email", "bluesky_did"}

IDENTITY_CATEGORIES = {"username", "email", "phone", "name", "profile"}


def identity_bearing(category: str) -> bool:
    """Whether an observation can represent a person/account identity node.

    Domains, hosts, and network observations belong in the discovery graph and
    synthesized profile, but a shared organization domain is not unique-person
    evidence and must never create or merge identity entities.
    """
    return category in IDENTITY_CATEGORIES


class _UF:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


@dataclass
class Identity:
    id: int
    findings: list[Finding] = field(default_factory=list)
    signals: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    flags: list[str] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        for k, v in f.signals.items():
            base = k.split(":", 1)[0]
            self.signals[base].add(v)


def cluster(findings: list[Finding], query=None) -> list[Identity]:
    """Group confirmation-satisfied findings without crossing contradictions."""
    from . import coherence
    from .blocking import candidate_pairs
    from .resolver import classify, record_from, score

    eligible = [
        finding
        for finding in findings
        if confirmation_satisfied(finding, findings, query)
    ]
    if not eligible:
        return []

    uf = _UF()
    records = [record_from(index, f.category, f.label, f.signals) for index, f in enumerate(eligible)]
    for index in range(len(records)):
        uf.find(str(index))

    ranked_pairs = []
    for left, right in candidate_pairs(records):
        weight, _reasons = score(records[left], records[right])
        ranked_pairs.append((weight, left, right))
    ranked_pairs.sort(reverse=True)
    for weight, left, right in ranked_pairs:
        if classify(weight) != "MERGE":
            continue
        left_root, right_root = uf.find(str(left)), uf.find(str(right))
        if left_root == right_root:
            continue
        combined = [
            records[index]
            for index in range(len(records))
            if uf.find(str(index)) in {left_root, right_root}
        ]
        if coherence.check(combined):
            continue
        uf.union(left_root, right_root)

    groups: dict[str, Identity] = {}
    next_id = 0
    root_to_id: dict[str, int] = {}
    grouped_records: dict[str, list] = defaultdict(list)
    for i, f in enumerate(eligible):
        root = uf.find(str(i))
        if root not in root_to_id:
            root_to_id[root] = next_id
            groups[root] = Identity(id=next_id)
            next_id += 1
        groups[root].add(f)
        grouped_records[root].append(records[i])

    for root, identity in groups.items():
        identity.flags = coherence.check(grouped_records[root])

    return list(groups.values())
