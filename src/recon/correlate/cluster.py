"""Union-find clustering over strong identity signals.

Two findings that share a strong signal (same gravatar_hash, orcid, phone, etc.)
are merged into one identity cluster. Deterministic, no LLM — mirrors Specter.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Finding

# Signal keys treated as strong enough to merge identities on their own.
STRONG_KEYS = {"gravatar_hash", "orcid", "phone_e164", "email"}

IDENTITY_CATEGORIES = {"username", "email", "phone", "name"}


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

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        for k, v in f.signals.items():
            base = k.split(":", 1)[0]
            self.signals[base].add(v)


def cluster(findings: list[Finding]) -> list[Identity]:
    """Group findings into identity clusters via shared strong signals."""
    uf = _UF()
    # Node per finding index; merge finding-nodes that share a strong signal value.
    sig_to_node: dict[str, str] = {}
    for i, f in enumerate(findings):
        node = f"f{i}"
        uf.find(node)
        for k, v in f.signals.items():
            base = k.split(":", 1)[0]
            if base in STRONG_KEYS and v:
                key = f"{base}={v.lower()}"
                if key in sig_to_node:
                    uf.union(node, sig_to_node[key])
                else:
                    sig_to_node[key] = node

    groups: dict[str, Identity] = {}
    next_id = 0
    root_to_id: dict[str, int] = {}
    for i, f in enumerate(findings):
        root = uf.find(f"f{i}")
        if root not in root_to_id:
            root_to_id[root] = next_id
            groups[root] = Identity(id=next_id)
            next_id += 1
        groups[root].add(f)

    return list(groups.values())
