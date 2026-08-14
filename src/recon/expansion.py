"""One gate for capabilities that materially increase privacy or security risk."""

from __future__ import annotations


CAPABILITIES = {"source_pack", "ml_identity", "remote_dashboard", "multi_user"}


class ExpansionBlocked(RuntimeError):
    pass


def readiness(db) -> dict:
    from .maturity import assess

    return assess(db)


def require_ready(db, capability: str) -> dict:
    if capability not in CAPABILITIES:
        raise ValueError(f"unknown expansion capability: {capability}")
    result = readiness(db)
    if not result["expansion_ready"]:
        blockers = [check["name"] for check in result["checks"] if not check["passed"]]
        raise ExpansionBlocked(
            f"{capability} is blocked by the maturity gate: {', '.join(blockers)}"
        )
    return result
