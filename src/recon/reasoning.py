"""Auditable investigation planning over the evolving discovery graph.

The planner is deliberately evidence-bound: it may reorder already-authorized
module dispatches and recommend a next action, but it cannot create findings,
broaden scope, enable active collection, or increase a request budget.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, Field

from .graph_models import Artifact, ArtifactType
from .models import Finding, Query, Verdict

ExecutionMode = Literal["automatic", "manual", "approval"]
ActionStatus = Literal["ready", "needs_review", "blocked"]
Priority = Literal["critical", "high", "medium", "low"]


class NextAction(BaseModel):
    id: str
    title: str
    rationale: str
    priority: Priority
    execution: ExecutionMode
    status: ActionStatus = "ready"
    confidence: float = Field(ge=0.0, le=1.0)
    requires: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)


class ReasoningReport(BaseModel):
    version: int = 1
    objective: str
    assessment: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_state: dict[str, Any]
    uncertainties: list[str] = Field(default_factory=list)
    next_actions: list[NextAction] = Field(default_factory=list)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    guardrails: list[str] = Field(default_factory=list)


_TYPE_VALUE = {
    ArtifactType.EMAIL: 100,
    ArtifactType.ACCOUNT_PROFILE: 90,
    ArtifactType.DOMAIN: 80,
    ArtifactType.USERNAME: 75,
    ArtifactType.SUBDOMAIN: 60,
    ArtifactType.HOSTNAME: 55,
    ArtifactType.MX_HOST: 50,
    ArtifactType.NAMESERVER: 45,
    ArtifactType.URL: 40,
    ArtifactType.LINK: 38,
    ArtifactType.IP_ADDRESS: 35,
    ArtifactType.NETBLOCK: 30,
    ArtifactType.ASN: 28,
    ArtifactType.BREACH: 25,
    ArtifactType.HASH: 20,
    ArtifactType.PHONE: 15,
    ArtifactType.NAME: 10,
}
_IDENTITY_OUTPUTS = {
    ArtifactType.EMAIL,
    ArtifactType.USERNAME,
    ArtifactType.ACCOUNT_PROFILE,
    ArtifactType.HASH,
}
_PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _objective(findings: list[Finding]) -> str:
    if not findings:
        return "Establish initial evidence"
    counts = Counter(finding.verdict for finding in findings)
    if counts[Verdict.FOUND] == 0:
        if counts[Verdict.ERROR] + counts[Verdict.UNVERIFIABLE]:
            return "Recover evidence coverage"
        return "Verify the supplied identifiers"
    if counts[Verdict.UNCERTAIN] + counts[Verdict.UNVERIFIABLE]:
        return "Resolve ambiguous evidence"
    return "Corroborate confirmed evidence"


class InvestigationReasoner:
    """Ranks authorized work and synthesizes an evidence-bound next-step plan."""

    def __init__(self) -> None:
        self.decisions: list[dict[str, Any]] = []

    @staticmethod
    def _dispatch_score(
        artifact: Artifact,
        module: Any,
        *,
        seen_types: set[ArtifactType],
        findings: list[Finding],
    ) -> tuple[float, list[str]]:
        found = sum(finding.verdict == Verdict.FOUND for finding in findings)
        base = float(_TYPE_VALUE.get(artifact.type, 0))
        reliability = float(module.reliability_prior) * 12.0
        output_value = max((_TYPE_VALUE.get(kind, 0) for kind in module.produces), default=0)
        novelty = 12.0 if module.produces - seen_types else 0.0
        identity_gain = 10.0 if found and module.produces & _IDENTITY_OUTPUTS else 0.0
        seed_verification = 8.0 if not found and artifact.depth == 0 else 0.0
        depth_cost = artifact.depth * 2.0
        score = (
            base + reliability + output_value * 0.2 + novelty + identity_gain
            + seed_verification + artifact.confidence * 5.0 - depth_cost
        )
        reasons = [f"{artifact.type.value} lead value {base:.0f}"]
        if novelty:
            reasons.append("may add a new evidence type")
        if identity_gain:
            reasons.append("can corroborate identity-bearing evidence")
        if seed_verification:
            reasons.append("directly tests a supplied identifier")
        reasons.append(f"source prior {module.reliability_prior:.2f}")
        return round(score, 2), reasons

    def rank_dispatches(
        self,
        frontier: list[Artifact],
        dispatches: list[tuple[Artifact, Any]],
        findings: list[Finding],
        artifacts: list[Artifact],
        remaining_requests: int,
    ) -> list[tuple[Artifact, Any]]:
        seen_types = {artifact.type for artifact in artifacts}
        ranked: list[tuple[float, int, Artifact, Any, list[str]]] = []
        for index, (artifact, module) in enumerate(dispatches):
            score, reasons = self._dispatch_score(
                artifact, module, seen_types=seen_types, findings=findings
            )
            ranked.append((score, -index, artifact, module, reasons))
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        self.decisions.append({
            "wave": len(self.decisions) + 1,
            "objective": _objective(findings),
            "frontier_size": len(frontier),
            "candidate_dispatches": len(dispatches),
            "remaining_requests": max(0, remaining_requests),
            "prioritized": [
                {
                    "artifact": artifact.key,
                    "module": module.name,
                    "score": score,
                    "reasons": reasons,
                }
                for score, _index, artifact, module, reasons in ranked[:8]
            ],
        })
        return [(artifact, module) for _score, _index, artifact, module, _reasons in ranked]

    def report(
        self,
        query: Query,
        findings: list[Finding],
        artifacts: list[Artifact],
        summary: dict[str, Any],
        *,
        stop_reason: str | None,
        scope_mode: str,
        passive_only: bool,
        out_of_scope: list[Artifact],
    ) -> dict[str, Any]:
        verdicts = Counter(finding.verdict.value for finding in findings)
        artifact_types = Counter(artifact.type.value for artifact in artifacts)
        found = [finding for finding in findings if finding.verdict == Verdict.FOUND]
        distinct_sources = sorted({finding.source for finding in found})
        clusters = summary.get("clusters") or []
        independent_classes = max(
            (
                int((cluster.get("corroboration") or {}).get("independent_classes", 0))
                for cluster in clusters
            ),
            default=0,
        )
        if found:
            evidence_confidence = sum(finding.confidence for finding in found) / len(found)
            corroboration_factor = min(1.0, 0.7 + 0.1 * max(0, independent_classes - 1))
            confidence = round(evidence_confidence * corroboration_factor, 2)
        else:
            confidence = 0.2 if findings else 0.1

        if found and independent_classes >= 2:
            assessment = (
                f"{len(found)} confirmed finding(s) are supported by "
                f"{independent_classes} independent evidence classes."
            )
        elif found:
            assessment = (
                f"{len(found)} finding(s) are confirmed, but corroboration is still limited."
            )
        elif findings:
            assessment = "The scan produced evidence, but none of it is confirmed yet."
        else:
            assessment = "The scan produced no evidence to support a conclusion."

        uncertainties: list[str] = []
        if verdicts[Verdict.UNCERTAIN.value]:
            uncertainties.append(
                f"{verdicts[Verdict.UNCERTAIN.value]} candidate finding(s) need review."
            )
        blocked = verdicts[Verdict.UNVERIFIABLE.value]
        errors = verdicts[Verdict.ERROR.value]
        if blocked:
            uncertainties.append(f"{blocked} source result(s) were blocked or unverifiable.")
        if errors:
            uncertainties.append(f"{errors} source check(s) failed.")
        if found and independent_classes < 2:
            uncertainties.append("Confirmed evidence lacks independent corroboration.")
        if stop_reason:
            uncertainties.append(f"Traversal stopped because {stop_reason}.")
        if out_of_scope:
            uncertainties.append(
                f"{len(out_of_scope)} discovered pivot(s) were recorded but not followed."
            )

        actions: dict[str, NextAction] = {}

        def add(action: NextAction) -> None:
            existing = actions.get(action.id)
            if existing is None or _PRIORITY_RANK[action.priority] > _PRIORITY_RANK[existing.priority]:
                actions[action.id] = action

        if not found:
            add(NextAction(
                id="refine-identifiers",
                title="Add a verified identifier",
                rationale=(
                    "No confirmed evidence was found; another known identifier can reduce ambiguity "
                    "without broadening scope."
                ),
                priority="high",
                execution="manual",
                status="needs_review",
                confidence=0.91,
                requires=[
                    "a verified username, email, domain, phone, name, public URL, or IP"
                ],
            ))
        if verdicts[Verdict.UNCERTAIN.value]:
            add(NextAction(
                id="review-candidates",
                title="Review ambiguous candidates",
                rationale="Candidate findings should be accepted or rejected before identity conclusions change.",
                priority="high",
                execution="manual",
                status="needs_review",
                confidence=0.95,
                inputs=[finding.source for finding in findings if finding.verdict == Verdict.UNCERTAIN][:5],
            ))
        if blocked or errors:
            add(NextAction(
                id="retry-degraded-sources",
                title="Retry degraded sources",
                rationale="Blocked and failed checks leave material gaps in evidence coverage.",
                priority="high" if not found else "medium",
                execution="automatic",
                status="blocked",
                confidence=0.88,
                requires=["source circuit closed", "request budget available"],
                inputs=[
                    finding.source for finding in findings
                    if finding.verdict in {Verdict.ERROR, Verdict.UNVERIFIABLE}
                ][:5],
            ))
        if found and independent_classes < 2:
            add(NextAction(
                id="corroborate-findings",
                title="Seek independent corroboration",
                rationale="A separate evidence class is needed before treating the identity link as dependable.",
                priority="high",
                execution="automatic",
                status="blocked",
                confidence=0.93,
                requires=["passive source with an independent evidence class"],
                inputs=distinct_sources[:5],
            ))
        conflicting = [cluster for cluster in clusters if cluster.get("flags")]
        if conflicting:
            add(NextAction(
                id="resolve-conflicts",
                title="Resolve identity conflicts",
                rationale="The correlation graph contains conflicting attributes or a review boundary.",
                priority="critical",
                execution="manual",
                status="needs_review",
                confidence=0.98,
                inputs=[str(cluster.get("id")) for cluster in conflicting[:5]],
            ))
        if stop_reason:
            add(NextAction(
                id="continue-bounded-scan",
                title="Continue with a revised limit",
                rationale=f"Useful work may remain because the scan stopped at {stop_reason}.",
                priority="high",
                execution="approval",
                status="needs_review",
                confidence=0.86,
                requires=["investigator approval", "revised bounded limit"],
            ))
        if out_of_scope:
            add(NextAction(
                id="review-scope-pivots",
                title="Review out-of-scope pivots",
                rationale="External pivots were retained as leads but strict scope prevented collection.",
                priority="medium",
                execution="approval",
                status="needs_review",
                confidence=0.9,
                requires=["documented authorization before scope expansion"],
                inputs=[artifact.key for artifact in out_of_scope[:5]],
            ))
        if found and independent_classes >= 2:
            add(NextAction(
                id="monitor-confirmed-evidence",
                title="Monitor confirmed evidence",
                rationale="Corroborated evidence is suitable for bounded change monitoring.",
                priority="low",
                execution="automatic",
                status="blocked",
                confidence=0.82,
                requires=["watchlist schedule"],
            ))
        if not actions:
            add(NextAction(
                id="review-completed-scan",
                title="Review the completed scan",
                rationale="No automatic continuation has higher expected value than investigator review.",
                priority="medium",
                execution="manual",
                status="needs_review",
                confidence=0.8,
            ))

        seed_fields = [
            field for field in (
                "username", "email", "phone", "domain", "name", "url", "ip_address"
            )
            if getattr(query, field)
        ]
        report = ReasoningReport(
            objective=_objective(findings),
            assessment=assessment,
            confidence=confidence,
            evidence_state={
                "seed_fields": seed_fields,
                "findings": len(findings),
                "verdicts": dict(sorted(verdicts.items())),
                "artifacts": len(artifacts),
                "artifact_types": dict(sorted(artifact_types.items())),
                "confirmed_sources": distinct_sources,
                "independent_classes": independent_classes,
                "out_of_scope_pivots": len(out_of_scope),
                "stop_reason": stop_reason,
            },
            uncertainties=uncertainties,
            next_actions=sorted(
                actions.values(),
                key=lambda action: (-_PRIORITY_RANK[action.priority], action.id),
            ),
            decisions=self.decisions,
            guardrails=[
                f"Scope remained {scope_mode}.",
                "Only already-enabled modules were considered.",
                (
                    "Only passive collection was allowed."
                    if passive_only else "Active collection was explicitly enabled for this scan."
                ),
                "Reasoning changed priority, never evidence or confidence scores.",
            ],
        )
        return report.model_dump()
