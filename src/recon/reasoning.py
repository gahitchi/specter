"""Auditable investigation planning over the evolving discovery graph.

The planner is deliberately evidence-bound: it may reorder already-authorized
module dispatches and recommend a next action, but it cannot create findings,
broaden scope, enable active collection, or increase a request budget.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, Field

from .evidence import confirmation_satisfied
from .graph_models import Artifact, ArtifactType
from .models import Finding, Query, Verdict

ExecutionMode = Literal["automatic", "manual", "approval"]
ActionStatus = Literal["ready", "needs_review", "blocked"]
Priority = Literal["critical", "high", "medium", "low"]

NEXT_ACTION_IDS = frozenset({
    "refine-identifiers",
    "review-candidates",
    "retry-degraded-sources",
    "corroborate-findings",
    "resolve-conflicts",
    "continue-bounded-scan",
    "review-scope-pivots",
    "review-policy-blocked-leads",
    "review-phone-conflicts",
    "corroborate-phone-association",
    "monitor-confirmed-evidence",
    "review-completed-scan",
})
STOP_CODES = frozenset({
    "diminishing_returns",
    "bounded_limit_reached",
    "authorized_frontier_exhausted",
    "continue_expected_value",
})


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
    expected_value: dict[str, float] = Field(default_factory=dict)


class StopDecision(BaseModel):
    code: str
    stop: bool
    terminal: bool
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    triggers: dict[str, Any] = Field(default_factory=dict)


class ReasoningReport(BaseModel):
    version: int = 2
    objective: str
    assessment: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_state: dict[str, Any]
    uncertainties: list[str] = Field(default_factory=list)
    next_actions: list[NextAction] = Field(default_factory=list)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    stop_decision: StopDecision
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
    ArtifactType.PHONE: 95,
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
    confirming = sum(confirmation_satisfied(finding, findings) for finding in findings)
    if confirming == 0:
        if counts[Verdict.ERROR] + counts[Verdict.UNVERIFIABLE]:
            return "Recover evidence coverage"
        return "Verify the supplied identifiers"
    if counts[Verdict.UNCERTAIN] + counts[Verdict.UNVERIFIABLE]:
        return "Resolve ambiguous evidence"
    return "Corroborate identity evidence"


class InvestigationReasoner:
    """Ranks authorized work and synthesizes an evidence-bound next-step plan."""

    def __init__(self) -> None:
        self.decisions: list[dict[str, Any]] = []
        self.low_yield_waves = 0

    @staticmethod
    def _dispatch_score(
        artifact: Artifact,
        module: Any,
        *,
        seen_types: set[ArtifactType],
        findings: list[Finding],
    ) -> tuple[float, dict[str, float], list[str]]:
        found = sum(confirmation_satisfied(finding, findings) for finding in findings)
        base = float(_TYPE_VALUE.get(artifact.type, 0)) / 100.0
        reliability = float(module.reliability_prior)
        output_value = (
            max((_TYPE_VALUE.get(kind, 0) for kind in module.produces), default=0) / 100.0
        )
        novelty = 1.0 if module.produces - seen_types else 0.0
        identity_gain = 1.0 if found and module.produces & _IDENTITY_OUTPUTS else 0.0
        seed_verification = 1.0 if not found and artifact.depth == 0 else 0.0
        policy = getattr(module, "evidence_policy", None)
        candidate_only = bool(policy is not None and policy.candidate_only)
        request_cost = max(1, int(getattr(module, "estimated_request_cost", 1)))
        active_risk = 0.35 if not getattr(module, "passive", True) else 0.0
        depth_risk = min(0.3, artifact.depth * 0.08)
        policy_risk = 0.25 if candidate_only else 0.0
        information_gain = min(
            1.0,
            0.25 * base
            + 0.25 * output_value
            + 0.2 * novelty
            + 0.15 * identity_gain
            + 0.15 * seed_verification,
        )
        evidence_quality = min(1.0, 0.7 * reliability + 0.3 * artifact.confidence)
        cost = min(1.0, request_cost / 6.0)
        risk = min(1.0, active_risk + depth_risk + policy_risk)
        utility = (
            0.52 * information_gain
            + 0.34 * evidence_quality
            + 0.08 * novelty
            - 0.04 * cost
            - 0.18 * risk
        )
        dimensions = {
            "information_gain": round(information_gain, 3),
            "evidence_quality": round(evidence_quality, 3),
            "novelty": round(novelty, 3),
            "cost": round(cost, 3),
            "risk": round(risk, 3),
            "utility": round(utility, 3),
        }
        reasons = [f"{artifact.type.value} can reduce a material evidence gap"]
        if novelty:
            reasons.append("may add a new evidence type")
        if identity_gain:
            reasons.append("can corroborate identity-bearing evidence")
        if seed_verification:
            reasons.append("directly tests a supplied identifier")
        if candidate_only:
            reasons.append("candidate-only output cannot pivot automatically")
        if request_cost > 1:
            reasons.append(f"estimated request cost {request_cost}")
        reasons.append(f"source quality prior {module.reliability_prior:.2f}")
        return round(utility, 3), dimensions, reasons

    def rank_dispatches(
        self,
        frontier: list[Artifact],
        dispatches: list[tuple[Artifact, Any]],
        findings: list[Finding],
        artifacts: list[Artifact],
        remaining_requests: int,
    ) -> list[tuple[Artifact, Any]]:
        seen_types = {artifact.type for artifact in artifacts}
        ranked: list[tuple[float, int, Artifact, Any, dict[str, float], list[str]]] = []
        for index, (artifact, module) in enumerate(dispatches):
            score, dimensions, reasons = self._dispatch_score(
                artifact, module, seen_types=seen_types, findings=findings
            )
            ranked.append((score, -index, artifact, module, dimensions, reasons))
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        self.decisions.append(
            {
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
                        "expected_value": dimensions,
                        "reasons": reasons,
                    }
                    for score, _index, artifact, module, dimensions, reasons in ranked[:8]
                ],
                "deferred": [
                    {
                        "artifact": artifact.key,
                        "module": module.name,
                        "score": score,
                        "reason": "lower expected value than the prioritized work",
                    }
                    for score, _index, artifact, module, _dimensions, _reasons in ranked[8:16]
                ],
            }
        )
        return [
            (artifact, module) for _score, _index, artifact, module, _dimensions, _reasons in ranked
        ]

    def complete_wave(self, *, new_findings: int, new_artifacts: int, requests_used: int) -> None:
        """Record observed yield so later decisions can detect diminishing returns."""
        if not self.decisions:
            return
        decision = self.decisions[-1]
        decision["outcome"] = {
            "new_findings": max(0, new_findings),
            "new_artifacts": max(0, new_artifacts),
            "requests_used": max(0, requests_used),
        }
        low_yield = new_findings == 0 and new_artifacts == 0 and requests_used > 0
        self.low_yield_waves = self.low_yield_waves + 1 if low_yield else 0
        decision["low_yield"] = low_yield

    def stop_decision(
        self,
        *,
        stop_reason: str | None,
        frontier_exhausted: bool = True,
        unresolved: int = 0,
    ) -> StopDecision:
        if stop_reason == "diminishing returns":
            return StopDecision(
                code="diminishing_returns",
                stop=True,
                terminal=True,
                rationale=(
                    "Repeated request waves produced no new evidence or artifacts; "
                    "more automatic collection has low expected value."
                ),
                confidence=0.9,
                triggers={"low_yield_waves": max(2, self.low_yield_waves)},
            )
        if stop_reason:
            return StopDecision(
                code="bounded_limit_reached",
                stop=True,
                terminal=False,
                rationale=(
                    f"Automatic collection stopped because {stop_reason}; continuing requires "
                    "an explicit bounded-limit decision."
                ),
                confidence=0.98,
                triggers={"limit": stop_reason},
            )
        if self.low_yield_waves >= 2:
            return StopDecision(
                code="diminishing_returns",
                stop=True,
                terminal=True,
                rationale=(
                    "Two consecutive request waves produced no new evidence or artifacts; "
                    "more automatic collection has low expected value."
                ),
                confidence=0.9,
                triggers={"low_yield_waves": self.low_yield_waves},
            )
        if frontier_exhausted:
            return StopDecision(
                code="authorized_frontier_exhausted",
                stop=True,
                terminal=unresolved == 0,
                rationale=(
                    "Every authorized lead was processed."
                    if unresolved == 0
                    else "Every authorized lead was processed; unresolved evidence now needs review."
                ),
                confidence=0.96,
                triggers={"unresolved_findings": unresolved},
            )
        return StopDecision(
            code="continue_expected_value",
            stop=False,
            terminal=False,
            rationale="Authorized work remains with positive expected information value.",
            confidence=0.8,
        )

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
        observed = [finding for finding in findings if finding.verdict == Verdict.FOUND]
        found = [
            finding
            for finding in observed
            if confirmation_satisfied(finding, observed, query)
        ]
        distinct_sources = sorted({finding.source for finding in found})
        policy_blocked = [
            artifact
            for artifact in artifacts
            if artifact.depth > 0
            and not (artifact.data.get("promotion") or {}).get("allowed", True)
        ]
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
                f"{len(found)} identity-supporting finding(s) are backed by "
                f"{independent_classes} independent evidence classes."
            )
        elif found:
            assessment = (
                f"{len(found)} finding(s) can support identity, but corroboration is still limited."
            )
        elif observed:
            assessment = (
                "The scan produced positive metadata or contextual observations, but no evidence "
                "is eligible to establish an identity link."
            )
        elif findings:
            assessment = "The scan produced evidence, but none can support identity yet."
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
            uncertainties.append("Identity-supporting evidence lacks independent corroboration.")
        if observed and not found:
            uncertainties.append(
                "Observed metadata or page mentions do not establish a person-level association."
            )
        if stop_reason:
            uncertainties.append(f"Traversal stopped because {stop_reason}.")
        if out_of_scope:
            uncertainties.append(
                f"{len(out_of_scope)} discovered pivot(s) were recorded but not followed."
            )
        if policy_blocked:
            uncertainties.append(
                f"{len(policy_blocked)} candidate or uncorroborated lead(s) were retained "
                "without automatic expansion."
            )

        actions: dict[str, NextAction] = {}

        def add(action: NextAction) -> None:
            if action.execution == "automatic" and not action.expected_value:
                information_gain = {
                    "critical": 0.9,
                    "high": 0.8,
                    "medium": 0.6,
                    "low": 0.35,
                }[action.priority]
                action.expected_value = {
                    "information_gain": information_gain,
                    "evidence_quality": action.confidence,
                    "cost": 0.35,
                    "risk": 0.15 if passive_only else 0.4,
                    "utility": round(
                        0.52 * information_gain
                        + 0.34 * action.confidence
                        - 0.04 * 0.35
                        - 0.18 * (0.15 if passive_only else 0.4),
                        3,
                    ),
                }
            existing = actions.get(action.id)
            if (
                existing is None
                or _PRIORITY_RANK[action.priority] > _PRIORITY_RANK[existing.priority]
            ):
                actions[action.id] = action

        if not found:
            add(
                NextAction(
                    id="refine-identifiers",
                    title="Add a verified identifier",
                    rationale=(
                        "No identity-supporting evidence was found; another known identifier can reduce ambiguity "
                        "without broadening scope."
                    ),
                    priority="high",
                    execution="manual",
                    status="needs_review",
                    confidence=0.91,
                    requires=["a verified username, email, domain, phone, name, public URL, or IP"],
                )
            )
        if verdicts[Verdict.UNCERTAIN.value]:
            add(
                NextAction(
                    id="review-candidates",
                    title="Review ambiguous candidates",
                    rationale="Candidate findings should be accepted or rejected before identity conclusions change.",
                    priority="high",
                    execution="manual",
                    status="needs_review",
                    confidence=0.95,
                    inputs=[
                        finding.source
                        for finding in findings
                        if finding.verdict == Verdict.UNCERTAIN
                    ][:5],
                )
            )
        if blocked or errors:
            add(
                NextAction(
                    id="retry-degraded-sources",
                    title="Retry degraded sources",
                    rationale="Blocked and failed checks leave material gaps in evidence coverage.",
                    priority="high" if not found else "medium",
                    execution="automatic",
                    status="blocked",
                    confidence=0.88,
                    requires=["source circuit closed", "request budget available"],
                    inputs=[
                        finding.source
                        for finding in findings
                        if finding.verdict in {Verdict.ERROR, Verdict.UNVERIFIABLE}
                    ][:5],
                )
            )
        if found and independent_classes < 2:
            add(
                NextAction(
                    id="corroborate-findings",
                    title="Seek independent corroboration",
                    rationale="A separate evidence class is needed before treating the identity link as dependable.",
                    priority="high",
                    execution="automatic",
                    status="blocked",
                    confidence=0.93,
                    requires=["passive source with an independent evidence class"],
                    inputs=distinct_sources[:5],
                )
            )
        conflicting = [cluster for cluster in clusters if cluster.get("flags")]
        if conflicting:
            add(
                NextAction(
                    id="resolve-conflicts",
                    title="Resolve identity conflicts",
                    rationale="The correlation graph contains conflicting attributes or a review boundary.",
                    priority="critical",
                    execution="manual",
                    status="needs_review",
                    confidence=0.98,
                    inputs=[str(cluster.get("id")) for cluster in conflicting[:5]],
                )
            )
        if stop_reason:
            add(
                NextAction(
                    id="continue-bounded-scan",
                    title="Continue with a revised limit",
                    rationale=f"Useful work may remain because the scan stopped at {stop_reason}.",
                    priority="high",
                    execution="approval",
                    status="needs_review",
                    confidence=0.86,
                    requires=["investigator approval", "revised bounded limit"],
                )
            )
        if out_of_scope:
            add(
                NextAction(
                    id="review-scope-pivots",
                    title="Review out-of-scope pivots",
                    rationale="External pivots were retained as leads but strict scope prevented collection.",
                    priority="medium",
                    execution="approval",
                    status="needs_review",
                    confidence=0.9,
                    requires=["documented authorization before scope expansion"],
                    inputs=[artifact.key for artifact in out_of_scope[:5]],
                )
            )
        if policy_blocked:
            add(
                NextAction(
                    id="review-policy-blocked-leads",
                    title="Review guarded leads",
                    rationale=(
                        "Candidate and single-origin leads remain visible but cannot steer "
                        "automatic collection without corroboration or review."
                    ),
                    priority="medium",
                    execution="manual",
                    status="needs_review",
                    confidence=0.96,
                    inputs=[artifact.key for artifact in policy_blocked[:5]],
                )
            )
        phone_research = (
            (summary.get("profile") or {}).get("phone_research") if query.phone else None
        )
        phone_decision = (phone_research or {}).get("decision") or {}
        if phone_decision.get("status") == "manual_review":
            add(
                NextAction(
                    id="review-phone-conflicts",
                    title="Review phone-association conflicts",
                    rationale=phone_decision.get("recommended_action", ""),
                    priority="critical",
                    execution="manual",
                    status="needs_review",
                    confidence=0.98,
                    inputs=["phone lifecycle", "conflicting names or emails"],
                )
            )
        elif phone_decision.get("status") == "needs_corroboration":
            add(
                NextAction(
                    id="corroborate-phone-association",
                    title="Corroborate the phone association",
                    rationale=phone_decision.get("recommended_action", ""),
                    priority="high",
                    execution="automatic",
                    status="blocked",
                    confidence=0.95,
                    requires=["another independent direct public page"],
                )
            )
        if found and independent_classes >= 2:
            add(
                NextAction(
                    id="monitor-confirmed-evidence",
                    title="Monitor confirmed evidence",
                    rationale="Corroborated evidence is suitable for bounded change monitoring.",
                    priority="low",
                    execution="automatic",
                    status="blocked",
                    confidence=0.82,
                    requires=["watchlist schedule"],
                )
            )
        if not actions:
            add(
                NextAction(
                    id="review-completed-scan",
                    title="Review the completed scan",
                    rationale="No automatic continuation has higher expected value than investigator review.",
                    priority="medium",
                    execution="manual",
                    status="needs_review",
                    confidence=0.8,
                )
            )

        seed_fields = [
            field
            for field in ("username", "email", "phone", "domain", "name", "url", "ip_address")
            if getattr(query, field)
        ]
        report = ReasoningReport(
            objective=_objective(findings),
            assessment=assessment,
            confidence=confidence,
            evidence_state={
                "seed_fields": seed_fields,
                "findings": len(findings),
                "observed_findings": len(observed),
                "confirmation_satisfied_findings": len(found),
                # Kept for report-schema compatibility; semantics are now strict.
                "confirmation_eligible_findings": len(found),
                "verdicts": dict(sorted(verdicts.items())),
                "artifacts": len(artifacts),
                "artifact_types": dict(sorted(artifact_types.items())),
                "confirmed_sources": distinct_sources,
                "independent_classes": independent_classes,
                "out_of_scope_pivots": len(out_of_scope),
                "policy_blocked_pivots": len(policy_blocked),
                "stop_reason": stop_reason,
            },
            uncertainties=uncertainties,
            next_actions=sorted(
                actions.values(),
                key=lambda action: (-_PRIORITY_RANK[action.priority], action.id),
            ),
            decisions=self.decisions,
            stop_decision=self.stop_decision(
                stop_reason=stop_reason,
                unresolved=(
                    verdicts[Verdict.UNCERTAIN.value]
                    + verdicts[Verdict.UNVERIFIABLE.value]
                    + verdicts[Verdict.ERROR.value]
                    + len(policy_blocked)
                ),
            ),
            guardrails=[
                f"Scope remained {scope_mode}.",
                "Only already-enabled modules were considered.",
                (
                    "Only passive collection was allowed."
                    if passive_only
                    else "Active collection was explicitly enabled for this scan."
                ),
                "Reasoning changed priority, never evidence or confidence scores.",
                "Candidate-only and uncorroborated leads did not expand automatically.",
                "Automatic work stopped when authorized leads or expected value were exhausted.",
            ],
        )
        return report.model_dump()
