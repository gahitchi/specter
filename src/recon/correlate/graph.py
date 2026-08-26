"""Identity graph construction over the Store.

correlate_run() rebuilds the target's identity clusters from all its accumulated
observations: blocking -> probabilistic scoring -> union-find merge of MERGE
pairs, REVIEW pairs recorded as edges (never silently merged). Persists Entity
nodes, links observations, and computes coherence flags + confidence.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import delete, select

from ..evidence import confirmation_satisfied
from ..models import Query
from ..store import models_db as m
from ..store import repo
from ..trust import corroboration
from . import coherence, confidence
from .blocking import candidate_pairs
from .cluster import _UF
from .cluster import identity_bearing
from .resolver import Record, classify, record_from, score


def _merge_attributes(records: list[Record]) -> dict:
    emails, usernames, names = set(), set(), set()
    strong: dict[str, set] = defaultdict(set)
    for r in records:
        emails |= r.emails
        usernames |= r.usernames
        names |= r.names
        for k, vs in r.strong.items():
            strong[k] |= vs
    attrs: dict[str, list] = {}
    if emails:
        attrs["email"] = sorted(emails)
    if usernames:
        attrs["username"] = sorted(usernames)
    if names:
        attrs["name"] = sorted(names)
    for k, vs in strong.items():
        if k != "email":
            attrs[k] = sorted(vs)
    return attrs


def _label(attrs: dict) -> str:
    for k in ("name", "email", "username", "phone_e164"):
        if attrs.get(k):
            return str(attrs[k][0])
    return "identity"


def _resolve_conflicts(records: list, observations: list) -> dict:
    """Conflict resolution (#3): when one strong identifier has multiple values in
    a cluster, pick the canonical one from the highest-reliability, then
    highest-confidence, observation that asserts it. Returns {attr: canonical}.
    """
    from .resolver import STRONG

    # value -> best (reliability, confidence) seen among observations asserting it
    best: dict[str, dict[str, tuple[float, float]]] = {}
    for o in observations:
        rel = o.reliability or 0.5
        for k, v in (o.signals or {}).items():
            base = k.split(":", 1)[0]
            if base not in STRONG or not v:
                continue
            vv = v.lower()
            cur = best.setdefault(base, {}).get(vv, (-1.0, -1.0))
            best[base][vv] = max(cur, (rel, o.confidence))

    canonical: dict[str, str] = {}
    for attr, values in best.items():
        if len(values) > 1:  # only meaningful when there's a conflict
            canonical[attr] = max(values.items(), key=lambda kv: kv[1])[0]
    return canonical


def correlate_run(db, run_id: int) -> dict:
    from ..config import SETTINGS

    identity_model = None
    if SETTINGS.expansion_requested and SETTINGS.ml_model_file:
        from ..expansion import require_ready
        from ..ml_identity import load_model

        require_ready(db, "ml_identity")
        identity_model = load_model(SETTINGS.ml_model_file)
    with db.session() as s:
        run = s.get(m.Run, run_id)
        target_id = run.target_id
        target = s.get(m.Target, target_id)
        query = Query.model_validate(target.query)
        target_observations = repo.observations_for_target(s, target_id, hits_only=True)
        obs = [
            observation
            for observation in target_observations
            if identity_bearing(observation.category)
            and confirmation_satisfied(observation, target_observations, query)
        ]

        records = [record_from(o.id, o.category, o.label, o.signals) for o in obs]
        obs_by_oid = {o.id: o for o in obs}

        # --- clear prior correlation for this target (rebuild is deterministic) ---
        linked_observations = list(
            s.execute(
                select(m.Observation).where(
                    m.Observation.target_id == target_id,
                    m.Observation.entity_id.is_not(None),
                )
            )
            .scalars()
            .all()
        )
        old_ids = sorted({o.entity_id for o in linked_observations if o.entity_id is not None})
        for observation in linked_observations:
            observation.entity_id = None
        s.flush()
        if old_ids:
            s.execute(
                delete(m.EntityEdge).where(
                    m.EntityEdge.src_id.in_(old_ids) | m.EntityEdge.dst_id.in_(old_ids)
                )
            )
            s.execute(delete(m.Entity).where(m.Entity.id.in_(old_ids)))

        # --- score candidate pairs, merge / mark for review ---
        uf = _UF()
        for i in range(len(records)):
            uf.find(str(i))
        review: list[tuple[int, int, float, list[str], dict | None]] = []
        for i, j in candidate_pairs(records):
            w, reasons = score(records[i], records[j])
            decision = classify(w)
            ml_result = None
            if identity_model is not None:
                from ..ml_identity import pair_features

                ml_result = identity_model.predict(
                    pair_features(obs_by_oid[records[i].obs_id], obs_by_oid[records[j].obs_id])
                )
            if decision == "MERGE":
                left_root, right_root = uf.find(str(i)), uf.find(str(j))
                combined = [
                    records[index]
                    for index in range(len(records))
                    if uf.find(str(index)) in {left_root, right_root}
                ]
                merge_flags = coherence.check(combined)
                if merge_flags:
                    review.append(
                        (i, j, w, [*reasons, *[f"blocked by {flag}" for flag in merge_flags]], ml_result)
                    )
                else:
                    uf.union(str(i), str(j))
            elif decision == "REVIEW" or (
                ml_result is not None and ml_result["suggest_same_identity"]
            ):
                review.append((i, j, w, reasons, ml_result))

        clusters: dict[str, list[int]] = defaultdict(list)
        for i in range(len(records)):
            clusters[uf.find(str(i))].append(i)

        # --- persist entities ---
        idx_to_entity: dict[int, int] = {}
        summary_clusters = []
        for idxs in clusters.values():
            recs = [records[k] for k in idxs]
            cl_obs = [obs_by_oid[records[k].obs_id] for k in idxs]
            flags = coherence.check(recs)
            cluster_observation_ids = {observation.id for observation in cl_obs}
            contradictions = list(
                s.execute(
                    select(m.ObservationContradiction).where(
                        (
                            m.ObservationContradiction.earlier_observation_id.in_(
                                cluster_observation_ids
                            )
                        )
                        | (
                            m.ObservationContradiction.later_observation_id.in_(
                                cluster_observation_ids
                            )
                        )
                    )
                )
                .scalars()
                .all()
            )
            for contradiction in contradictions:
                flag = f"evidence-contradiction:{contradiction.kind}"
                if flag not in flags:
                    flags.append(flag)
            attrs = _merge_attributes(recs)
            canonical = _resolve_conflicts(recs, cl_obs)
            if canonical:
                attrs["_canonical"] = canonical  # winning value per conflicted id
            bd = confidence.entity_confidence(cl_obs, flags)
            conf = bd.total
            ent = m.Entity(
                label=_label(attrs),
                attributes=attrs,
                confidence=conf,
                breakdown=bd.model_dump(),
                flags=flags,
            )
            s.add(ent)
            s.flush()
            for k in idxs:
                idx_to_entity[k] = ent.id
                obs_by_oid[records[k].obs_id].entity_id = ent.id
            summary_clusters.append(
                {
                    "id": ent.id,
                    "label": ent.label,
                    "score": conf,
                    "confidence_shadow": bd.shadow_total,
                    "breakdown": bd.model_dump(),
                    "signals": attrs,
                    "flags": flags,
                    "corroboration": corroboration(cl_obs),
                    "contradictions": len(contradictions),
                    "found": sum(1 for o in cl_obs if o.verdict == "FOUND"),
                    "uncertain": sum(1 for o in cl_obs if o.verdict == "UNCERTAIN"),
                    "sources": sorted({o.source for o in cl_obs}),
                }
            )

        # --- REVIEW edges between the resulting (distinct) entities ---
        for i, j, w, reasons, ml_result in review:
            ei, ej = idx_to_entity[i], idx_to_entity[j]
            if ei != ej:
                detail = {"reasons": reasons}
                if ml_result is not None:
                    detail["ml_suggestion"] = ml_result
                s.add(m.EntityEdge(src_id=ei, dst_id=ej, kind="review", weight=w, detail=detail))

        summary_clusters.sort(key=lambda c: -c["score"])
        return {
            "identities": len(summary_clusters),
            "clusters": summary_clusters,
            "ml_review_assist": identity_model is not None,
        }
