"""Change detection between a run and the target's previous finished run.

Emits ChangeEvents: accounts that appeared/disappeared, and profiles whose
content fingerprint (Evidence SimHash, carried on the observation) changed.
This is what makes long-term monitoring actionable.
"""

from __future__ import annotations

from ..correlate.cluster import identity_bearing
from ..evidence import confirmation_satisfied
from ..models import Query
from ..store import models_db as m
from ..store import repo
from ..verify.similarity import similarity_hex


def _key(o: m.Observation) -> tuple[str, str]:
    return (o.source, o.label)


def diff_run(db, target_id: int, run_id: int) -> list[dict]:
    with db.session() as s:
        prev = repo.latest_finished_run(s, target_id, before_run_id=run_id)
        target = s.get(m.Target, target_id)
        query = Query.model_validate(target.query)
        cur_all = repo.observations_for_run(s, run_id, hits_only=True)
        cur_obs = [
            observation
            for observation in cur_all
            if identity_bearing(observation.category)
            and confirmation_satisfied(observation, cur_all, query)
        ]
        if prev is None:
            return []  # first run: nothing to compare against (no false alarms)

        prev_all = repo.observations_for_run(s, prev.id, hits_only=True)
        prev_obs = [
            observation
            for observation in prev_all
            if identity_bearing(observation.category)
            and confirmation_satisfied(observation, prev_all, query)
        ]
        cur = {_key(o): o for o in cur_obs}
        old = {_key(o): o for o in prev_obs}

        changes: list[dict] = []

        for key, o in cur.items():
            if key not in old:
                changes.append(_emit(s, target_id, run_id, "appeared", o,
                                      {"url": o.url}))
        for key, o in old.items():
            if key not in cur:
                changes.append(_emit(s, target_id, run_id, "disappeared", o,
                                     {"url": o.url}))
        for key, o in cur.items():
            if key in old:
                fa, fb = o.fingerprint, old[key].fingerprint
                if fa and fb:
                    sim = similarity_hex(fa, fb)
                    if sim < 0.92:
                        changes.append(_emit(s, target_id, run_id, "changed", o,
                                             {"url": o.url, "similarity": round(sim, 3)}))
        return changes


def _emit(s, target_id, run_id, kind, obs: m.Observation, detail: dict) -> dict:
    repo.add_change(s, target_id, run_id, kind, obs.source, obs.label, detail)
    return {"kind": kind, "source": obs.source, "label": obs.label, "detail": detail}
