"""Probabilistic correlation engine + change detection (offline, via the store)."""

from recon.correlate.resolver import classify, record_from, score
from recon.correlate.graph import correlate_run
from recon.monitor.diff import diff_run
from recon.models import Finding, Query, Verdict
from recon.store import get_db, repo


def _rec(oid, category, label, signals):
    return record_from(oid, category, label, signals)


def test_shared_email_merges():
    a = _rec(1, "email", "Gravatar", {"email": "ada@x.com", "gravatar_hash": "h1"})
    b = _rec(2, "name", "OpenAlex: Ada Lovelace", {"email": "ada@x.com"})
    w, reasons = score(a, b)
    assert classify(w) == "MERGE", (w, reasons)


def test_conflicting_orcid_not_merged():
    a = _rec(1, "name", "ORCID: Ada Lovelace", {"orcid": "0000-1", "email": "ada@x.com"})
    b = _rec(2, "name", "ORCID: Ada L", {"orcid": "0000-2", "email": "ada@x.com"})
    w, _ = score(a, b)
    # email agrees (+8) but orcid conflicts (-5.4) -> not a clean merge
    assert classify(w) != "MERGE"


def test_distinct_people_stay_separate():
    a = _rec(1, "name", "OpenAlex: Ada Lovelace", {"orcid": "0000-1"})
    b = _rec(2, "name", "OpenAlex: Charles Babbage", {"orcid": "0000-2"})
    w, _ = score(a, b)
    assert classify(w) == "DISTINCT"


def test_shared_domain_is_not_identity_proof():
    a = _rec(1, "domain", "DNS", {"domain": "example.com"})
    b = _rec(2, "network", "rDNS", {"domain": "example.com"})

    weight, reasons = score(a, b)

    assert weight == 0
    assert reasons == []


def _seed_run(query, findings):
    db = get_db()
    with db.session() as s:
        t = repo.get_or_create_target(s, query)
        r = repo.create_run(s, t)
        for f in findings:
            repo.add_observation(s, r, f)
        repo.finish_run(s, r, "done", {})
        return db, t.id, r.id


def test_correlate_run_clusters_by_strong_signal():
    db, tid, rid = _seed_run(Query(name="Ada Lovelace", email="ada@x.com"), [
        Finding(source="email:gravatar", category="email", label="Gravatar",
                verdict=Verdict.FOUND, confidence=0.9,
                signals={"gravatar_hash": "h1", "email": "ada@x.com"}),
        Finding(source="name:openalex", category="name", label="OpenAlex: Ada Lovelace",
                verdict=Verdict.FOUND, confidence=0.8, signals={"email": "ada@x.com"}),
        Finding(source="name:orcid", category="name", label="ORCID: Charles Babbage",
                verdict=Verdict.UNCERTAIN, confidence=0.5, signals={"orcid": "0000-9"}),
    ])
    summary = correlate_run(db, rid)
    # Ada's two confirmed observations merge. The unconfirmed Babbage candidate
    # is retained as an observation but cannot create or influence an identity.
    assert summary["identities"] == 1
    top = summary["clusters"][0]
    assert top["found"] >= 2
    assert top["uncertain"] == 0


def test_infrastructure_observations_do_not_create_identity_entities():
    db, _target_id, run_id = _seed_run(Query(domain="example.com"), [
        Finding(
            source="domain:dns",
            category="domain",
            label="DNS example.com",
            verdict=Verdict.FOUND,
            confidence=0.9,
            signals={"domain": "example.com"},
        ),
        Finding(
            source="resolve:dns",
            category="dns",
            label="Resolve example.com",
            verdict=Verdict.FOUND,
            confidence=0.9,
            signals={"domain": "example.com"},
        ),
    ])

    summary = correlate_run(db, run_id)

    assert summary["identities"] == 0
    assert summary["clusters"] == []


def test_conflict_resolution_picks_canonical_by_reliability():
    # Both observations share gravatar_hash AND email (so they merge), but assert
    # different orcids. The higher-reliability source's orcid wins as canonical.
    db = get_db()
    with db.session() as s:
        t = repo.get_or_create_target(s, Query(email="ada@x.com"))
        r = repo.create_run(s, t)
        repo.add_observation(s, r, Finding(
            source="name:orcid", category="name", label="ORCID",
            verdict=Verdict.FOUND, confidence=0.9,
            signals={"gravatar_hash": "shared", "email": "ada@x.com", "orcid": "0000-1"}),
            reliability=0.95)
        repo.add_observation(s, r, Finding(
            source="scraper:x", category="name", label="Scraper",
            verdict=Verdict.FOUND, confidence=0.9,
            signals={"gravatar_hash": "shared", "email": "ada@x.com", "orcid": "0000-2"}),
            reliability=0.30)
        repo.finish_run(s, r, "done", {})
        rid2 = r.id

    summary = correlate_run(db, rid2)
    merged = [c for c in summary["clusters"] if "_canonical" in c["signals"]]
    assert merged, "expected a single merged cluster with a resolved conflict"
    assert merged[0]["signals"]["_canonical"]["orcid"] == "0000-1"


def test_diff_detects_appeared_account():
    q = Query(username="alice")
    db, tid, r1 = _seed_run(q, [
        Finding(source="username:GitHub", category="username", label="GitHub",
                url="https://github.com/alice", verdict=Verdict.FOUND, confidence=1.0,
                data={"fingerprint": "aaaa"}),
    ])
    assert diff_run(db, tid, r1) == []  # first run: no alarms

    with db.session() as s:
        t = repo.get_or_create_target(s, q)
        r2 = repo.create_run(s, t)
        repo.add_observation(s, r2, Finding(
            source="username:GitHub", category="username", label="GitHub",
            url="https://github.com/alice", verdict=Verdict.FOUND, confidence=1.0,
            data={"fingerprint": "aaaa"}))
        repo.add_observation(s, r2, Finding(
            source="username:GitLab", category="username", label="GitLab",
            url="https://gitlab.com/alice", verdict=Verdict.FOUND, confidence=1.0,
            data={"fingerprint": "bbbb"}))
        repo.finish_run(s, r2, "done", {})
        r2id = r2.id

    changes = diff_run(db, tid, r2id)
    kinds = {(c["kind"], c["label"]) for c in changes}
    assert ("appeared", "GitLab") in kinds
