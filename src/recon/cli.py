"""Command-line entry point.

  specter scan torvalds [--format json] [--watch "0 */6 * * *"]
  specter serve            # local web dashboard + API
  specter worker           # process queued scan jobs (run N of these to scale)
  specter monitor          # run the cron scheduler for watch-listed targets
  specter review           # record an investigator decision
  specter maturity         # check whether high-risk expansion is unblocked
  specter targets|runs|changes|sources   # inspect stored investigation data

Back-compat: the legacy `recon` entry point remains available.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from .models import Finding, Verdict

_COLORS = {
    Verdict.FOUND: "\033[92m", Verdict.UNCERTAIN: "\033[93m",
    Verdict.UNVERIFIABLE: "\033[95m",  # magenta — bot-wall/WAF/etc.
    Verdict.NOT_FOUND: "\033[90m", Verdict.ERROR: "\033[91m",
}
_RESET = "\033[0m"
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _terminal_text(value: object) -> str:
    return _CONTROL_RE.sub("", str(value)).replace("\x1b", "")


def _line(f: Finding) -> str:
    c = _COLORS.get(f.verdict, "")
    why = f"  ({_terminal_text(f.reasons[0])})" if f.reasons else ""
    url = f"  {_terminal_text(f.url)}" if f.url else ""
    source = _terminal_text(f.source)
    label = _terminal_text(f.label)
    return f"{c}{f.verdict.value:<10}{_RESET} {f.confidence:>4.2f}  {source:<26} {label}{url}{why}"


def _add_identifier_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--phone")
    p.add_argument("--domain")
    p.add_argument("--name")
    p.add_argument("--url")
    p.add_argument("--ip", dest="ip_address")


# --- scan ------------------------------------------------------------------

async def _cmd_scan(args) -> int:
    import dataclasses

    from .orchestrator import scan
    from .config import SETTINGS
    from . import reporting
    from .identifiers import resolve_query

    try:
        query, intake = resolve_query(
            args.subject,
            hint=args.subject_type,
            default_phone_region=SETTINGS.phone_default_region,
            username=args.username,
            email=args.email,
            phone=args.phone,
            domain=args.domain,
            name=args.name,
            url=args.url,
            ip_address=args.ip_address,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    overrides: dict = {}
    if args.max_depth is not None:
        overrides["max_depth"] = args.max_depth
    if getattr(args, "max_requests", None):
        overrides["max_requests"] = args.max_requests
    if args.scope:
        overrides["scope_mode"] = args.scope
    if args.passive is not None:
        overrides["passive_only"] = args.passive
    settings = dataclasses.replace(SETTINGS, **overrides) if overrides else SETTINGS

    watch = bool(args.watch)
    result = await scan(
        query,
        label=args.label,
        watchlist=watch,
        settings=settings,
        intake=intake,
    )

    print(
        f"Interpreted input as {intake['kind']}: {intake['normalized']} "
        f"({intake['confidence']:.0%} classifier confidence)",
        file=sys.stderr,
    )

    findings = result["findings"]
    for f in findings:
        if args.all or f.is_notable:
            print(_line(f))
            if args.explain and f.breakdown:
                bd = f.breakdown
                print(f"           base {bd.base:+.2f}", file=sys.stderr)
                for c in bd.contributions:
                    print(f"           {c.delta:+.2f}  {c.term}: {c.reason}", file=sys.stderr)
                print(f"           = {bd.total:.2f}", file=sys.stderr)

    summary = result["summary"]
    profile = summary.get("profile") or {}
    if profile:
        print(
            f"\nProfile: {profile['status']} — {profile['assessment']} "
            f"({profile['confidence']:.0%} evidence confidence)",
            file=sys.stderr,
        )
    if summary.get("clusters"):
        print("\nIdentities (correlated):", file=sys.stderr)
        for c in summary["clusters"]:
            flag = f" [{','.join(c['flags'])}]" if c.get("flags") else ""
            corro = c.get("corroboration") or {}
            tag = ""
            if corro:
                tag = f" — {corro['label']} ({corro['independent_classes']} indep. class(es)"
                if corro.get("inflation", 0) > 1:
                    tag += f", {corro['inflation']}× inflated"
                tag += ")"
            print(f"  #{c['id']} {c['label']}: score {c['score']} "
                  f"({c['found']} found/{c['uncertain']} uncertain){flag}{tag}", file=sys.stderr)

    if result["changes"]:
        print("\nChanges since last run:", file=sys.stderr)
        for ch in result["changes"]:
            print(f"  {ch['kind']:<11} {ch['source']} {ch['label']}", file=sys.stderr)

    insights = result.get("insights", [])
    if insights:
        print("\nInsights (correlation rules fired):", file=sys.stderr)
        for h in insights:
            print(f"  [{h.severity:<6}] {h.title}"
                  f"{(' — ' + h.key) if h.key not in ('*', '') else ''}", file=sys.stderr)

    reasoning = result.get("reasoning") or {}
    actions = reasoning.get("next_actions") or []
    if reasoning:
        print(f"\nNext objective: {reasoning.get('objective', 'Review evidence')}", file=sys.stderr)
        print(f"  {reasoning.get('assessment', '')}", file=sys.stderr)
        for action in actions[:5]:
            print(
                f"  [{action['priority']:<8}] {action['title']} "
                f"({action['execution']}) — {action['rationale']}",
                file=sys.stderr,
            )

    stop = f"  (stopped: {result['stop_reason']})" if result.get("stop_reason") else ""
    print(f"\nrun #{result['run_id']} — {sum(1 for f in findings if f.is_hit)} hit(s) "
          f"of {len(findings)} checks; {len(result.get('artifacts', []))} artifact(s) "
          f"discovered.{stop}", file=sys.stderr)

    if watch and args.watch:
        from .store import get_db, repo
        from .monitor.scheduler import validate_cron
        if not validate_cron(args.watch):
            print(f"warning: invalid cron '{args.watch}', schedule not created", file=sys.stderr)
        else:
            db = get_db()
            with db.session() as s:
                repo.create_schedule(s, result["target_id"], args.watch)
            print(f"watch scheduled: '{args.watch}' (run `specter monitor`)", file=sys.stderr)

    if args.format:
        path = reporting.save(query.normalized(), findings, summary, args.format, args.out)
        print(f"report written: {path}", file=sys.stderr)
    return 0


# --- inspect ---------------------------------------------------------------

def _cmd_list(args) -> int:
    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        if args.what == "targets":
            for t in repo.list_targets(s):
                w = " (watch)" if t.watchlist else ""
                print(f"#{t.id}  {t.label}{w}  {t.query}")
        elif args.what == "runs":
            for r in repo.list_runs(s, target_id=args.target):
                print(f"#{r.id}  target={r.target_id}  {r.status}  {r.stats}")
        elif args.what == "changes":
            for c in repo.list_changes(s, target_id=args.target):
                print(f"{c.created_at:%Y-%m-%d %H:%M}  {c.kind:<11} {c.source} {c.label}")
        elif args.what == "sources":
            for src in repo.list_sources(s):
                print(f"{src.name:<14} rel={src.reliability:.2f}  "
                      f"ok={src.successes} fail={src.failures}  breaker={src.breaker_state}")
    return 0


# --- graph -----------------------------------------------------------------

def _cmd_graph(args) -> int:
    """Print the discovery graph of a run as a depth-indented artifact tree."""
    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        run_id = args.run
        if run_id is None:
            runs = repo.list_runs(s, limit=1)
            if not runs:
                print("no runs yet", file=sys.stderr)
                return 1
            run_id = runs[0].id
        arts = repo.list_artifacts(s, run_id)
        edges = repo.list_artifact_edges(s, run_id)

    if not arts:
        print(f"run #{run_id}: no artifacts recorded", file=sys.stderr)
        return 0

    children: dict[int, list] = {}
    has_parent: set[int] = set()
    by_id = {a.id: a for a in arts}
    for e in edges:
        if e.src_artifact_id in by_id and e.dst_artifact_id in by_id:
            children.setdefault(e.src_artifact_id, []).append(e.dst_artifact_id)
            has_parent.add(e.dst_artifact_id)

    print(f"run #{run_id} — {len(arts)} artifact(s), {len(edges)} edge(s)")
    seen: set[int] = set()

    def walk(aid: int, indent: int) -> None:
        if aid in seen:  # an artifact can be reached by multiple parents
            a = by_id[aid]
            print(f"{'  ' * indent}↳ {a.type}:{a.value}  (↑ shared)")
            return
        seen.add(aid)
        a = by_id[aid]
        via = f"  via {a.source_module}" if a.source_module != "seed" else ""
        print(f"{'  ' * indent}• {a.type:<16} {a.value}{via}")
        for cid in children.get(aid, []):
            walk(cid, indent + 1)

    for a in arts:
        if a.id not in has_parent:  # roots (seeds)
            walk(a.id, 0)
    return 0


def _cmd_insights(args) -> int:
    """Print the correlation-rule insights that fired on a run's graph."""
    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        run_id = args.run
        if run_id is None:
            runs = repo.list_runs(s, limit=1)
            if not runs:
                print("no runs yet", file=sys.stderr)
                return 1
            run_id = runs[0].id
        rows = repo.list_rule_findings(s, run_id)
        items = [(r.severity, r.title, r.key, list(r.evidence)) for r in rows]

    if not items:
        print(f"run #{run_id}: no insights — no correlation rules fired")
        return 0
    rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
    items.sort(key=lambda t: -rank.get(t[0], 0))
    print(f"run #{run_id} — {len(items)} insight(s):")
    for sev, title, key, evidence in items:
        tail = f"  ({key})" if key not in ("*", "") else ""
        print(f"  [{sev:<6}] {title}{tail}")
        for e in evidence[:4]:
            print(f"            ↳ {e.get('type')}: {e.get('value')}")
    return 0


def _cmd_provenance(args) -> int:
    """Print a run's reproducibility stamp (the inputs it was produced under)."""
    import json

    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        run_id = args.run
        if run_id is None:
            runs = repo.list_runs(s, limit=1)
            if not runs:
                print("no runs yet", file=sys.stderr)
                return 1
            run_id = runs[0].id
        run = s.get(repo.m.Run, run_id)
        prov = run.provenance if run else None

    if not prov:
        print(f"run #{run_id}: no provenance recorded "
              "(older run, or not a persisted scan)", file=sys.stderr)
        return 0
    print(f"run #{run_id} provenance:")
    print(json.dumps(prov, indent=2, default=str))
    return 0


async def _cmd_calibrate(args) -> int:
    """Run calibration over ground-truth labels and report (never auto-tunes)."""
    from .calibrate import independence_impact, run_calibration
    from .store import get_db, repo

    from .calibrate.labels import labels_file, load_labels
    from .provenance import sha256_file

    path = labels_file(args.labels)
    labels = load_labels(path)
    report = await run_calibration(labels=labels, n_bins=args.bins)
    report["label_provenance"] = {
        "source": "packaged_fixture" if args.labels is None and not os.environ.get(
            "RECON_CALIBRATION_FILE"
        ) else "external",
        "sha256": sha256_file(path) if path.is_file() else None,
    }
    if report["n"] == 0:
        print("no calibration samples — set RECON_CALIBRATION_FILE to a label "
              "dataset and ensure the sites are reachable.",
              file=sys.stderr)
        return 0

    print(f"Calibration over {report['n']} sample(s) "
          f"({report['positives']} present / {report['negatives']} absent)")
    print(f"  Brier {report['brier']}   ECE {report['ece']}   MCE {report['mce']}")
    print("  reliability (predicted -> empirical present):")
    for b in report["bins"]:
        if not b["count"]:
            continue
        bar = "#" * int(round(b["empirical"] * 20))
        print(f"   [{b['lo']:.1f}-{b['hi']:.1f}] n={b['count']:<3} "
              f"pred {b['mean_pred']:.2f}  emp {b['empirical']:.2f}  {bar}")
    cf = report["confusion_found"]
    print(f"  at FOUND>={report['found_threshold']}: FP-rate {cf['fp_rate']:.0%} "
          f"(tp{cf['tp']} fp{cf['fp']} tn{cf['tn']} fn{cf['fn']})")
    print(f"  suggestion: {report['suggestion']['rationale']}")

    db = get_db()
    imp = independence_impact(db)
    report["independence_impact"] = imp
    print(f"  independence flip: {imp['entities_changed']}/{imp['entities']} stored "
          f"entities would change (mean delta {imp['mean_abs_delta']}); flip "
          "`confidence_independence` once verify calibration is healthy.")
    with db.session() as s:
        row = repo.save_calibration(s, report)
    print(f"  saved calibration #{row.id}", file=sys.stderr)
    if args.require_adequate and not report.get("sample_quality", {}).get("adequate"):
        print("calibration dataset does not meet the minimum quality gate", file=sys.stderr)
        return 1
    return 0


def _cmd_analytics(args) -> int:
    """Print confidence analytics aggregated over all stored observations."""
    from . import analytics
    from .store import get_db

    a = analytics.compute(get_db())
    if not a["n_observations"]:
        print("no observations yet — run a saved scan first", file=sys.stderr)
        return 0
    print(f"Confidence analytics over {a['n_observations']} observation(s)")
    mix = a["verdict_mix"]
    print("  verdicts: " + " · ".join(f"{k} {v}" for k, v in sorted(mix.items())))
    print("  confidence distribution:")
    for b in a["confidence_histogram"]:
        if b["count"]:
            print(f"   [{b['lo']:.1f}-{b['hi']:.1f}] {'#' * b['count']} {b['count']}")
    ic = a["independence_coverage"]
    print(f"  corroboration: {ic['distinct_sources']} source(s) → "
          f"{ic['distinct_classes']} independent class(es) (inflation {ic['inflation']}×)")
    if a["top_terms"]:
        print("  top score signals: " + ", ".join(
            f"{t['term']}({t['count']}, {t['mean_delta']:+.2f})" for t in a["top_terms"][:5]))
    if a["calibration_drift"]:
        last = a["calibration_drift"][-1]
        print(f"  latest calibration: Brier {last['brier']} · ECE {last['ece']} (n={last['n']})")
    return 0


# --- review / governance --------------------------------------------------

def _cmd_review(args) -> int:
    from .governance import review_observation
    from .store import get_db

    try:
        with get_db().session() as session:
            review = review_observation(
                session,
                args.observation,
                args.decision,
                note=args.note or "",
                reviewer=args.reviewer,
            )
        print(f"review #{review.id}: observation {review.observation_id} -> {review.decision}")
        return 0
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _cmd_export_target(args) -> int:
    from .governance import add_audit_event, target_export
    from .store import get_db

    redacted = not args.include_sensitive
    try:
        with get_db().session() as session:
            payload = target_export(session, args.target, redacted=redacted)
            add_audit_event(
                session,
                "target.exported",
                "target",
                args.target,
                detail={"redacted": redacted, "encrypted": args.encrypt},
            )
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    raw = (json.dumps(payload, indent=2, default=str) + "\n").encode("utf-8")
    suffix = ".orx" if args.encrypt else ".json"
    path = Path(args.out or f"reports/target-{args.target}{'-redacted' if redacted else ''}{suffix}")
    if args.encrypt:
        from .crypto import encrypt

        passphrase = os.environ.get("RECON_EXPORT_PASSPHRASE")
        if not passphrase:
            print("set RECON_EXPORT_PASSPHRASE for encrypted exports", file=sys.stderr)
            return 2
        raw = encrypt(raw, passphrase)
    _atomic_bytes(path, raw)
    print(f"target export written: {path}")
    return 0


def _cmd_decrypt_export(args) -> int:
    from .crypto import decrypt

    passphrase = os.environ.get("RECON_EXPORT_PASSPHRASE")
    if not passphrase:
        print("set RECON_EXPORT_PASSPHRASE to decrypt exports", file=sys.stderr)
        return 2
    source, destination = Path(args.input), Path(args.out)
    try:
        plaintext = decrypt(source.read_bytes(), passphrase)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"decrypt failed: {exc}", file=sys.stderr)
        return 1
    _atomic_bytes(destination, plaintext)
    print(f"decrypted export written: {destination}")
    return 0


def _cmd_retention(args) -> int:
    from .governance import apply_retention
    from .store import get_db

    with get_db().session() as session:
        result = apply_retention(
            session,
            args.days,
            dry_run=not args.apply,
            actor=args.actor,
        )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_purge(args) -> int:
    from .governance import purge_target
    from .store import get_db

    if not args.confirm:
        print("refusing to purge without --confirm", file=sys.stderr)
        return 2
    try:
        with get_db().session() as session:
            deleted = purge_target(session, args.target, actor=args.actor)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"target_id": args.target, "deleted": deleted}, indent=2))
    return 0


def _cmd_review_labels(args) -> int:
    from .governance import reviewed_calibration_labels
    from .store import get_db

    with get_db().session() as session:
        labels = reviewed_calibration_labels(session)
    path = Path(args.out)
    _atomic_bytes(path, (json.dumps({"labels": labels}, indent=2) + "\n").encode())
    print(f"wrote {len(labels)} reviewed label(s): {path}")
    return 0


async def _cmd_source_check(args) -> int:
    from .sources import load_canaries, run_canaries, validate_contracts

    errors = validate_contracts()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    try:
        results = await run_canaries(load_canaries(args.config))
    except (OSError, ValueError) as exc:
        print(f"invalid canary configuration: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"results": results}, indent=2))
    failing = {"failed", "error"} | ({"skipped"} if args.fail_on_skip else set())
    return 1 if any(result["status"] in failing for result in results) else 0


def _cmd_maturity(args) -> int:
    from .maturity import assess
    from .store import get_db

    result = assess(get_db())
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "BLOCK"
            print(f"{status:<5} {check['name']}: {check['detail']}")
        print("READY" if result["expansion_ready"] else "NOT READY")
    return 0 if result["expansion_ready"] else 1


def _cmd_db_upgrade(_args) -> int:
    from .store.db import init_db

    db = init_db()
    print(f"database upgraded to {db.schema_revision()}")
    return 0


def _cmd_db_check(_args) -> int:
    from .store.db import Database, _default_dsn

    with Database(_default_dsn()) as db:
        db.ping()
        current = db.schema_revision()
        head = db.migration_head()
    print(f"database current={current or 'none'} head={head}")
    return 0 if current == head else 1


def _validate_background_mode() -> None:
    from .config import SETTINGS
    from .store import get_db

    db = get_db()
    if not SETTINGS.production_mode:
        return
    if SETTINGS.auto_migrate:
        raise RuntimeError("production background services require RECON_AUTO_MIGRATE=0")
    if db.engine.dialect.name != "postgresql":
        raise RuntimeError("production background services require PostgreSQL")
    if SETTINGS.queue_backend != "arq":
        raise RuntimeError("production background services require RECON_QUEUE_BACKEND=arq")
    from .expansion import require_ready

    require_ready(db, "multi_user")


def _account_password(confirm: bool = False) -> str:
    from .config import env_value

    password = env_value("RECON_USER_PASSWORD")
    if password is not None:
        return password
    if not sys.stdin.isatty():
        raise ValueError(
            "set RECON_USER_PASSWORD or RECON_USER_PASSWORD_FILE when stdin is not interactive"
        )
    import getpass
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise ValueError("passwords do not match")
    return password


def _cmd_user_add(args) -> int:
    from .auth import create_user
    from .store import get_db

    try:
        password = _account_password(confirm=True)
        with get_db().session() as session:
            user = create_user(
                session, args.username, password, role=args.role,
                display_name=args.display_name or "",
            )
        print(f"created {user.role} account: {user.username}")
        return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _cmd_user_list(_args) -> int:
    from .auth import list_users
    from .store import get_db

    with get_db().session() as session:
        users = list_users(session)
    for user in users:
        state = "active" if user.active else "disabled"
        print(f"{user.username:<24} {user.role:<9} {state}")
    return 0


def _cmd_user_update(args) -> int:
    from .auth import ROLES, active_admin_count, get_user, set_password
    from .store import get_db

    try:
        with get_db().session() as session:
            user = get_user(session, args.username)
            if user is None:
                raise ValueError(f"user {args.username!r} not found")
            removing_admin = user.role == "admin" and (
                args.role not in {None, "admin"} or args.disable
            )
            if removing_admin and active_admin_count(session) <= 1:
                raise ValueError("cannot disable or demote the last active administrator")
            if args.role:
                if args.role not in ROLES:
                    raise ValueError("invalid role")
                user.role = args.role
            if args.enable:
                user.active = True
            if args.disable:
                user.active = False
            if args.reset_password:
                set_password(session, user, _account_password(confirm=True))
            user_id, username, role, active = user.id, user.username, user.role, user.active
        print(f"updated user #{user_id}: {username} ({role}, {'active' if active else 'disabled'})")
        return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _cmd_pair_review(args) -> int:
    from .ml_identity import review_pair
    from .store import get_db

    try:
        with get_db().session() as session:
            row = review_pair(
                session,
                args.left,
                args.right,
                args.decision == "same",
                reviewer=args.reviewer,
                verification_method=args.method,
                note=args.note or "",
            )
        print(f"pair review #{row.id}: {row.left_observation_id}/{row.right_observation_id} "
              f"-> {'same' if row.same_identity else 'distinct'}")
        return 0
    except (LookupError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _cmd_ml_train(args) -> int:
    from .expansion import ExpansionBlocked, require_ready
    from .ml_identity import train
    from .store import get_db

    db = get_db()
    try:
        require_ready(db, "ml_identity")
        with db.session() as session:
            result = train(session, args.out)
        print(json.dumps(result, indent=2))
        return 0 if result["activation_eligible"] else 1
    except (ExpansionBlocked, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _cmd_ml_status(args) -> int:
    from .ml_identity import load_model

    try:
        model = load_model(args.model)
        print(json.dumps(model.payload, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _cmd_source_pack(args) -> int:
    from .source_pack import install

    try:
        result = install(args.input, args.out)
        print(json.dumps(result, indent=2))
        print(f"enable after maturity passes with RECON_SITES_FILE={result['path']} "
              "and RECON_ENABLE_EXPANSION=1", file=sys.stderr)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


# --- main ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="specter", description="Specter local-first OSINT research framework."
    )
    sub = p.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="run a durable, correlated, persisted scan")
    sc.add_argument(
        "subject",
        nargs="?",
        help="one username, email, phone, domain, name, public URL, or IP address",
    )
    sc.add_argument(
        "--type",
        dest="subject_type",
        choices=["username", "email", "phone", "domain", "name", "url", "ip_address"],
        help="override automatic classification of the starting value",
    )
    _add_identifier_args(sc)
    sc.add_argument("--label")
    sc.add_argument("--all", action="store_true", help="also print NOT_FOUND/ERROR")
    sc.add_argument("--explain", action="store_true",
                    help="print the score breakdown (per-term contributions) under each finding")
    sc.add_argument("--watch", metavar="CRON", help="add target to watchlist on this cron")
    sc.add_argument("--format", choices=["json", "csv", "pdf"])
    sc.add_argument("--out")
    # Recursive-engine controls (override config defaults for this run).
    sc.add_argument("--max-depth", type=int, dest="max_depth",
                    help="how many pivots deep the recursive engine may go")
    sc.add_argument("--max-requests", type=int, dest="max_requests",
                    help="ceiling on real outbound requests (spent best-first across the frontier)")
    sc.add_argument("--scope", choices=["strict", "aggressive"],
                    help="strict: only expand artifacts tied to the seed; aggressive: follow external pivots")
    pg = sc.add_mutually_exclusive_group()
    pg.add_argument("--passive", dest="passive", action="store_true", default=None,
                    help="passive modules only (default)")
    pg.add_argument("--active", dest="passive", action="store_false",
                    help="also run active modules")

    gr = sub.add_parser("graph", help="print the discovery graph (artifact tree) of a run")
    gr.add_argument("--run", type=int, help="run id (defaults to the latest run)")

    ins = sub.add_parser("insights", help="print correlation-rule insights that fired on a run")
    ins.add_argument("--run", type=int, help="run id (defaults to the latest run)")

    prov = sub.add_parser("provenance", help="print the reproducibility stamp of a run")
    prov.add_argument("--run", type=int, help="run id (defaults to the latest run)")

    cal = sub.add_parser("calibrate",
                         help="measure whether the confidence score is calibrated (vs labels)")
    cal.add_argument("--bins", type=int, default=10, help="reliability-diagram bins")
    cal.add_argument("--labels", help="validated external ground-truth JSON file")
    cal.add_argument("--require-adequate", action="store_true",
                     help="exit nonzero unless sample size and class balance meet the gate")

    sub.add_parser("analytics", help="confidence analytics across all stored observations")

    review = sub.add_parser("review", help="record an investigator decision")
    review.add_argument("--observation", type=int, required=True)
    review.add_argument("--decision", choices=["accepted", "rejected", "unresolved"], required=True)
    review.add_argument("--note")
    review.add_argument("--reviewer", default="local")

    export = sub.add_parser("export-target", help="export one target (redacted by default)")
    export.add_argument("--target", type=int, required=True)
    export.add_argument("--out")
    export.add_argument("--include-sensitive", action="store_true")
    export.add_argument("--encrypt", action="store_true")

    decrypt = sub.add_parser("decrypt-export", help="decrypt an encrypted target export")
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--out", required=True)

    retention = sub.add_parser("retention", help="preview or apply subject retention")
    retention.add_argument("--days", type=int, required=True)
    retention.add_argument("--apply", action="store_true")
    retention.add_argument("--actor", default="local")

    purge = sub.add_parser("purge-target", help="delete a target and dependent investigation data")
    purge.add_argument("--target", type=int, required=True)
    purge.add_argument("--confirm", action="store_true")
    purge.add_argument("--actor", default="local")

    labels = sub.add_parser("review-labels", help="export reviewed username labels")
    labels.add_argument("--out", required=True)

    source_check = sub.add_parser("source-check", help="run designated live source canaries")
    source_check.add_argument("--config", required=True)
    source_check.add_argument("--fail-on-skip", action="store_true")

    maturity = sub.add_parser("maturity", help="check the gate before high-risk expansion")
    maturity.add_argument("--json", action="store_true")
    sub.add_parser("db-upgrade", help="upgrade the database to the packaged schema head")
    sub.add_parser("db-check", help="verify database connectivity and schema revision")

    serve = sub.add_parser("serve", help="launch the web dashboard + API")
    serve.add_argument("--remote", action="store_true", help="authenticated TLS remote mode")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--tls-cert")
    serve.add_argument("--tls-key")
    serve.add_argument("--allowed-hosts", help="comma-separated trusted hostnames")

    user_add = sub.add_parser("user-add", help="create a dashboard account")
    user_add.add_argument("username")
    user_add.add_argument("--role", choices=["admin", "analyst", "reviewer"], default="analyst")
    user_add.add_argument("--display-name")
    sub.add_parser("user-list", help="list dashboard accounts")
    user_update = sub.add_parser("user-update", help="change a dashboard account")
    user_update.add_argument("username")
    user_update.add_argument("--role", choices=["admin", "analyst", "reviewer"])
    state = user_update.add_mutually_exclusive_group()
    state.add_argument("--enable", action="store_true")
    state.add_argument("--disable", action="store_true")
    user_update.add_argument("--reset-password", action="store_true")

    pair = sub.add_parser("pair-review", help="label an observation pair for ML training")
    pair.add_argument("--left", type=int, required=True)
    pair.add_argument("--right", type=int, required=True)
    pair.add_argument("--decision", choices=["same", "distinct"], required=True)
    pair.add_argument("--method", required=True, help="independent verification method")
    pair.add_argument("--reviewer", default="local")
    pair.add_argument("--note")

    ml_train = sub.add_parser("ml-train", help="train an explainable pair-review model")
    ml_train.add_argument("--out", required=True)
    ml_status = sub.add_parser("ml-status", help="inspect and validate an identity model")
    ml_status.add_argument("--model", required=True)

    source_pack = sub.add_parser("source-pack", help="validate and install a source pack")
    source_pack.add_argument("--input", required=True)
    source_pack.add_argument("--out", required=True)
    wk = sub.add_parser("worker", help="process queued scan jobs")
    wk.add_argument("--once", action="store_true", help="drain the queue then exit")
    sub.add_parser("monitor", help="run the cron scheduler for watch-listed targets")

    ls = sub.add_parser("targets")
    ls.add_argument("--target", type=int)
    rn = sub.add_parser("runs")
    rn.add_argument("--target", type=int)
    chg = sub.add_parser("changes")
    chg.add_argument("--target", type=int)
    sub.add_parser("sources")
    return p


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Back-compat: bare flags -> scan.
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["scan", *argv]

    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.cmd or "scan"

    if cmd == "scan":
        raise SystemExit(asyncio.run(_cmd_scan(args)))
    if cmd == "graph":
        raise SystemExit(_cmd_graph(args))
    if cmd == "insights":
        raise SystemExit(_cmd_insights(args))
    if cmd == "provenance":
        raise SystemExit(_cmd_provenance(args))
    if cmd == "calibrate":
        raise SystemExit(asyncio.run(_cmd_calibrate(args)))
    if cmd == "analytics":
        raise SystemExit(_cmd_analytics(args))
    if cmd == "review":
        raise SystemExit(_cmd_review(args))
    if cmd == "export-target":
        raise SystemExit(_cmd_export_target(args))
    if cmd == "decrypt-export":
        raise SystemExit(_cmd_decrypt_export(args))
    if cmd == "retention":
        raise SystemExit(_cmd_retention(args))
    if cmd == "purge-target":
        raise SystemExit(_cmd_purge(args))
    if cmd == "review-labels":
        raise SystemExit(_cmd_review_labels(args))
    if cmd == "source-check":
        raise SystemExit(asyncio.run(_cmd_source_check(args)))
    if cmd == "maturity":
        raise SystemExit(_cmd_maturity(args))
    if cmd == "db-upgrade":
        raise SystemExit(_cmd_db_upgrade(args))
    if cmd == "db-check":
        raise SystemExit(_cmd_db_check(args))
    if cmd == "user-add":
        raise SystemExit(_cmd_user_add(args))
    if cmd == "user-list":
        raise SystemExit(_cmd_user_list(args))
    if cmd == "user-update":
        raise SystemExit(_cmd_user_update(args))
    if cmd == "pair-review":
        raise SystemExit(_cmd_pair_review(args))
    if cmd == "ml-train":
        raise SystemExit(_cmd_ml_train(args))
    if cmd == "ml-status":
        raise SystemExit(_cmd_ml_status(args))
    if cmd == "source-pack":
        raise SystemExit(_cmd_source_pack(args))
    if cmd == "serve":
        if args.remote:
            os.environ["RECON_REMOTE_MODE"] = "1"
            os.environ["RECON_AUTH_REQUIRED"] = "1"
            os.environ["RECON_ENABLE_EXPANSION"] = "1"
        for name, value in (
            ("RECON_HOST", args.host), ("RECON_PORT", args.port),
            ("RECON_TLS_CERT", args.tls_cert), ("RECON_TLS_KEY", args.tls_key),
            ("RECON_ALLOWED_HOSTS", args.allowed_hosts),
        ):
            if value is not None:
                os.environ[name] = str(value)
        from .server import main as serve_main
        serve_main()
        return
    if cmd == "worker":
        _validate_background_mode()
        from .config import SETTINGS

        if SETTINGS.queue_backend == "arq":
            try:
                from arq.worker import run_worker as run_arq_worker
                from .jobs.arq_queue import WorkerSettings
            except ImportError as exc:
                raise SystemExit(
                    "ARQ worker requires: pip install -e '.[distributed]'"
                ) from exc
            run_arq_worker(WorkerSettings, burst=getattr(args, "once", False))
            return
        from .jobs.worker import run_worker
        n = asyncio.run(run_worker(once=getattr(args, "once", False)))
        print(f"processed {n} job(s)", file=sys.stderr)
        return
    if cmd == "monitor":
        _validate_background_mode()
        from .monitor.scheduler import MonitorScheduler

        async def run_monitor() -> None:
            sched = MonitorScheduler()
            loaded = sched.start()
            print(
                f"scheduler running with {loaded} schedule(s); Ctrl-C to stop",
                file=sys.stderr,
            )
            try:
                await asyncio.Event().wait()
            finally:
                sched.shutdown()

        try:
            asyncio.run(run_monitor())
        except KeyboardInterrupt:
            pass
        return
    if cmd in ("targets", "runs", "changes", "sources"):
        args.what = cmd
        raise SystemExit(_cmd_list(args))

    parser.print_help()


if __name__ == "__main__":
    main()
