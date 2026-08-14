# osint-recon

`osint-recon` is a local-first OSINT research framework for authorized
investigations. It collects public evidence, rejects common soft-404 false
positives, follows bounded pivots, correlates confirmed observations, and stores
runs for reporting and change detection.

This is a pre-1.0 project. It has substantial automated test coverage, but its
API and database schema may still change. The synthesized profile distinguishes
operator input, confirmed facts, candidates, and unresolved gaps; it is an
evidence summary, not proof of identity or a claim of completeness.

## What it does

- Accepts one username, email address, international phone number, domain, name,
  public profile URL, or IP address and classifies it before collection starts.
- Uses control probes, site-specific rules, response similarity, and block-page
  detection instead of treating every `200 OK` as a match.
- Traverses a typed discovery graph with strict depth, artifact, scope, and real
  outbound-request ceilings.
- Correlates confirmed observations using explicit signals and keeps ambiguous
  entity matches for review.
- Synthesizes a unified profile with confirmed identifiers, public accounts,
  established details, evidence coverage, confidence, and explicit gaps.
- Persists targets, runs, observations, graphs, source health, schedules, and
  change events in SQLite by default.
- Streams a live execution graph of inputs, module processes, sanitized outbound
  requests, discovered artifacts, and verdict-colored findings. Durable worker
  jobs persist compact graph state for production polling and replay.
- Records immutable investigator decisions separately from automated verdicts.
- Provides JSON, CSV, HTML/PDF reporting plus a loopback dashboard and gated,
  authenticated TLS remote mode.
- Supports isolated analyst accounts, reviewer access, and administrator roles.
- Can train a portable, explainable identity-review model from independently
  labeled observation pairs; the model never merges identities automatically.
- Supports optional Shodan, VirusTotal, AbuseIPDB, GitHub, and HIBP credentials.

Every finding has one of these verdicts:

| Verdict | Meaning | Counted as a hit? |
| --- | --- | --- |
| `FOUND` | Evidence met the configured confirmation threshold | Yes |
| `UNCERTAIN` | Plausible but unconfirmed candidate | No |
| `UNVERIFIABLE` | A block, challenge, or rate limit prevented a conclusion | No |
| `NOT_FOUND` | Evidence indicates absence | No |
| `ERROR` | The source or module failed | No |

Only `FOUND` observations drive identity correlation, change detection, and hit
counts. `UNCERTAIN` findings remain visible in the live results and reports.

## Privacy model

"Local-first" describes storage and operation, not offline collection. The
database, cache, keys file, and reports stay on the operator's machine. During a
scan, supplied identifiers are sent to the selected public sources, and those
services can observe the requests. Review the enabled modules and source terms
before investigating sensitive subjects.

The dashboard binds to `127.0.0.1` by default and rejects untrusted hosts,
cross-site requests, and non-JSON mutations. Remote mode is a separate gated
configuration with authentication, CSRF protection, TLS, and explicit trusted
hosts. See
[`SECURITY.md`](https://github.com/gahitchi/osint-recon/blob/main/SECURITY.md)
for the security model and reporting process.

## Quick start

Python 3.10 through 3.14 is supported. Install the published CLI in an isolated
environment with `pipx`:

```bash
pipx install osint-recon
recon scan torvalds
recon serve
```

For development, [`uv`](https://docs.astral.sh/uv/) is the recommended
environment and lockfile manager:

```bash
git clone https://github.com/gahitchi/osint-recon.git
cd osint-recon
uv sync

uv run recon scan torvalds
uv run recon scan person@example.com
uv run recon scan https://github.com/torvalds
uv run recon scan --email person@example.com --domain example.com --explain
uv run recon scan --domain example.com --max-depth 2 --max-requests 200
```

Open the local dashboard:

```bash
uv run recon serve
# http://127.0.0.1:8000
```

`uv run specter` starts the dashboard, local worker, and monitor together.
Use `--no-browser` or `--no-workers` when appropriate.

### One starting value

`recon scan VALUE` uses the same conservative classifier as the dashboard and
API. Email, international phone, domain, URL, and IP syntax are recognized
deterministically. A multi-word value is treated as a name. A single bare token
is treated as a username but remains explicitly marked as an ambiguous
classification. Use `--type` to override that interpretation:

```bash
uv run recon scan mercury --type name
uv run recon scan +14155552671
uv run recon scan 8.8.8.8
```

Known profile URLs also seed their public domain and, for recognized profile
hosts, their handle. Local-network and credential-bearing URLs are rejected.
Typed options remain available for investigations that begin with several known
identifiers. A conflicting automatic and explicit value is rejected rather than
silently choosing one.

The New investigation workspace renders collection as it happens. Request
details include the public host, sanitized URL, method, HTTP status, and duration;
credential-like query values are redacted before an activity leaves the engine.
In production, `Run and save` reads the same graph state from the durable job so
collection remains outside the web process.

The completed workspace presents a profile synthesis before the raw evidence.
`provided` means operator input, `confirmed` means at least one source produced a
`FOUND` observation, and `candidate` never participates in automatic identity
merges. Coverage marked `checked` means sources ran without confirming a fact;
it does not prove that the fact does not exist.

Saved observations can be reviewed in the dashboard or from the CLI:

```bash
uv run recon review --observation 42 --decision accepted --note "verified independently"
uv run recon review-labels --out reviewed-labels.json
```

Review decisions never overwrite the automated verdict. Their immutable history
provides an audit trail and can supply independently checked calibration labels.

The CLI can export a scan directly. JSON and HTML/PDF include the synthesized
profile; CSV remains a flat finding table:

```bash
uv run recon scan --username torvalds --format json --out reports/torvalds.json
uv run recon scan --username torvalds --format csv --out reports/torvalds.csv
uv run recon scan --username torvalds --format pdf --out reports/torvalds.pdf
```

PDF output requires the optional dependency:

```bash
uv sync --extra pdf
```

Without WeasyPrint, a requested PDF falls back to a standalone HTML report.

## Sources and pivots

The default username dataset is a deliberately small curated set packaged with
the application. A downloaded [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
dataset must pass the HTTPS-only source-pack validator before use:

```bash
uv run python scripts/fetch_wmn.py
uv run recon source-pack --input data/wmn-data.json --out data/wmn-validated.json
RECON_SITES_FILE=data/wmn-validated.json RECON_ENABLE_EXPANSION=1 \
  uv run recon scan --username torvalds
```

PowerShell equivalent:

```powershell
$env:RECON_SITES_FILE = "data/wmn-validated.json"
$env:RECON_ENABLE_EXPANSION = "1"
uv run recon scan --username torvalds
```

Modules include username verification, Gravatar and MX evidence, DNS/RDAP/CT
data, name sources, phone normalization, GitHub public-profile enrichment,
Wayback and Common Crawl lookups, network/ASN data, breach checks, and optional
keyed reputation sources. The default mode runs modules marked passive. Use
`--active` only when you understand the additional target interaction.

After the maturity gate passes, expansion mode also enables exact-profile
lookups through the official [GitLab Users API](https://docs.gitlab.com/api/users/),
[Bluesky AppView API](https://docs.bsky.app/docs/tutorials/viewing-profiles),
[Hacker News API](https://github.com/HackerNews/API), and name candidates from
the [Wikidata API](https://www.mediawiki.org/wiki/Wikibase/API). These modules
remain visible but gated before then.

Every module has a source contract disclosing its operator, interaction type,
evidence class, data sent, rate policy, and terms scope. The HTTP-only free
`ip_geo` integration is retained for compatibility but disabled by default.

## Investigation reasoning

Each scan includes an evidence-bound planner. During traversal it reprioritizes
the already-authorized module queue as findings arrive, favoring direct seed
verification, novel evidence types, reliable sources, and independent
corroboration. It never creates findings or changes their confidence scores.

At completion the planner records:

- the current investigation objective and an evidence-based assessment;
- material uncertainties, including blocked sources and budget ceilings;
- ranked next actions with confidence, prerequisites, and execution mode;
- a compact wave-by-wave decision trace; and
- the scope, collection-mode, module, and budget guardrails that remained active.

Actions marked `automatic` are safe passive continuations within the existing
authorization boundary. `manual` actions require investigator judgment, while
`approval` actions may change scope or a bounded limit and are never executed
silently. An automatic action remains `blocked` until its listed prerequisites
exist. The dashboard exposes live and saved-run reasoning; saved reports are
also available at `GET /api/runs/{run_id}/reasoning` and in `Run.stats`.

The core planner is local and deterministic. No investigation data is sent to a
language-model provider, and narrative output is never treated as evidence.

Saved profile synthesis is available at `GET /api/runs/{run_id}/profile`. The
same object is stored in `Run.stats.profile` and embedded in JSON and HTML/PDF
reports. Domains and network observations remain infrastructure facts; they do
not create person-identity nodes or merge people who share an organization.

## Bounds and scope

Traffic policy is centralized in one HTTP client:

- `robots.txt` checks and redirect hops count toward `max_requests`.
- Requests are rate-limited per host and globally concurrency-limited.
- A request is rejected before transport if it would exceed the hard ceiling.
- Response bodies are streamed only up to `max_body_bytes`.
- Only absolute HTTP(S) URLs without embedded credentials are accepted.

Strict scope, the default, expands identifiers tied to the original seed and
records unrelated external links without following them. Aggressive scope can
follow external pivots and is intentionally noisier.

## Credentials

Credentials can be supplied as environment variables:

```bash
RECON_KEY_SHODAN=...
RECON_KEY_VIRUSTOTAL=...
RECON_KEY_ABUSEIPDB=...
RECON_KEY_GITHUB=...
RECON_KEY_HIBP=...
```

The dashboard can also write known keys to
`~/.config/osint-recon/keys.toml`. Values are never returned by the API. The file
is written atomically with restrictive permissions where the operating system
supports them; it is still plaintext, so environment variables or an OS secret
manager are preferable on shared machines.

Install the secure extra and select the OS keyring backend to avoid the plaintext
file vault:

```bash
uv sync --extra secure
RECON_KEY_BACKEND=keyring uv run recon serve
```

## Monitoring and workers

Add a target to the watchlist while scanning:

```bash
uv run recon scan --username torvalds --watch "0 */6 * * *"
uv run recon monitor
uv run recon worker
```

Local jobs use atomic leases. A crashed worker's lease expires and can be
reclaimed; repeated failures stop after the configured maximum attempts.

For multi-machine workers, install the optional Redis/arq and Postgres drivers:

```bash
uv sync --extra distributed --extra postgres
RECON_DB_DSN=postgresql+psycopg://user:pass@host/recon \
RECON_REDIS_DSN=redis://redis-host:6379 \
RECON_QUEUE_BACKEND=arq \
uv run recon worker
```

All workers must share the same database and Redis instance. SQLite and Postgres
schemas are upgraded through packaged Alembic revisions when the application
opens the database. Back up valuable investigation data first. Operators can
also inspect or apply revisions explicitly with `alembic current` and
`alembic upgrade head`.

## Calibration and confidence

```bash
uv run recon calibrate
uv run recon analytics
```

Calibration reports include reliability bins, Brier score, ECE/MCE, confusion
metrics, and a threshold suggestion. The packaged label file contains only a
small functional fixture. It is not a statistically sufficient benchmark, and
the tool marks reports based on a small or imbalanced sample as advisory. Supply
independently verified labels through `RECON_CALIBRATION_FILE` before using the
results to tune thresholds.

The expansion gate combines representative calibration, migration state, source
contracts, and recent designated canaries:

```bash
uv run recon source-check --config canaries.json --fail-on-skip
uv run recon maturity
```

Canary configuration contains operator-designated test artifacts and is never
included in the repository. Default CI runs contract and parser tests without
sending identities to live sources. See
[`MATURITY.md`](https://github.com/gahitchi/osint-recon/blob/main/MATURITY.md).

Confidence scores are deterministic and explainable, but they are not universal
probabilities until validated against representative ground truth for the
operator's sources and use case.

## Expansion capabilities

All expansion capabilities fail closed until `recon maturity` reports `READY`.
Setting `RECON_ENABLE_EXPANSION=1` does not bypass that check.

Create independently verified identity-pair labels and train the optional model:

```bash
uv run recon pair-review --left 41 --right 87 --decision same \
  --method "verified through independent account records" --reviewer analyst
uv sync --extra ml
uv run recon ml-train --out data/identity-model.json
RECON_ENABLE_EXPANSION=1 RECON_ML_MODEL=data/identity-model.json \
  uv run recon scan --username example
```

Training requires at least 100 latest pair labels with at least 20 examples in
each class. Activation additionally requires held-out false-positive rate at or
below 0.05 and ECE at or below 0.10. The JSON model contributes an explainable
review suggestion to ambiguous entity edges; it cannot create an automatic
merge.

Bootstrap an administrator before enabling authenticated or remote service:

```bash
RECON_USER_PASSWORD="a long unique administrator password" \
  uv run recon user-add administrator --role admin
uv run recon user-list
```

Remote service requires a passed maturity gate, a non-loopback bind address, an
active administrator, a certificate and private key, and explicit trusted host
names:

```bash
uv run recon serve --remote --host 0.0.0.0 --port 8443 \
  --allowed-hosts recon.example.org \
  --tls-cert /etc/recon/fullchain.pem --tls-key /etc/recon/privkey.pem
```

Analysts see only targets they own. Reviewers can read and review all evidence
but cannot scan or administer. Administrators manage accounts, credentials,
retention, and the audit trail. Legacy targets without an owner remain visible
only to administrators and reviewers.

## Data governance

Target exports are redacted by default. Raw labels, URLs, reasons, traces,
signals, payloads, and review notes are omitted unless explicitly requested:

```bash
uv run recon export-target --target 7
uv run recon export-target --target 7 --include-sensitive --out reports/target-7.json
```

Encrypted exports require the secure extra and a passphrase supplied through the
environment rather than a command-line argument:

```bash
RECON_EXPORT_PASSPHRASE="a long private passphrase" \
  uv run recon export-target --target 7 --include-sensitive --encrypt
RECON_EXPORT_PASSPHRASE="a long private passphrase" \
  uv run recon decrypt-export --input reports/target-7.orx --out target-7.json
```

Retention is always explicit. Preview before applying, or purge one subject and
its dependent investigation graph:

```bash
uv run recon retention --days 90
uv run recon retention --days 90 --apply
uv run recon purge-target --target 7 --confirm
```

Deletion keeps only a count-based audit event; it does not retain the subject's
query or evidence.

## Production deployment

The supported production profile uses Caddy for public TLS, one Uvicorn process
per web container, PostgreSQL for durable state, Redis/arq workers for every
scan, and a separate scheduler. Services fail closed on stale migrations,
unsafe proxy trust, missing authentication, or an incomplete evidence maturity
gate.

Versioned multi-architecture images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/gahitchi/osint-recon:0.11.0
docker run --rm ghcr.io/gahitchi/osint-recon:0.11.0 --help
```

Follow
[`PRODUCTION.md`](https://github.com/gahitchi/osint-recon/blob/main/PRODUCTION.md)
for artifact verification, secret generation, bootstrap, health checks,
metrics, backup/restore drills, upgrades, and incident response. The included
`compose.production.yaml` accepts a complete tagged or digest-pinned image
reference through `RECON_IMAGE_REF`; use a digest for staging and production
promotion.

## Development

```bash
uv sync --locked --all-extras
uv run ruff check .
uv run pytest -q
uv run bandit -q -c pyproject.toml -r src scripts
uv build --clear --no-create-gitignore
```

`uv.lock` is the cross-platform reproducibility lock. CI tests Python 3.10
through 3.14 on Linux plus Python 3.12 on Windows, builds the wheel, verifies
that dashboard/data/migration assets are present, and runs dependency and static
security audits. Weekly scheduled CI remains offline; live source canaries are
run only after the operator explicitly authorizes their configured artifacts.

Release history and support commitments live in
[`CHANGELOG.md`](https://github.com/gahitchi/osint-recon/blob/main/CHANGELOG.md),
[`SUPPORT.md`](https://github.com/gahitchi/osint-recon/blob/main/SUPPORT.md), and
[`RELEASING.md`](https://github.com/gahitchi/osint-recon/blob/main/RELEASING.md).
Contributions follow
[`CONTRIBUTING.md`](https://github.com/gahitchi/osint-recon/blob/main/CONTRIBUTING.md)
and the
[`CODE_OF_CONDUCT.md`](https://github.com/gahitchi/osint-recon/blob/main/CODE_OF_CONDUCT.md).

The curated site rules are based on the WhatsMyName schema and carry the
attribution recorded in the dataset. The application code is MIT licensed.

## Responsible use

Use this software only for lawful, authorized research. Respect source terms,
privacy rights, robots policies, and applicable rate limits. Do not treat an
automated match as identity proof, and do not publish sensitive findings without
independent verification and a legitimate basis.
