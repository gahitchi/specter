# Specter

Specter is a local-first OSINT research framework for authorized
investigations. It collects public evidence, rejects common soft-404 false
positives, follows bounded pivots, correlates corroborated identity evidence, and stores
runs for reporting and change detection.

This is a pre-1.0 project. It has substantial automated test coverage, but its
API and database schema may still change. The synthesized profile distinguishes
operator input, positive source observations, corroborated associations, candidates,
and unresolved gaps; it is an
evidence summary, not proof of identity or a claim of completeness.

## What it does

- Accepts one or more matching usernames, email addresses, phone numbers,
  domains, names, public profile URLs, or IP addresses and classifies them before
  collection starts.
- Uses control probes, site-specific rules, response similarity, and block-page
  detection instead of treating every `200 OK` as a match.
- Traverses a typed discovery graph with strict depth, artifact, scope, and real
  outbound-request ceilings.
- Correlates only identity-bearing, policy-eligible observations using explicit
  unique signals and keeps ambiguous
  entity matches for review.
- Synthesizes a unified profile with corroborated identifiers, observed public
  accounts and details, evidence coverage, confidence, and explicit gaps.
- Persists targets, runs, observations, graphs, source health, schedules, and
  change events in SQLite by default.
- Streams a live execution graph of inputs, module processes, sanitized outbound
  requests, discovered artifacts, and verdict-colored findings. Durable worker
  jobs persist compact graph state for production polling and replay.
- Presents live research as a readable Research Room: real activity drives its
  phase trail, current-step explanation, discovery journal, milestones, and
  animated graph. Focus keeps it calm; Explore exposes branches and provenance.
- Records immutable investigator decisions separately from automated verdicts.
- Provides JSON, CSV, HTML/PDF reporting plus a loopback dashboard and gated,
  authenticated TLS remote mode.
- Supports isolated analyst accounts, reviewer access, and administrator roles.
- Can train a portable, explainable identity-review model from independently
  labeled observation pairs; the model never merges identities automatically.
- Supports optional Shodan, VirusTotal, AbuseIPDB, GitHub, and HIBP credentials.

Every finding has one of these verdicts:

| Verdict | Meaning | Positive source observation? |
| --- | --- | --- |
| `FOUND` | The source established its narrow stated observation | Yes |
| `UNCERTAIN` | Plausible but unconfirmed candidate | No |
| `UNVERIFIABLE` | A block, challenge, or rate limit prevented a conclusion | No |
| `NOT_FOUND` | Evidence indicates absence | No |
| `ERROR` | The source or module failed | No |

`FOUND` never means that a profile, mailbox, name, or number belongs to the
investigation subject. Only current, identity-bearing `FOUND` observations whose
evidence policy permits confirmation and whose unique non-seed identifier is
repeated by the required independent origins can drive correlation. Name-only
agreement is never enough for automatic identity confirmation. Numbering-plan metadata,
historical mentions, directories, shared service numbers, and candidate-only
tools remain visible without becoming identity evidence. `UNCERTAIN` findings
also remain visible in live results and reports.

During a scan, the Activity view can be left in **Focus** for a guided account
of the investigation or switched to **Explore** for graph inspection. Journal
entries focus their corresponding graph nodes. A selected node can isolate its
branch, explain why it is connected, or prepare the discovered value as a new
starting point. These controls never fabricate progress or silently expand the
scope of the running investigation.

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
[`SECURITY.md`](https://github.com/gahitchi/specter/blob/main/SECURITY.md)
for the security model and reporting process.

## Quick start

Install and launch the complete local application with one command. The
installer creates an isolated user environment and installs `uv` when needed;
administrator or root access is not required.

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/gahitchi/specter/gpt-branch/install.ps1 | iex
```

Arch Linux:

```bash
curl -LsSf https://raw.githubusercontent.com/gahitchi/specter/gpt-branch/install.sh | bash
```

Existing installations should run the matching installer once more after this
upgrade. That one-time repair adds the Qt desktop components, desktop launcher,
and operating-system menu entry; later application updates use the built-in
update manager.

The installer opens Specter as a desktop application and creates both a desktop
launcher and a Windows Start menu or Linux application-menu entry. The local
API, worker, and monitor are started and stopped with the application. A second
launch brings the existing window forward instead of starting another copy.

Specter checks the GitHub branch immediately and every five minutes while it is
running. A newer build is downloaded to a local cache without changing the
running application. Offline failures do not prevent startup. Open **Tools >
Update Manager** to see recent build names, dates, and statuses; download a
specific build; or install the downloaded build. A manually selected build is
not replaced by the five-minute background check. Installation is always an
explicit choice, and Specter restarts after it completes. Update checks and
notifications can be changed under **Tools > Settings**.

Until tagged releases are published, Version History lists immutable builds
from the `gpt-branch` commit history. This also allows an older build to be
downloaded and installed. Specter warns before an older build is selected
because data created by newer builds may not be backward compatible. Automatic
checks may still download a newer build later, but they never install it.

The terminal fallback remains available:

```text
specter --update
```

If no build is waiting, the command checks once before applying. It uses an
already downloaded build exactly as selected, including when GitHub is
temporarily unavailable. Specter refuses to replace its installation while
another instance is running. Rerunning the platform installer repairs the
isolated environment in place.

The Python distribution retains the compatibility name `osint-recon`. Use the
matching one-command uninstaller to remove the application and both launchers:

```powershell
irm https://raw.githubusercontent.com/gahitchi/specter/gpt-branch/uninstall.ps1 | iex
```

```bash
curl -LsSf https://raw.githubusercontent.com/gahitchi/specter/gpt-branch/uninstall.sh | bash
```

Uninstalling leaves investigation databases and settings in place.

Local application data is stored under `%LOCALAPPDATA%\Specter` on Windows or
`${XDG_DATA_HOME:-~/.local/share}/specter` on Linux. Settings use `%APPDATA%\Specter`
or `${XDG_CONFIG_HOME:-~/.config}/specter`, and logs use the platform state
directory. On first launch, an older `data/recon.db` database is copied into the
stable application-data location without deleting the original.

Python 3.10 through 3.14 is supported. The published CLI can also be installed
in an isolated environment with `pipx`:

```bash
pipx install 'osint-recon[desktop]'
specter scan torvalds
specter serve
```

For development, [`uv`](https://docs.astral.sh/uv/) is the recommended
environment and lockfile manager:

```bash
git clone https://github.com/gahitchi/specter.git
cd specter
uv sync --extra desktop

uv run specter scan torvalds
uv run specter scan person@example.com
uv run specter scan https://github.com/torvalds
uv run specter scan --email person@example.com --domain example.com --explain
uv run specter scan --domain example.com --max-depth 2 --max-requests 200
```

Run the web service without the desktop shell:

```bash
uv run specter serve
# http://127.0.0.1:8000
```

`uv run --extra desktop specter` starts the desktop application and its local
services together. Development checkouts do not update themselves. Use
`--headless`, `--no-workers`, or `--no-update` when appropriate.

### Identity clues

The dashboard accepts typed name, username, email, phone, profile URL, domain,
and IP address clues. Every filled field belongs to one investigation subject:
Specter sends them through one query, uses them together when choosing research
branches, and tests the resulting links without treating operator input as
independent confirmation.

The terminal also supports a single starting value for quick investigations.

`specter scan VALUE` uses the same conservative classifier as the dashboard and
API. Email, international phone, domain, URL, and IP syntax are recognized
deterministically. National phone formats are also recognized when
`RECON_PHONE_DEFAULT_REGION` is configured. A multi-word value is treated as a
name. A single bare token is treated as a username but remains explicitly
marked as an ambiguous classification. Use `--type` to override that
interpretation:

```bash
uv run specter scan mercury --type name
uv run specter scan +14155552671
uv run specter scan 8.8.8.8
```

Known profile URLs also seed their public domain and, for recognized profile
hosts, their handle. Local-network and credential-bearing URLs are rejected.
Typed options remain available in the terminal and API for investigations that
begin with several known identifiers. A conflicting automatic and explicit
value is rejected rather than silently choosing one.

The New investigation workspace renders collection as it happens. Request
details include the public host, sanitized URL, method, HTTP status, duration,
response size, and a SHA-256 response receipt; credential-like query values are
redacted before an activity leaves the engine. The receipt can prove that two
records came from the same capped response bytes without storing the page body
in the report. It is not an identity fingerprint.

Every dashboard investigation is saved as a durable background job. Closing or
reloading the window does not cancel it: the Activity view reconnects to its
stored progress, and an application restart resumes queued local work. Failed
jobs retry within their configured limit. The operator can request cooperative
cancellation after the current source check and can deliberately retry a failed
or cancelled job. Production collection remains outside the web process.

Starting or scheduling research requires an explicit authorization basis. A
saved subject can reload its clues, but Specter clears the earlier confirmation
before another run. Saved investigations also expose bounded six-hour, daily,
and weekly monitoring presets; disabling a preset stops future scheduled
requests. Completed runs can be reopened in the conclusion-first reader or
downloaded as readable HTML, JSON, or CSV evidence records.

The completed workspace presents a profile synthesis before the raw evidence.
`provided` means operator input. `confirmed` means a current identity-bearing
observation is allowed to support that claim and has satisfied independent
corroboration; it does not merely mean that a page returned a positive response.
`candidate` never participates in automatic identity merges. Coverage marked
`observed` contains a positive contextual fact that cannot establish identity;
`checked` means sources ran without confirming a fact. Neither state proves that
an unobserved fact does not exist.

Phone-led investigations add a number dossier that separates allocation
metadata from directly verified public mentions, labels explicit person,
organization, and directory contexts, surfaces stale or reassignment language,
and promotes unique identity links only after independent corroboration. Repeated
names remain candidates. A public mention never establishes current ownership or control.

Saved observations can be reviewed in the dashboard or from the CLI:

```bash
uv run specter review --observation 42 --decision accepted --note "verified independently"
uv run specter review-labels --out reviewed-labels.json
```

Review decisions never overwrite the automated verdict. Their immutable history
provides an audit trail and can supply independently checked calibration labels.

The CLI can export a scan directly. JSON and HTML/PDF include the synthesized
profile; CSV remains a flat finding table:

```bash
uv run specter scan --username torvalds --format json --out reports/torvalds.json
uv run specter scan --username torvalds --format csv --out reports/torvalds.csv
uv run specter scan --username torvalds --format pdf --out reports/torvalds.pdf
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
uv run specter source-pack --input data/wmn-data.json --out data/wmn-validated.json
RECON_SITES_FILE=data/wmn-validated.json RECON_ENABLE_EXPANSION=1 \
  uv run specter scan --username torvalds
```

PowerShell equivalent:

```powershell
$env:RECON_SITES_FILE = "data/wmn-validated.json"
$env:RECON_ENABLE_EXPANSION = "1"
uv run specter scan --username torvalds
```

Modules include username verification, Gravatar and MX evidence, DNS/RDAP/CT
data, name sources, evidence-first phone research, GitHub public-profile enrichment,
Wayback and Common Crawl lookups, network/ASN data, breach checks, and optional
keyed reputation sources. The default mode runs modules marked passive. Use
`--active` only when you understand the additional target interaction.

Public profile pages and phone-discovery pages pass through one bounded document
analyzer. It separates visible content from scripts, resolves public links,
extracts guarded JSON-LD, and rejects local or credential-bearing URLs before a
module can treat them as evidence.

### Phone research

Phone research is a restrained public-web workflow, not an API aggregation
screen. Specter first parses the number locally and reports numbering-plan
facts such as canonical formats, region, line type, allocation carrier, and
portability support. Those facts never identify the current subscriber and the
interface says so explicitly.

APIs remain internal enrichment tools where they add evidence; they are not the
product surface and their responses are not stacked into a provider checklist.
When directly verified phone pages yield a guarded email, name, or profile lead,
the existing modules can deepen it only after two independent, non-historical
person records agree. Directory copies share one lineage and cannot satisfy that
gate. Organization, service, ambiguous, and reassigned-number mentions remain
context and never steer person-level research automatically.

For public-web research, Specter submits at most three exact E.164,
international, and national-format queries to DuckDuckGo's HTML search, keeps at
most six candidate pages, and fetches those pages directly through the shared
rate limiter and robots policy. Likely directory results are checked after more
direct-looking public pages.
Search snippets are discovery hints only. A `FOUND` result requires the exact
normalized phone on the directly retrieved page. Name, email, and profile
pivots require the exact phone and those fields to occur in the same JSON-LD
`Person` or `ProfilePage` record.

The default workflow does not probe messenger accounts, trigger password
recovery, query breach or infostealer services, or treat carrier metadata as
ownership. Blocked and partially retrieved pages are `UNVERIFIABLE`, not false
negatives. A clean bounded pass means only that no match was found in that pass.

Traffic and national-number parsing can be tuned without adding providers:

```bash
RECON_PHONE_WEB_ENABLED=true
RECON_PHONE_WEB_MAX_QUERIES=3
RECON_PHONE_WEB_MAX_PAGES=6
RECON_PHONE_DEFAULT_REGION=IT  # optional; required for ambiguous national formats
```

### Optional Maigret candidates

Specter can optionally use Maigret as a small username-discovery helper. It is
not part of the normal installation and is disabled by default. The adapter
checks at most 25 sites with four connections, disables recursion and Maigret
self-updates, and stops the process after two minutes. Specter does not pass API
keys or stored credentials into that process.

Maigret results are deliberately weaker than Specter's native verification. A
reported page appears as an `UNCERTAIN` candidate URL; it never becomes a
confirmed account, never creates an account-profile identity pivot, and never
proves that two profiles share an owner. Native and Maigret observations for the
same site count as one source lineage during corroboration.

After the optional component is installed, the desktop Settings window exposes
the source under Research sources and applies the choice on the next restart.
When the component is absent, the setting says so instead of enabling a source
that cannot run.

Install and enable the optional adapter in a development checkout:

```bash
uv sync --extra desktop --extra maigret
RECON_MAIGRET_ENABLED=true uv run specter
```

PowerShell equivalent:

```powershell
uv sync --extra desktop --extra maigret
$env:RECON_MAIGRET_ENABLED = "true"
uv run specter
```

For an isolated branch install, use:

```bash
pipx install --force 'osint-recon[desktop,maigret] @ git+https://github.com/gahitchi/specter.git@gpt-branch'
```

The adapter's outbound site probes are governed by its own hard limits and are
not included in Specter's native HTTP request counter or live request graph.
This distinction is shown in the saved observation metadata. Site responses can
change or produce false positives, so candidate pages still require direct,
independent review.

After the maturity gate passes, expansion mode also enables exact-profile
lookups through the official [GitLab Users API](https://docs.gitlab.com/api/users/),
[Bluesky AppView API](https://docs.bsky.app/docs/tutorials/viewing-profiles),
[Hacker News API](https://github.com/HackerNews/API), and name candidates from
the [Wikidata API](https://www.mediawiki.org/wiki/Wikibase/API). These modules
remain visible but gated before then.

Every module has a source contract disclosing its operator, interaction type,
evidence class, data sent, rate policy, and terms scope. The HTTP-only free
`ip_geo` integration is retained for compatibility but disabled by default.
New research paths must follow the evidence-to-evaluation sequence in
[`EXTENDING.md`](EXTENDING.md).

### Evidence Model v2

Specter stores an observation as more than a verdict and score. New saved
evidence records include:

- the collector, upstream origin, evidence class, and independence identity;
- the input artifact, document URL, extraction method and location,
  transformation chain, and retrieval time when available;
- observed, first-seen, last-seen, validity, and current, historical, or unknown state;
- complete, partial, or unknown collection coverage;
- separate match-quality, source-reliability, recency, independence,
  transformation-certainty, and completeness dimensions; and
- an evidence policy that independently controls confirmation and automatic
  pivoting.

Confidence does not grant permission. Candidate-only output is retained for
review but cannot confirm an account or launch another request. A lead marked
as requiring corroboration remains dormant until the same normalized artifact
has support from the configured number of independent origins. This policy is
enforced in the graph engine rather than left to collector convention.

When the same stable claim changes between `FOUND` and `NOT_FOUND`, or a still
present page changes the identity fields it asserts, Specter creates a
contradiction record and marks the earlier observation historical.
It does not silently overwrite history, and historical evidence is excluded
from current identity correlation. Contradictions are available through
`GET /api/runs/{run_id}/contradictions`, saved reports, and the review UI.

External tools use a bounded observation contract and adapter conformance
checks. The Maigret pilot supports versions `>=0.6.4,<0.7`; the application
reports missing, unknown, supported, and incompatible installations instead of
assuming any executable has a compatible output format. Sanitized replay
fixtures and adversarial parser tests run offline in CI.

The Confidence quality view reports provenance and temporal coverage,
duplicate-collapse rate, policy-blocked pivots, contradictions, parser failure
rate, and module timeout rate. These are operational quality indicators, not a
claim that the evidence is universally calibrated.

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
RECON_KEY_BACKEND=keyring uv run specter serve
```

## Monitoring and workers

Add a target to the watchlist while scanning:

```bash
uv run specter scan --username torvalds --watch "0 */6 * * *"
uv run specter monitor
uv run specter worker
```

Local jobs use atomic leases. A crashed worker's lease expires and can be
reclaimed; repeated failures stop after the configured maximum attempts.

For multi-machine workers, install the optional Redis/arq and Postgres drivers:

```bash
uv sync --extra distributed --extra postgres
RECON_DB_DSN=postgresql+psycopg://user:pass@host/recon \
RECON_REDIS_DSN=redis://redis-host:6379 \
RECON_QUEUE_BACKEND=arq \
uv run specter worker
```

All workers must share the same database and Redis instance. SQLite and Postgres
schemas are upgraded through packaged Alembic revisions when the application
opens the database. Back up valuable investigation data first. Operators can
also inspect or apply revisions explicitly with `alembic current` and
`alembic upgrade head`.

## Calibration and confidence

```bash
uv run specter calibrate
uv run specter evaluate
uv run specter analytics
uv run specter diagnostics
```

Calibration reports include reliability bins, Brier score, ECE/MCE, confusion
metrics, and a threshold suggestion. The packaged label file contains only a
small functional fixture. It is not a statistically sufficient benchmark, and
the tool marks reports based on a small or imbalanced sample as advisory. Supply
independently verified labels through `RECON_CALIBRATION_FILE` before using the
results to tune thresholds.

`evaluate` measures frozen, reviewed investigation snapshots: finding precision
and recall, false positives, synthesized profile status, planner actions, stop
decisions, and source-level behavior. It does not rerun public collection and
must not be described as a live end-to-end benchmark. Designated canaries cover
current source reachability separately.

The desktop's **Advanced > Confidence quality > Quality review set** flow has
two honest modes. **Private self-check** lets one operator evaluate runs using
their own authorized information; it is useful pilot evidence but can never
unlock release readiness. **Independent release evaluation** exports a blind
CSV and requires an outside reviewer. Private subject data stays in the
platform data directory and is not a packaged project asset.

Related identifiers must share one non-identifying person label. A phone
number, two emails, and several usernames owned by the same person still count
as one subject, even when they are tested in separate runs.

The same operator workflow is available from the command line:

```bash
specter evaluation-kit create --out private-kit.json --name "My private check" \
  --mode operator_pilot
specter evaluation-kit capture --kit private-kit.json --run 42 \
  --case phone-positive-01 --subject-group me --category phone \
  --authorization self_owned
specter evaluation-kit review-sheet --kit private-kit.json --out self-check.csv
specter evaluation-kit finalize --kit private-kit.json \
  --review completed-review.csv --out reviewed-cases.json
specter evaluate --dataset reviewed-cases.json --require-ready
```

Externally verified cases require an authorized subject or controlled asset, a
reviewer independent of Specter development, a blind review, the verification
method, and the review date. Create that workflow with `--mode independent`.
The packaged dataset and operator pilots always report `NEEDS_EVIDENCE`. See
[`EVALUATION.md`](https://github.com/gahitchi/specter/blob/main/EVALUATION.md)
for the sampling and review protocol.

`diagnostics` produces a redacted installation report covering packaged assets,
database revision, storage access, source contracts, and update-manager support.
It does not include subject identifiers, credentials, cookies, or database DSNs.

The expansion gate combines representative calibration, migration state, source
contracts, and recent designated canaries:

```bash
uv run specter source-check --config canaries.json --fail-on-skip
uv run specter maturity
```

Canary configuration contains operator-designated test artifacts and is never
included in the repository. Default CI runs contract and parser tests without
sending identities to live sources. See
[`MATURITY.md`](https://github.com/gahitchi/specter/blob/main/MATURITY.md).

Confidence scores are deterministic and explainable, but they are not universal
probabilities until validated against representative ground truth for the
operator's sources and use case.

## Expansion capabilities

All expansion capabilities fail closed until `specter maturity` reports `READY`.
Setting `RECON_ENABLE_EXPANSION=1` does not bypass that check.

Create independently verified identity-pair labels and train the optional model:

```bash
uv run specter pair-review --left 41 --right 87 --decision same \
  --method "verified through independent account records" --reviewer analyst
uv sync --extra ml
uv run specter ml-train --out data/identity-model.json
RECON_ENABLE_EXPANSION=1 RECON_ML_MODEL=data/identity-model.json \
  uv run specter scan --username example
```

Training requires at least 100 latest pair labels with at least 20 examples in
each class. Activation additionally requires held-out precision at or above
0.99, false-positive rate at or below 0.01, and ECE at or below 0.10. The JSON
model contributes an explainable
review suggestion to ambiguous entity edges; it cannot create an automatic
merge.

Bootstrap an administrator before enabling authenticated or remote service:

```bash
RECON_USER_PASSWORD="a long unique administrator password" \
  uv run specter user-add administrator --role admin
uv run specter user-list
```

Remote service requires a passed maturity gate, a non-loopback bind address, an
active administrator, a certificate and private key, and explicit trusted host
names:

```bash
uv run specter serve --remote --host 0.0.0.0 --port 8443 \
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
uv run specter export-target --target 7
uv run specter export-target --target 7 --include-sensitive --out reports/target-7.json
```

Encrypted exports require the secure extra and a passphrase supplied through the
environment rather than a command-line argument:

```bash
RECON_EXPORT_PASSPHRASE="a long private passphrase" \
  uv run specter export-target --target 7 --include-sensitive --encrypt
RECON_EXPORT_PASSPHRASE="a long private passphrase" \
  uv run specter decrypt-export --input reports/target-7.orx --out target-7.json
```

Retention is always explicit. Preview before applying, or purge one subject and
its dependent investigation graph:

```bash
uv run specter retention --days 90
uv run specter retention --days 90 --apply
uv run specter purge-target --target 7 --confirm
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
docker pull ghcr.io/gahitchi/specter:0.11.0
docker run --rm ghcr.io/gahitchi/specter:0.11.0 --help
```

Follow
[`PRODUCTION.md`](https://github.com/gahitchi/specter/blob/main/PRODUCTION.md)
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
[`CHANGELOG.md`](https://github.com/gahitchi/specter/blob/main/CHANGELOG.md),
[`SUPPORT.md`](https://github.com/gahitchi/specter/blob/main/SUPPORT.md), and
[`RELEASING.md`](https://github.com/gahitchi/specter/blob/main/RELEASING.md).
Contributions follow
[`CONTRIBUTING.md`](https://github.com/gahitchi/specter/blob/main/CONTRIBUTING.md)
and the
[`CODE_OF_CONDUCT.md`](https://github.com/gahitchi/specter/blob/main/CODE_OF_CONDUCT.md).

The curated site rules are based on the WhatsMyName schema and carry the
attribution recorded in the dataset. The application code is MIT licensed.

## Responsible use

Use this software only for lawful, authorized research. Respect source terms,
privacy rights, robots policies, and applicable rate limits. Do not treat an
automated match as identity proof, and do not publish sensitive findings without
independent verification and a legitimate basis.
