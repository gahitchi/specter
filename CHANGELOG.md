# Changelog

This project follows [Semantic Versioning](https://semver.org/) while pre-1.0:
minor versions may contain documented API or schema changes.

The 0.8.0 through 0.10.0 headings below record internal development milestones.
They were not published releases; their changes are included in 0.11.0.

## [0.11.0] - Unreleased

### Added

- A fail-closed production profile with PostgreSQL, Redis/arq workers, explicit
  migration checks, trusted-proxy TLS, secret-file injection, health probes,
  Prometheus metrics, structured logs, request limits, and login throttling.
- A non-root multi-stage container image, production Compose topology, Caddy TLS
  edge, database backup/restore scripts, and an operator runbook.
- Release automation for checksummed Python distributions, multi-architecture
  GHCR images, SBOM and build-provenance attestations, GitHub Releases, and
  tokenless PyPI trusted publishing.
- Complete package metadata, release validation, support and security policies,
  contribution guidance, and structured issue and pull-request templates.
- Tenant-owned durable scan jobs with run linkage, dispatch-failure recording,
  bounded retention, lease recovery, and scheduler reconciliation.
- PostgreSQL and container smoke checks in CI.
- An evidence-bound investigation reasoner that adaptively prioritizes passive
  collection, records its decision trace, and proposes ranked next actions with
  explicit manual and approval boundaries.
- A real-time execution graph for inputs, module processes, sanitized outbound
  requests, artifacts, and findings, including accessible node inspection and
  verdict-aware outcomes.
- Compact durable job-activity persistence and an owner-scoped polling API so
  production worker scans update the graph without running collection in the
  web process.
- Conservative single-value intake shared by CLI, API, live streams, queued
  workers, and the dashboard, including validated public URL/IP seeds and
  explicit classification provenance.
- Evidence-backed profile synthesis with confirmed identifiers, public
  accounts, established attributes, coverage, confidence, and unresolved gaps;
  saved profiles are available through reports and a run-scoped API.
- One-command, unprivileged installers for Windows PowerShell and Arch Linux.
- A non-disruptive update monitor for isolated `uv` and `pipx` installs. It
  checks GitHub every five minutes, downloads immutable revisions to a local
  cache, and applies them only after an explicit `specter --update` command.
- A cross-platform Qt desktop application with a native window, menu system,
  single-instance activation, persisted settings, system tray notifications,
  investigation-completion alerts, and a human-readable update manager.
- A version-history manager for recent immutable GitHub builds, with readable
  commit titles and dates, exact-build downloads, deliberate older-build
  installation, compatibility warnings, and protection from background
  replacement of a manual selection.
- Start menu and Linux application-menu integration, application artwork, and
  one-command uninstallers that preserve local investigations and settings.
- A distinct Specter ghost icon for the desktop window, tray, Start menu,
  Linux application menu, and local web workspace.
- A shared bounded public-document analyzer for visible text, safe links,
  contact data, social profiles, and guarded JSON-LD phone evidence.
- A versioned external-observation contract, secret-scrubbed subprocess runner,
  and disabled-by-default Maigret pilot that emits candidate URLs only.
- A desktop Research sources setting that exposes Maigret only when its optional
  component is installed and clearly requests a restart when the choice changes.
- Evidence Model v2 with first-class source origins, independence identities,
  value-level extraction provenance, temporal validity, completeness, explicit
  contradiction records, decomposed confidence inputs, and policy-gated pivots.
- Adapter conformance checks, sanitized replay fixtures, adversarial parser
  coverage, Maigret version compatibility reporting, and evidence-quality
  metrics for provenance coverage, duplicate collapse, blocked pivots,
  contradictions, parser failures, and timeouts.
- A replayable end-to-end evaluation program with independently verified dataset
  requirements, finding/profile/planner/stop-policy metrics, source breakdowns,
  durable history, a dashboard readiness view, and maturity-gate integration.
- Conservative phone lifecycle and mention-role synthesis, independently
  corroborated identity links, and a dedicated phone dossier.
- Redacted cross-platform diagnostics and non-destructive local/staging
  operational drills for migrations, backup restoration, functional replay,
  readiness probes, and immutable container digests.

### Changed

- Specter is now the product name and primary command. Legacy package, command,
  import, configuration, and infrastructure identifiers remain compatible.
- The dashboard now uses a responsive operations workspace with grouped
  accordion navigation, a focused Start/Activity/Evidence investigation flow,
  clearer scan states, accessible page context, verdict filtering, denser
  evidence views, a responsive live graph, and content-revisioned assets.
- Live research now unfolds in a Focus/Explore Research Room with truthful
  phase progression, plain-language activity explanations, an interactive
  discovery journal, milestones, branch following, connection explanations,
  smoothly animated graph changes, and reduced-motion support.
- New investigations now begin with clear typed identity clues instead of one
  ambiguous dashboard prompt. Supplied clues are summarized and researched as
  one subject, and compatible graph discoveries can be added without silently
  replacing an existing clue.
- The one-command installers now open the native Specter application instead of
  a browser tab. Headless services and research commands remain available from
  the terminal.
- Local databases, settings, and bounded logs now use stable platform data
  directories. Existing working-directory databases are copied forward on first
  launch without deleting the original file.
- Production scans are always dispatched to workers; web requests no longer
  execute collection work in-process.
- Production schema upgrades are one-shot deployment steps and never happen in
  web or worker startup.
- Infrastructure observations no longer create person-identity entities, and a
  shared domain is no longer sufficient to merge identities.
- Profile-link enrichment no longer scans raw scripts with regular expressions;
  blocked, unsupported, and truncated pages now preserve uncertainty explicitly.
- Candidate-only evidence remains visible but cannot steer automatic research.
  Contact details extracted from public pages require independent corroboration
  before recursive expansion, and historical observations no longer contribute
  to current identity clusters.
- Investigation planning now scores expected information gain, evidence quality,
  novelty, request cost, and policy risk, records observed wave yield, and emits
  an explicit auditable stop decision including diminishing returns.
- Evidence review defaults to unresolved work and surfaces contradiction counts;
  phone, reasoning, and evaluation results use progressive disclosure in the
  guided investigation workspace.

### Security

- Production refuses SQLite, local queues, wildcard proxy trust, live scan
  streams, dashboard credential writes, or unauthenticated metrics.
- Public traffic reaches only Caddy; database, Redis, workers, and application
  health/metrics interfaces remain on an internal network.

## 0.10.0 development milestone

### Added

- Authenticated multi-user dashboard with administrator, analyst, and reviewer
  roles; server-side sessions; CSRF defenses; lockouts; and target ownership.
- Gated native-TLS remote serving with explicit trusted hosts and administrator
  bootstrap checks.
- Explainable logistic-regression identity review assistance trained from
  independently labeled observation pairs and stored as portable JSON.
- Validated HTTPS-only WhatsMyName source packs with provenance, license,
  checksums, and rejection reports.
- Gated public API modules for GitLab, Bluesky, Hacker News, and Wikidata.
- Additive account and pair-review Alembic migration.

### Security

- Expansion capabilities fail closed unless the existing maturity gate passes.
- ML suggestions cannot merge identities automatically.
- Analysts cannot enumerate, read, export, review, or delete another analyst's
  targets; legacy ownerless targets remain administrator/reviewer-only.
- Remote mode refuses wildcard hosts, loopback-only configuration, plaintext
  transport, and operation without an active administrator.

## 0.9.0 development milestone

### Added

- Versioned Alembic migrations for SQLite and Postgres, including adoption of
  pre-Alembic databases.
- Immutable investigator reviews, review history, audit events, and reviewed
  calibration-label export.
- Explicit source contracts and opt-in designated-account canary checks.
- A measurable `specter maturity` gate for calibration and source health.
- Redacted target exports, optional AES-GCM encrypted exports, retention
  previews, and complete subject deletion.
- Optional operating-system keyring storage.
- Linux/Windows CI, dependency audits, Dependabot, and validated tag builds.

### Changed

- Only `FOUND` is a confirmed hit or correlation input; `UNCERTAIN` remains a
  visible candidate.
- Every outbound collector request now uses the shared budgeted HTTP client.
- Request ceilings include robots and redirects and cannot overshoot.
- Dashboard and API mutations enforce local-origin, host, content-type, and
  response-security policies.
- Dashboard and datasets are packaged inside the wheel.
- Distributed workers use real ARQ jobs with durable leases and bounded retry.

### Security

- Caller headers are stripped on cross-origin and transport-downgrade redirects.
- Reports escape untrusted values and CSV exports neutralize spreadsheet formulas.
- Secrets are redacted from persisted errors and written atomically when the file
  vault is used.
- Locked dependencies were refreshed and are audited in CI.

### Removed

- The platform-specific `requirements.lock`; `uv.lock` is now authoritative.
- Implicit nullable-column backfills; schema changes are migration-driven.

## 0.8.0 development milestone

Initial recursive collection, persistence, correlation, monitoring, calibration,
and local dashboard implementation.
