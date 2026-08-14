# Production operations

This runbook describes the supported production profile. It is intentionally
fail-closed: the web service will not start until the database is migrated, an
administrator exists, and the evidence maturity gate passes with real labels
and explicitly authorized source canaries.

## Architecture

- Caddy owns public ports 80/443 and certificate lifecycle.
- One Uvicorn process runs in each web container. Scale containers, not workers
  inside a container.
- PostgreSQL is the system of record.
- Redis/arq dispatches durable scan jobs to separate worker containers.
- A single scheduler container enqueues watch-list jobs.
- A one-shot migration service upgrades the schema before application startup.
- Only Caddy publishes ports. The application, database, and Redis share an
  internal network. Caddy has the fixed address used for proxy-header trust.

## Prepare

1. Install Docker Engine with Compose v2 on a Linux host.
2. Point the production hostname at the host and permit inbound TCP 80/443.
3. Copy `deploy/.env.production.example` to `.env`, set `RECON_DOMAIN`, and set
   `RECON_IMAGE_REF` to the exact release digest promoted from staging.
4. Create each file in `deploy/secrets/` from its `.example` counterpart.
5. Generate independent random values. URL-encode passwords embedded in DSNs.

Example secret generation:

```bash
umask 077
openssl rand -base64 48 > deploy/secrets/db_password
openssl rand -base64 48 > deploy/secrets/redis_password
openssl rand -hex 32 > deploy/secrets/metrics_token
openssl rand -base64 48 > deploy/secrets/admin_password
```

`db_dsn` and `redis_dsn` must contain the same generated passwords. Never store
real secret files in Git, shell history, images, or Compose environment output.

## Verify the release

Release images are published for Linux AMD64 and ARM64. Verify the image's
GitHub build attestation before pulling it, then inspect the manifest and record
the digest in `.env`:

```bash
gh attestation verify \
  oci://ghcr.io/gahitchi/osint-recon:0.11.0 \
  --repo gahitchi/osint-recon
docker buildx imagetools inspect ghcr.io/gahitchi/osint-recon:0.11.0
docker pull ghcr.io/gahitchi/osint-recon:0.11.0
```

Use `RECON_IMAGE_REF=ghcr.io/gahitchi/osint-recon@sha256:...` for deployment.
The tagged default is convenient for initial evaluation, but production should
not depend on a mutable tag. The PostgreSQL, Redis, and Caddy defaults are
digest-pinned and can be upgraded through their corresponding `*_IMAGE_REF`
variables after testing.

## Bootstrap

Pull and migrate without starting the public service:

```bash
docker compose -f compose.production.yaml pull
docker compose -f compose.production.yaml up -d db redis
docker compose -f compose.production.yaml run --rm migrate
docker compose -f compose.production.yaml run --rm \
  -e RECON_USER_PASSWORD_FILE=/run/secrets/admin_password \
  migrate user-add administrator --role admin
docker compose -f compose.production.yaml run --rm migrate db-check
```

Supply representative, independently verified calibration labels and authorized
canaries. Run `calibrate`, `source-check`, and `maturity` from the migration
container. Do not copy synthetic test labels into a production database.

Once `maturity` reports `READY`:

```bash
docker compose -f compose.production.yaml up -d
docker compose -f compose.production.yaml ps
```

The public dashboard should answer only at `https://$RECON_DOMAIN`. Direct HTTP
to the application is rejected except for internal health and token-protected
metrics endpoints.

## Observe

- Liveness: `GET /health/live`
- Readiness: `GET /health/ready` checks database revision and Redis connectivity.
- Metrics: `GET /metrics` with `Authorization: Bearer <metrics token>` from the
  internal network. Caddy deliberately returns 404 for public `/metrics`.
- Logs: JSON on standard error, with request IDs, method, path, status, and
  duration. Query strings, request bodies, client addresses, and identifiers are
  not logged.
- Durable graph updates: `GET /api/jobs/{job_id}/activity` is owner-scoped and
  returns sanitized node state after a sequence cursor. Its rows follow the
  durable job retention policy and are removed with the job.
- Saved profile synthesis: `GET /api/runs/{run_id}/profile` is tenant-scoped and
  returns the same evidence-backed profile stored in `Run.stats.profile`.

Alert on repeated readiness failures, HTTP 5xx responses, queue errors, disk
pressure, PostgreSQL connection saturation, certificate renewal failure, and
worker restart loops. Scrape each web replica because metrics are process-local.

## Back up and restore

Run an encrypted off-host backup at least daily:

```bash
sh ./scripts/backup-postgres.sh
```

The script writes a private PostgreSQL custom archive under `backups/` and
verifies its table of contents. Move it immediately to encrypted storage with a
documented retention policy. Database backups contain sensitive investigation
data and account records.

Test restoration on an isolated host regularly. The restore script stops the
application services, verifies the archive, drops and recreates the database,
and restores its contents:

```bash
RECON_RESTORE_CONFIRM=RESTORE sh ./scripts/restore-postgres.sh backups/recon-TIMESTAMP.dump
docker compose -f compose.production.yaml run --rm migrate db-check
docker compose -f compose.production.yaml up -d
```

Record recovery point and recovery time results. A backup that has never been
restored is not a verified backup.

## Upgrade

1. Back up and verify the current database.
2. Verify the release attestation and pull the exact digest tested in staging.
3. Run `migrate db-upgrade` as a one-shot job.
4. Start one web and one worker replica and inspect readiness, logs, and a test
   investigation owned by a non-administrator account.
5. Roll out remaining replicas. Do not run migrations from web workers.

Rollback application containers only when the release notes state that the old
code supports the new schema. Otherwise restore the pre-upgrade backup.

## Security operations

- Put the host and backup store on encrypted disks.
- Restrict SSH and metrics access to an administrative network.
- Keep public registration disabled; administrators create all accounts.
- Inject provider credentials through `RECON_KEY_<NAME>_FILE`. Dashboard key
  writes are disabled in production.
- Rotate database, Redis, metrics, administrator, and provider credentials after
  suspected exposure. Restart dependent services after replacing secret files.
- Review `/api/audit`, failed logins, account changes, exports, purges, and
  credential events.
- Apply OS, container-base, Python dependency, PostgreSQL, Redis, and Caddy
  updates through the same tested release process.

## Incident response

For suspected compromise, remove public access, preserve logs and database
snapshots, revoke sessions by resetting affected account passwords, rotate all
reachable credentials, and investigate from a copy. Do not destroy the original
evidence while establishing scope. Notify affected data owners according to the
operator's legal and contractual obligations.
