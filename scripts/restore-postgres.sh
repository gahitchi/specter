#!/bin/sh
set -eu

if [ "${RECON_RESTORE_CONFIRM:-}" != "RESTORE" ]; then
  echo "Set RECON_RESTORE_CONFIRM=RESTORE to acknowledge destructive restore." >&2
  exit 2
fi
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "Usage: RECON_RESTORE_CONFIRM=RESTORE $0 BACKUP.dump" >&2
  exit 2
fi

compose_file="${COMPOSE_FILE:-compose.production.yaml}"
backup="$1"

docker compose -f "$compose_file" exec -T db pg_restore --list < "$backup" > /dev/null
docker compose -f "$compose_file" stop proxy web worker scheduler
docker compose -f "$compose_file" exec -T db sh -ec '
  export PGPASSWORD="$(cat /run/secrets/db_password)"
  dropdb --if-exists --force --maintenance-db=postgres \
    --username="$POSTGRES_USER" "$POSTGRES_DB"
  createdb --maintenance-db=postgres --username="$POSTGRES_USER" "$POSTGRES_DB"
  exec pg_restore --exit-on-error --no-owner --no-acl \
    --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
' < "$backup"
docker compose -f "$compose_file" run --rm migrate db-upgrade

echo "Restore complete. Run db-check and the release smoke tests before restarting services."
