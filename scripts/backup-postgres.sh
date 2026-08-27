#!/bin/sh
set -eu

umask 077
compose_file="${COMPOSE_FILE:-compose.production.yaml}"
backup_dir="${BACKUP_DIR:-backups}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="${1:-${backup_dir}/recon-${timestamp}.dump}"
temporary="${destination}.partial"

mkdir -p "$(dirname "$destination")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

docker compose -f "$compose_file" exec -T db sh -ec '
  export PGPASSWORD="$(cat /run/secrets/db_password)"
  exec pg_dump --format=custom --no-owner --no-acl \
    --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
' > "$temporary"

docker compose -f "$compose_file" exec -T db pg_restore --list < "$temporary" > /dev/null
mv "$temporary" "$destination"
trap - EXIT HUP INT TERM
printf '%s\n' "Backup written to $destination"
