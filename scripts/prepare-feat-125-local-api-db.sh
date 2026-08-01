#!/usr/bin/env bash
set -euo pipefail

readonly container_name="yijie-postgres"
readonly database_name="yijie_api_feat125_local"
readonly database_owner="yijie"

if [[ "$(docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null || true)" != "true" ]]; then
  echo "FEAT-125 local API database requires the healthy yijie-postgres container." >&2
  exit 1
fi

database_exists="$(
  docker exec "$container_name" psql \
    --username "$database_owner" \
    --dbname postgres \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set ON_ERROR_STOP=1 \
    --command "SELECT count(*) FROM pg_database WHERE datname = 'yijie_api_feat125_local'"
)"

if [[ "$database_exists" == "0" ]]; then
  docker exec "$container_name" createdb \
    --username "$database_owner" \
    --owner "$database_owner" \
    --encoding UTF8 \
    --template template0 \
    "$database_name"
elif [[ "$database_exists" != "1" ]]; then
  echo "FEAT-125 local API database inventory is invalid." >&2
  exit 1
fi

database_facts="$(
  docker exec "$container_name" psql \
    --username "$database_owner" \
    --dbname postgres \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --field-separator : \
    --set ON_ERROR_STOP=1 \
    --command "SELECT owner.rolname, pg_encoding_to_char(database.encoding) FROM pg_database AS database JOIN pg_roles AS owner ON owner.oid = database.datdba WHERE database.datname = 'yijie_api_feat125_local'"
)"

if [[ "$database_facts" != "yijie:UTF8" ]]; then
  echo "FEAT-125 local API database owner or encoding drifted." >&2
  exit 1
fi

echo "FEAT-125 dedicated local API database is ready (loopback DSN required; no credential printed)."
