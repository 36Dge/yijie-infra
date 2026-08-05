#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_dir/docker-compose.local.yml"
profile="feat-126-s10"
action="${1:-}"
run_id="${2:-}"
services=(
  feat126-s10-api-db
  feat126-s10-keycloak-db
  feat126-s10-keycloak
  feat126-s10-caddy
)
if [[ "$action" != "config" && "$action" != "up" && "$action" != "stop" && "$action" != "status" && "$action" != "export-ca" ]]; then
  echo "usage: feat-126-s10-compose.sh config|up|stop|status|export-ca RUN_ID" >&2
  exit 2
fi
if [[ ! "$run_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
  echo "RUN_ID must be a canonical lowercase UUIDv4" >&2
  exit 2
fi
if [[ "$(docker compose version --short)" != "5.3.0" ]]; then
  echo "FEAT-126 S10E requires the reviewed Docker Compose v5.3.0" >&2
  exit 1
fi

compact_run_id="${run_id//-/}"
project="yijie-feat126-s10-$compact_run_id"
run_root="$repo_dir/environments/local/generated/feat-126-s10/$run_id"
secrets_file="$run_root/infra-secrets.env"
ca_file="$run_root/caddy-root.crt"
rejected_marker="$run_root/REJECTED"

if [[ -e "$rejected_marker" && "$action" != "stop" && "$action" != "status" ]]; then
  echo "Refusing to use a rejected FEAT-126 S10E run" >&2
  exit 1
fi

node "$repo_dir/scripts/validate-feat-126-s10-secrets.mjs" "$secrets_file"
compose=(
  docker compose
  --project-name "$project"
  --env-file "$secrets_file"
  -f "$compose_file"
  --profile "$profile"
)

case "$action" in
  config)
    FEAT126_S10_RUN_ID="$run_id" "${compose[@]}" config --no-interpolate --quiet
    echo "Validated FEAT-126 S10E Compose for run $run_id"
    ;;
  up)
    node "$repo_dir/scripts/verify-feat-126-s10-images.mjs"
    FEAT126_S10_RUN_ID="$run_id" "${compose[@]}" up \
      --detach --wait --pull never "${services[@]}"
    echo "FEAT-126 S10E isolated dependencies are ready for run $run_id"
    ;;
  stop)
    FEAT126_S10_RUN_ID="$run_id" "${compose[@]}" down --remove-orphans --timeout 30
    echo "Stopped FEAT-126 S10E run $run_id; named volumes were retained"
    ;;
  status)
    FEAT126_S10_RUN_ID="$run_id" "${compose[@]}" ps "${services[@]}"
    ;;
  export-ca)
    temporary_dir="$(mktemp -d)"
    trap 'rm -rf "$temporary_dir"' EXIT
    FEAT126_S10_RUN_ID="$run_id" "${compose[@]}" cp \
      feat126-s10-caddy:/data/caddy/pki/authorities/local/root.crt \
      "$temporary_dir/root.crt"
    if grep -q 'PRIVATE KEY' "$temporary_dir/root.crt"; then
      echo "Refusing to export a file containing private key material" >&2
      exit 1
    fi
    if [[ "$(wc -c <"$temporary_dir/root.crt" | tr -d ' ')" -gt 65536 ]]; then
      echo "Refusing an oversized CA certificate" >&2
      exit 1
    fi
    openssl x509 -in "$temporary_dir/root.crt" -noout -subject -issuer >/dev/null
    install -m 0600 "$temporary_dir/root.crt" "$ca_file"
    echo "Exported only the public Caddy root CA for run $run_id"
    ;;
esac
