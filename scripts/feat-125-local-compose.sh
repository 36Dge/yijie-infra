#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
secrets_file="$repo_dir/environments/local/feat-125.secrets.env"
compose_file="$repo_dir/docker-compose.local.yml"
profile="feat-125-local"
services=(feat125-keycloak-db feat125-keycloak feat125-caddy)
action="${1:-}"

if [[ "$action" != "up" && "$action" != "stop" && "$action" != "status" && "$action" != "export-ca" ]]; then
  echo "usage: feat-125-local-compose.sh up|stop|status|export-ca" >&2
  exit 2
fi

compose=(docker compose -f "$compose_file" --profile "$profile")
case "$action" in
  up)
    node "$repo_dir/scripts/validate-feat-125-local-secrets.mjs" "$secrets_file"
    docker compose --env-file "$secrets_file" -f "$compose_file" --profile "$profile" \
      up -d --wait "${services[@]}"
    ;;
  stop)
    "${compose[@]}" stop "${services[@]}"
    ;;
  status)
    "${compose[@]}" ps "${services[@]}"
    ;;
  export-ca)
    generated_dir="$repo_dir/environments/local/generated"
    output_file="$generated_dir/feat-125-caddy-root.crt"
    temporary_dir="$(mktemp -d)"
    trap 'rm -rf "$temporary_dir"' EXIT
    "${compose[@]}" cp \
      feat125-caddy:/data/caddy/pki/authorities/local/root.crt \
      "$temporary_dir/root.crt"
    if grep -q 'PRIVATE KEY' "$temporary_dir/root.crt"; then
      echo "Refusing to export a file containing private key material" >&2
      exit 1
    fi
    openssl x509 -in "$temporary_dir/root.crt" -noout -subject -issuer >/dev/null
    mkdir -p "$generated_dir"
    install -m 0600 "$temporary_dir/root.crt" "$output_file"
    echo "Exported only the public Caddy root CA certificate to $output_file"
    ;;
esac
