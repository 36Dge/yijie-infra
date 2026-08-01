#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
secrets_file="$repo_dir/environments/local/feat-125.secrets.env"

if [[ -e "$secrets_file" || -L "$secrets_file" ]]; then
  echo "Refusing to overwrite existing local secrets: $secrets_file" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate local-only credentials" >&2
  exit 1
fi

umask 077
temporary_file="$(mktemp "$repo_dir/environments/local/.feat-125.secrets.XXXXXX")"
trap 'rm -f "$temporary_file"' EXIT

database_password="$(openssl rand -hex 32)"
administrator_password="$(openssl rand -hex 32)"
user_a_password="$(openssl rand -hex 32)"
user_b_password="$(openssl rand -hex 32)"
if [[ "$(printf '%s\n' "$database_password" "$administrator_password" "$user_a_password" "$user_b_password" | sort -u | wc -l | tr -d ' ')" != "4" ]]; then
  echo "Generated credentials unexpectedly collided; run again" >&2
  exit 1
fi

printf 'FEAT125_KEYCLOAK_DB_PASSWORD=%s\n' "$database_password" >"$temporary_file"
printf 'FEAT125_KEYCLOAK_ADMIN_PASSWORD=%s\n' "$administrator_password" >>"$temporary_file"
printf 'FEAT125_SYNTHETIC_USER_A_PASSWORD=%s\n' "$user_a_password" >>"$temporary_file"
printf 'FEAT125_SYNTHETIC_USER_B_PASSWORD=%s\n' "$user_b_password" >>"$temporary_file"
chmod 0600 "$temporary_file"
if ! ln "$temporary_file" "$secrets_file"; then
  echo "Refusing to replace local secrets created by another process: $secrets_file" >&2
  exit 1
fi
rm -f "$temporary_file"
trap - EXIT

node "$repo_dir/scripts/validate-feat-125-local-secrets.mjs" "$secrets_file"
echo "Created ignored local secrets at $secrets_file"
