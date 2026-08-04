#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${1:-}"

if [[ ! "$run_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
  echo "RUN_ID must be a canonical lowercase UUIDv4" >&2
  exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate local-only credentials" >&2
  exit 1
fi

run_root="$repo_dir/environments/local/generated/feat-126-s10/$run_id"
secrets_file="$run_root/infra-secrets.env"
if [[ -e "$run_root" && -L "$run_root" ]]; then
  echo "Refusing a symlink S10 run root" >&2
  exit 1
fi
install -d -m 0700 "$run_root"
if [[ -e "$secrets_file" || -L "$secrets_file" ]]; then
  echo "Refusing to overwrite existing FEAT-126 S10 secrets" >&2
  exit 1
fi

umask 077
temporary_file="$(mktemp "$run_root/.infra-secrets.XXXXXX")"
trap 'rm -f "$temporary_file"' EXIT

api_database_password="$(openssl rand -hex 32)"
keycloak_database_password="$(openssl rand -hex 32)"
administrator_password="$(openssl rand -hex 32)"
user_a_password="$(openssl rand -hex 32)"
user_b_password="$(openssl rand -hex 32)"

if [[ "$(printf '%s\n' "$api_database_password" "$keycloak_database_password" "$administrator_password" "$user_a_password" "$user_b_password" | sort -u | wc -l | tr -d ' ')" != "5" ]]; then
  echo "Generated credentials unexpectedly collided; run again" >&2
  exit 1
fi

printf 'FEAT126_S10_API_DB_PASSWORD=%s\n' "$api_database_password" >"$temporary_file"
printf 'FEAT126_S10_KEYCLOAK_DB_PASSWORD=%s\n' "$keycloak_database_password" >>"$temporary_file"
printf 'FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD=%s\n' "$administrator_password" >>"$temporary_file"
printf 'FEAT126_S10_SYNTHETIC_USER_A_PASSWORD=%s\n' "$user_a_password" >>"$temporary_file"
printf 'FEAT126_S10_SYNTHETIC_USER_B_PASSWORD=%s\n' "$user_b_password" >>"$temporary_file"
chmod 0600 "$temporary_file"
if ! ln "$temporary_file" "$secrets_file"; then
  echo "Refusing to replace FEAT-126 S10 secrets created by another process" >&2
  exit 1
fi
rm -f "$temporary_file"
trap - EXIT

node "$repo_dir/scripts/validate-feat-126-s10-secrets.mjs" "$secrets_file"
echo "Created ignored FEAT-126 S10 secrets for run $run_id"
