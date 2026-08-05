#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${1:-}"
api_repo="${2:-}"
expected_api_sha="${3:-}"

if [[ "$#" -ne 3 ]]; then
  echo "usage: feat-126-s10-api-migration <RUN_ID> <API_REPO> <API_SHA>" >&2
  exit 2
fi
if [[ ! "$run_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
  echo "RUN_ID must be a canonical lowercase UUIDv4" >&2
  exit 2
fi
if [[ -z "$api_repo" || ! -d "$api_repo/.git" ]]; then
  echo "API_REPO must be a local yijie-api worktree" >&2
  exit 2
fi
if [[ ! "$expected_api_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "API_SHA must be a full lowercase commit SHA" >&2
  exit 2
fi

run_root="$repo_dir/environments/local/generated/feat-126-s10/$run_id"
secrets_file="$run_root/infra-secrets.env"
rejected_marker="$run_root/REJECTED"
if [[ -e "$rejected_marker" ]]; then
  echo "Refusing to migrate a rejected FEAT-126 S10E run" >&2
  exit 1
fi
node "$repo_dir/scripts/feat-126-s10-api-candidate.mjs" "$run_id" "$api_repo" "$expected_api_sha"
node "$repo_dir/scripts/validate-feat-126-s10-secrets.mjs" "$secrets_file"
set -a
# shellcheck disable=SC1090
source "$secrets_file"
set +a

export YIJIE_API_POSTGRES_DSN="postgres://yijie:${FEAT126_S10_API_DB_PASSWORD}@127.0.0.1:5432/yijie_api_feat126_s10?sslmode=disable"
(
  cd "$api_repo"
  go run ./cmd/migrate up
  go run ./cmd/migrate status
)
unset YIJIE_API_POSTGRES_DSN FEAT126_S10_API_DB_PASSWORD FEAT126_S10_KEYCLOAK_DB_PASSWORD
unset FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD FEAT126_S10_SYNTHETIC_USER_A_PASSWORD
unset FEAT126_S10_SYNTHETIC_USER_B_PASSWORD
