#!/usr/bin/env bash
set -euo pipefail

umask 077
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${1:-}"
api_repo="${2:-}"
expected_api_sha="${3:-}"
profile="feat-126-s10-local-lab"
issuer="https://localhost:8443/realms/yijie-local"

if [[ "$#" -ne 3 ]]; then
  echo "usage: feat-126-s10-api-bootstrap <RUN_ID> <API_REPO> <API_SHA>" >&2
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
evidence_dir="$run_root/bootstrap-evidence"
results_file="$evidence_dir/bootstrap-results.jsonl"
if [[ -e "$rejected_marker" ]]; then
  echo "Refusing to bootstrap a rejected FEAT-126 S10E run" >&2
  exit 1
fi
if [[ -e "$evidence_dir" ]]; then
  echo "Refusing to overwrite FEAT-126 S10 bootstrap evidence" >&2
  exit 1
fi
node "$repo_dir/scripts/feat-126-s10-api-candidate.mjs" "$run_id" "$api_repo" "$expected_api_sha"

manifest_relative_paths=(
  "config/nonproduction/feat-125-local-lab/user-a-tenant-a.json"
  "config/nonproduction/feat-125-local-lab/user-a-tenant-b.json"
  "config/nonproduction/feat-125-local-lab/user-b-tenant-a.json"
  "config/nonproduction/feat-125-local-lab/user-b-tenant-b.json"
)
for manifest in "${manifest_relative_paths[@]}"; do
  if ! git -C "$api_repo" ls-files --error-unmatch "$manifest" >/dev/null 2>&1 ||
     [[ ! -f "$api_repo/$manifest" || -L "$api_repo/$manifest" ]]; then
    echo "Reviewed FEAT-126 S10 bootstrap manifest is unavailable" >&2
    exit 1
  fi
done

node "$repo_dir/scripts/validate-feat-126-s10-secrets.mjs" "$secrets_file"
# shellcheck disable=SC1090
source "$secrets_file"

cleanup_environment() {
  unset YIJIE_ENV YIJIE_API_ACCESS_ISSUER YIJIE_API_POSTGRES_DSN
  unset FEAT126_S10_API_DB_PASSWORD FEAT126_S10_KEYCLOAK_DB_PASSWORD
  unset FEAT126_S10_KEYCLOAK_ADMIN_PASSWORD FEAT126_S10_SYNTHETIC_USER_A_PASSWORD
  unset FEAT126_S10_SYNTHETIC_USER_B_PASSWORD
  if [[ -f "$results_file" && ! -L "$results_file" ]]; then
    rm -f -- "$results_file"
  fi
}
trap cleanup_environment EXIT

export YIJIE_ENV="nonproduction"
export YIJIE_API_ACCESS_ISSUER="$issuer"
export YIJIE_API_POSTGRES_DSN="postgres://yijie:${FEAT126_S10_API_DB_PASSWORD}@127.0.0.1:5432/yijie_api_feat126_s10?sslmode=disable"

mkdir -m 0700 "$evidence_dir"
(
  cd "$api_repo"
  go run ./cmd/verify-nonprod-authz --profile "$profile" --expect empty
) >"$evidence_dir/pre-state.json"

: >"$results_file"
chmod 0600 "$results_file"
for pass in 1 2; do
  (
    cd "$api_repo"
    go run ./cmd/bootstrap-nonprod-authz-batch \
      --profile "$profile" \
      --input "${manifest_relative_paths[0]}" \
      --input "${manifest_relative_paths[1]}" \
      --input "${manifest_relative_paths[2]}" \
      --input "${manifest_relative_paths[3]}"
  ) >>"$results_file"
done
node "$repo_dir/scripts/verify-feat-126-s10-bootstrap-results.mjs" "$results_file" >"$evidence_dir/execution-summary.json"
(
  cd "$api_repo"
  go run ./cmd/verify-nonprod-authz --profile "$profile" --expect complete
) >"$evidence_dir/post-state.json"

rm -f -- "$results_file"
printf '%s\n' '{"status":"passed","profile":"feat-126-s10-local-lab","content_classification":"synthetic_only"}'
