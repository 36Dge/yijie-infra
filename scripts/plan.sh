#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed. Compose validation skipped."
  exit 0
fi

docker compose -f docker-compose.local.yml config >/dev/null
echo "Local Docker Compose plan is valid."
