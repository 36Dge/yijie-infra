#!/usr/bin/env bash
set -euo pipefail

pnpm validate

if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.local.yml config --no-interpolate --quiet
  echo "Docker Compose semantic validation passed."
else
  echo "Docker is unavailable; deterministic static Compose validation passed."
fi
