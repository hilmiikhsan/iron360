#!/usr/bin/env bash
# Local dev launcher for Iron360.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install -q -r requirements.txt
fi
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from example — set IRON360_ADMIN_PASSWORD (and ANTHROPIC_API_KEY for live AI) then re-run."
  exit 1
fi
exec ./.venv/bin/uvicorn backend.main:app --host "${IRON360_HOST:-127.0.0.1}" --port "${IRON360_PORT:-8000}" "$@"
