#!/usr/bin/env bash
# Boot hxxpsin's A2A server. The MCP stdio server is launched per-call
# by secretarius (see servus/docs/agents.example.json), so this script
# only starts the A2A side.
#
# For dev: HXXPSIN_COGNITION_INSECURE=1 ./scripts/run_hxxpsin.sh

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -x "$REPO_ROOT/.venv/bin/python3" ]]; then
  PYTHON="$REPO_ROOT/.venv/bin/python3"
else
  PYTHON="$(command -v python3)"
fi

cd "$REPO_ROOT"
export PYTHONPATH="${PYTHONPATH:-}${PYTHONPATH:+:}src"

exec "$PYTHON" -m a2a_server \
  --host "${HXXPSIN_A2A_HOST:-127.0.0.1}" \
  --port "${HXXPSIN_A2A_PORT:-9851}"
