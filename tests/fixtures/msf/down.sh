#!/usr/bin/env bash
# Tear down the MSF lab. -v drops the postgres volume so the next ./up.sh
# starts from a clean workspace.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down -v
