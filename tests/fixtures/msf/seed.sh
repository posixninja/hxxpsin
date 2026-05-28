#!/usr/bin/env bash
# Copy seed.rc into the running msf container and execute it.
set -euo pipefail
cd "$(dirname "$0")"

if ! docker compose ps msf --status running -q | grep -q .; then
    echo "[!] msf container is not running — run ./up.sh first" >&2
    exit 1
fi

docker cp seed.rc hxxpsin-msf:/seed.rc
# Pre-create the loot file — msfconsole's `!` shell escape is disabled in
# this image, so we can't create it from within seed.rc.
docker compose exec -T msf bash -lc \
    'echo "DVWA-style config snapshot (seeded)" > /tmp/seed-loot.txt'
# msfconsole lives at /usr/src/metasploit-framework/msfconsole (the image's
# WORKDIR) — not on $PATH. Invoke via the full bash login so MSF_DATABASE_CONFIG
# from the compose env is picked up.
docker compose exec -T -w /usr/src/metasploit-framework msf \
    bash -lc './msfconsole -q -r /seed.rc'

# Vulns get inserted via direct SQL — msfconsole's `vulns` command in this
# MSF version is read-only. seed_vulns.sql is idempotent.
echo "[+] injecting vulns via SQL"
docker compose exec -T db psql -U msf -d msf < seed_vulns.sql
