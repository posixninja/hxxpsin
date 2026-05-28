#!/usr/bin/env bash
# Bring up the MSF + Postgres + DVWA stack and seed the workspace.
# Idempotent: re-running is safe (msfdb init is a no-op on an initialised DB,
# and seed.rc's `workspace -a` only adds when missing).
set -euo pipefail
cd "$(dirname "$0")"

echo "[+] starting containers"
docker compose up -d

echo "[+] waiting for msfrpcd on 127.0.0.1:55553"
for i in {1..60}; do
    if (echo > /dev/tcp/127.0.0.1/55553) >/dev/null 2>&1; then
        echo "[+] msfrpcd is up"
        break
    fi
    sleep 2
    if [[ $i -eq 60 ]]; then
        echo "[!] msfrpcd never came up — check: docker compose logs msf" >&2
        exit 1
    fi
done

echo "[+] seeding workspace"
./seed.sh

cat <<EOF

[+] MSF lab is ready.

    msfrpcd:   127.0.0.1:55553   user=msf  pass=msfrpcpass  ssl=true
    postgres:  127.0.0.1:5432    user=msf  pass=msfpass     db=msf
    dvwa:      http://127.0.0.1:8080
    workspace: hxxpsin-test

  Run the integration tests:
    HXXPSIN_MSF_INTEGRATION=1 pytest tests/test_msf_ingest.py -v

  Tear down (drops the postgres volume):
    ./down.sh
EOF
