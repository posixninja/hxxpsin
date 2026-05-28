# MSF Integration Test Fixture

Docker-compose lab for testing `src/msf_ingest.py` against a real
Metasploit Framework + Postgres + a vulnerable web target (DVWA).

## What's in the lab

| Container         | Image                                          | Host port | Notes                                |
|-------------------|------------------------------------------------|-----------|--------------------------------------|
| `hxxpsin-msf-db`  | `postgres:13-alpine`                           | `5432`    | MSF database; also used by DB backend tests |
| `hxxpsin-msf`     | `metasploitframework/metasploit-framework`     | `55553`   | `msfrpcd` listening with SSL         |
| `hxxpsin-msf-target` | `vulnerables/web-dvwa`                      | `8080`    | A web target for `db_nmap` / probes  |

All ports bind to `127.0.0.1` — nothing is reachable off-host.

## Credentials (loopback-only, do not change to real secrets)

| Service   | User  | Password    |
|-----------|-------|-------------|
| `msfrpcd` | `msf` | `msfrpcpass` |
| `postgres` | `msf` | `msfpass`   |

These match the defaults wired into `tests/test_msf_ingest_integration.py`.
If you change them in `docker-compose.yml`, update the test fixtures too.

## Workflow

```bash
# Bring it up + seed the workspace
./up.sh

# Run the integration tests
HXXPSIN_MSF_INTEGRATION=1 pytest tests/test_msf_ingest_integration.py -v

# Re-seed without restarting (e.g. after vulns -d cleared the table)
./seed.sh

# Tear down (drops the postgres volume — fresh workspace next time)
./down.sh
```

## What `seed.rc` populates

The seed script creates a workspace named `hxxpsin-test` containing:

- 1 host (`172.20.0.10`, hostname `target.hxxpsin.test`)
- 4 services (HTTP/HTTPS/SSH/MySQL — all `open`)
- 2 vulns (DVWA default creds, MySQL anon login)
- 3 credentials (`admin/password`, `gordonb/abc123`, `1337/charley`)
- 2 notes (one `dns_enum`-style, one auth-finding)
- 1 loot record (fake webapp config dump)

This is enough to exercise every `fetch_*` and `merge_*` path in
`msf_ingest.py`. The integration tests assert on this exact shape — if
you change `seed.rc`, update the assertions in
`tests/test_msf_ingest_integration.py`.

## Driving hxxpsin against the lab

Point a hxxpsin scan at the DVWA target with MSF push enabled:

```toml
# hxxpsin.toml
[msf]
enabled       = true
workspace     = "hxxpsin-test"
rpc_host      = "127.0.0.1"
rpc_port      = 55553
rpc_user      = "msf"
rpc_pass      = "msfrpcpass"
rpc_ssl       = true
push_findings = true
push_min_score = 50
```

```bash
python3 -m src.main http://127.0.0.1:8080/ --auto-scope
```

You should see Stage 0 merge in the seeded hosts/services, and any
confirmed findings with score ≥ 50 will land as MSF vulns (idempotent —
re-runs dedupe via `msf_pushed.json`).

## Troubleshooting

- **`msfrpcd never came up`**: first boot pulls ~2GB; check
  `docker compose logs msf` for `msfdb init` progress.
- **`auth.login rejected`**: the RPC password in `docker-compose.yml` and
  the test fixture must match. Tear down with `./down.sh` and bring back
  up if you changed it mid-run.
- **DB tests skip with `psycopg not installed`**: `pip install
  psycopg[binary]` — it's listed as optional in `msf_ingest.py`.
- **Port conflict on 5432 / 55553 / 8080**: edit the host-side port in
  `docker-compose.yml` and the matching constants at the top of
  `test_msf_ingest_integration.py`.

## Why not just use mocks?

The offline tests in `tests/test_msf_ingest.py` use fake backends and
cover the merge/push logic. This fixture exists for the contract surface
that mocks can't fake: msfrpcd's msgpack framing quirks, the actual SQL
schema joins for `MSFDBBackend`, and the fact that MSF's schema has
shifted across versions (creds via `publics`/`privates` vs the old
`creds` table). When `msfrpcd` releases break us, these tests are how
we'll find out.
