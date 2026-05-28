"""Integration tests for msf_ingest against a real msfrpcd + Postgres.

Gated on HXXPSIN_MSF_INTEGRATION=1 so CI doesn't try to spin up Docker.
Bring the lab up first:
    tests/fixtures/msf/up.sh
Then:
    HXXPSIN_MSF_INTEGRATION=1 pytest tests/test_msf_ingest_integration.py -v

Asserts that both backends (RPC and direct-PG) can fetch the workspace
seeded by tests/fixtures/msf/seed.rc and that the merge helpers populate
the scope / enrichment structures with the right shapes.
"""
from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import msf_ingest  # noqa: E402
from msf_ingest import (  # noqa: E402
    MSFDBBackend, MSFRPCBackend, augment_scope_from_msf,
    merge_msf_into_enrichment,
)


_INTEGRATION = os.environ.get("HXXPSIN_MSF_INTEGRATION") == "1"
_WORKSPACE = "hxxpsin-test"
_SEEDED_HOST = "172.28.0.10"
_SEEDED_HOSTNAME = "target.hxxpsin.test"


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _INTEGRATION,
    reason="HXXPSIN_MSF_INTEGRATION=1 not set — run tests/fixtures/msf/up.sh first",
)


# ---------------------------------------------------------------------------
# Minimal scope/enrichment stand-ins so the merge helpers have something to
# write into. Shape matches what surface_mapper / enricher produce, but we
# don't import them — keeps this test independent of those modules.
# ---------------------------------------------------------------------------


@dataclass
class FakeScope:
    hosts: list = field(default_factory=list)
    notes: list = field(default_factory=list)


@dataclass
class FakeEnrichment:
    users: dict = field(default_factory=dict)
    secrets: dict = field(default_factory=dict)
    hosts: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RPC backend tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def rpc_client():
    if not _port_open("127.0.0.1", 55553):
        pytest.skip("msfrpcd not reachable on 127.0.0.1:55553")
    client = MSFRPCBackend(
        host="127.0.0.1", port=55553,
        user="msf", password="msfrpcpass",
        ssl_on=True, workspace=_WORKSPACE,
        # msfrpcd in the lab doesn't autoload database.yml — pass DB opts so
        # connect() issues db.connect after auth. The msf container resolves
        # `db` to the postgres service over the compose network.
        db_connect_opts={
            "driver": "postgresql", "host": "db", "port": 5432,
            "database": "msf", "username": "msf", "password": "msfpass",
        },
    )
    await client.connect()
    yield client
    await client.disconnect()


async def test_rpc_fetch_hosts(rpc_client):
    hosts = await rpc_client.fetch_hosts(_WORKSPACE)
    addresses = {h.address for h in hosts}
    assert _SEEDED_HOST in addresses, f"seeded host missing — got {addresses}"


async def test_rpc_fetch_services_has_open_ports(rpc_client):
    services = await rpc_client.fetch_services(_WORKSPACE)
    ports_for_target = {s.port for s in services if s.host == _SEEDED_HOST
                        and s.state == "open"}
    # seed.rc adds 80, 443, 22, 3306
    assert {80, 443, 22, 3306}.issubset(ports_for_target), \
        f"expected seeded ports in {ports_for_target}"


async def test_rpc_augment_scope_pulls_host_and_ports(rpc_client):
    scope = FakeScope()
    res = await augment_scope_from_msf(scope, rpc_client, _WORKSPACE)
    assert res.backend == "rpc"
    assert res.pulled_hosts >= 1
    assert res.pulled_services >= 4
    # Find the seeded host in the merged scope
    seeded = [h for h in scope.hosts if _SEEDED_HOST in h.addresses]
    assert seeded, "augment_scope_from_msf did not add the seeded host"
    assert {80, 443, 22, 3306}.issubset(set(seeded[0].open_ports))
    assert seeded[0].source == f"msf:{_WORKSPACE}"


async def test_rpc_merge_enrichment_pulls_creds_and_notes(rpc_client):
    enr = FakeEnrichment()
    res = await merge_msf_into_enrichment(enr, rpc_client, _WORKSPACE)
    # seed.rc adds 3 creds, 2 notes, 1 loot, 2 vulns
    assert res.pulled_creds >= 3
    assert res.pulled_notes >= 2
    assert res.pulled_loot >= 1
    assert res.pulled_vulns >= 2
    # Provenance on a known user
    admin = enr.users.get("admin")
    assert admin is not None, f"admin user missing — got {list(enr.users)}"
    assert any("password" in c.cred_type or c.algo == "plaintext"
               for c in admin.credentials)


# ---------------------------------------------------------------------------
# DB backend tests (direct PG fallback path)
# ---------------------------------------------------------------------------


@pytest.fixture
async def db_client():
    if not _port_open("127.0.0.1", 5432):
        pytest.skip("postgres not reachable on 127.0.0.1:5432")
    try:
        import psycopg  # noqa: F401
    except ImportError:
        pytest.skip("psycopg not installed — `pip install psycopg[binary]`")
    client = MSFDBBackend(
        host="127.0.0.1", port=5432, dbname="msf",
        user="msf", password="msfpass", workspace=_WORKSPACE,
    )
    await client.connect()
    yield client
    await client.disconnect()


async def test_db_fetch_hosts_matches_rpc(db_client):
    hosts = await db_client.fetch_hosts(_WORKSPACE)
    addresses = {h.address for h in hosts}
    assert _SEEDED_HOST in addresses


async def test_db_push_raises(db_client):
    # The DB backend is read-only by design — push must raise so callers
    # know to disable push_findings when this backend wins the fallback.
    with pytest.raises(msf_ingest.MSFIngestError):
        await db_client.push_vuln(host=_SEEDED_HOST, service="http",
                                  name="should-not-push", refs=[])
