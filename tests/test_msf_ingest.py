"""Offline tests for msf_ingest. Uses fake backends — no msgpack, psycopg,
or running msfrpcd required. Verifies:

  - RPC-first → DB-fallback when RPC connect raises MSFConnectionError
  - augment_scope_from_msf dedupes against existing scope hosts
  - merge_msf_into_enrichment attaches "msf:<workspace>" provenance to creds
  - push_findings is idempotent (msf_pushed.json sidecar dedupes re-runs)
  - push_findings respects push_min_score gating

Run:  python -m pytest tests/test_msf_ingest.py -v
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import msf_ingest  # noqa: E402
from msf_ingest import (  # noqa: E402
    MSFClient, MSFConnectionError, MSFCred, MSFHost, MSFIngestError,
    MSFLoot, MSFNote, MSFService, MSFVuln,
    augment_scope_from_msf, make_msf_client, merge_msf_into_enrichment,
    push_findings,
)


# ---------------------------------------------------------------------------
# Fake backends + profile
# ---------------------------------------------------------------------------


class FakeClient(MSFClient):
    """In-memory backend. Two modes:

      raise_on_connect = "rpc" → simulates msfrpcd unreachable
      raise_on_connect = None  → connects normally
    """
    backend = "fake"

    def __init__(self, workspace="default", raise_on_connect=None,
                 hosts=None, services=None, vulns=None, creds=None,
                 loot=None, notes=None):
        self.workspace = workspace
        self._raise = raise_on_connect
        self._hosts = hosts or []
        self._services = services or []
        self._vulns = vulns or []
        self._creds = creds or []
        self._loot = loot or []
        self._notes = notes or []
        self.pushed: list[dict] = []

    async def connect(self) -> None:
        if self._raise:
            raise MSFConnectionError(f"fake refuses to connect ({self._raise})")

    async def disconnect(self) -> None:
        return None

    async def fetch_hosts(self, workspace): return list(self._hosts)
    async def fetch_services(self, workspace): return list(self._services)
    async def fetch_vulns(self, workspace): return list(self._vulns)
    async def fetch_credentials(self, workspace): return list(self._creds)
    async def fetch_loot(self, workspace): return list(self._loot)
    async def fetch_notes(self, workspace): return list(self._notes)

    async def push_vuln(self, host, service, name, refs, info=""):
        vid = f"v{len(self.pushed) + 1}"
        self.pushed.append({"id": vid, "host": host, "service": service,
                            "name": name, "refs": refs, "info": info})
        return vid

    async def push_note(self, host, ntype, data): return f"n{len(self.pushed)+1}"
    async def push_loot(self, host, ltype, content, info="", content_type="text/plain"):
        return f"l{len(self.pushed)+1}"


@dataclass
class _Profile:
    enabled: bool = True
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_user: str = "msf"
    rpc_pass: str = "test"
    rpc_ssl: bool = True
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "msf"
    db_user: str = "msf"
    db_pass: str = "test"
    workspace: str = "default"
    pull_hosts: bool = True
    pull_creds: bool = True
    pull_loot: bool = True
    pull_notes: bool = True
    push_findings: bool = False
    push_min_score: int = 50


@dataclass
class _Finding:
    """Duck-type for classifier.Finding, just enough for push_findings."""
    url: str
    score: int
    categories: list
    method: str = "GET"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_rpc_first_then_db_fallback(monkeypatch):
    """When the RPC backend fails to connect, make_msf_client falls back to
    the DB backend instead of raising."""
    rpc_calls = {"n": 0}
    db_calls = {"n": 0}

    class StubRPC:
        backend = "rpc"
        def __init__(self, *a, **kw):
            rpc_calls["n"] += 1
            self.workspace = kw.get("workspace", "default")
        async def connect(self):
            raise MSFConnectionError("rpc unreachable")
        async def disconnect(self):
            return None

    class StubDB:
        backend = "db"
        def __init__(self, *a, **kw):
            db_calls["n"] += 1
            self.workspace = kw.get("workspace", "default")
        async def connect(self):
            return None
        async def disconnect(self):
            return None

    monkeypatch.setattr(msf_ingest, "_MSGPACK_OK", True)
    monkeypatch.setattr(msf_ingest, "_HTTPX_OK", True)
    monkeypatch.setattr(msf_ingest, "_PSYCOPG_OK", True)
    monkeypatch.setattr(msf_ingest, "MSFRPCBackend", StubRPC)
    monkeypatch.setattr(msf_ingest, "MSFDBBackend", StubDB)

    client = asyncio.run(make_msf_client(_Profile()))
    assert client is not None
    assert client.backend == "db"
    assert rpc_calls["n"] == 1
    assert db_calls["n"] == 1


def test_make_client_disabled_returns_none():
    """enabled = False → no connection attempt, returns None."""
    p = _Profile(enabled=False)
    assert asyncio.run(make_msf_client(p)) is None


def test_make_client_no_backend_available_raises(monkeypatch):
    """If both optional deps are missing AND no creds for either backend,
    make_msf_client raises MSFIngestError so the caller can degrade."""
    monkeypatch.setattr(msf_ingest, "_MSGPACK_OK", False)
    monkeypatch.setattr(msf_ingest, "_PSYCOPG_OK", False)
    p = _Profile()
    try:
        asyncio.run(make_msf_client(p))
    except MSFIngestError:
        return
    raise AssertionError("expected MSFIngestError when no backend is available")


def test_augment_dedupes_hosts():
    """When an MSF host's hostname or address matches an existing scope
    entry, it is NOT appended again; non-overlapping MSF hosts are added
    with source = msf:<workspace>."""
    from surface_mapper import HostRecord, Scope

    scope = Scope(seed="https://corp.local")
    scope.hosts.append(HostRecord(hostname="api.corp.local",
                                  addresses=["192.0.2.5"], source="seed"))

    fake = FakeClient(
        hosts=[
            MSFHost(address="192.0.2.5", hostname="api.corp.local"),  # overlap
            MSFHost(address="10.0.0.7", hostname="db.corp.local"),    # new
        ],
        services=[
            MSFService(host="10.0.0.7", port=5432, proto="tcp", name="postgres"),
            MSFService(host="10.0.0.7", port=22, proto="tcp", name="ssh"),
        ],
    )

    res = asyncio.run(augment_scope_from_msf(scope, fake, "default"))
    assert res.pulled_hosts == 2
    assert res.pulled_services == 2
    assert len(scope.hosts) == 2  # one existing + one new (overlap skipped)
    assert res.overlapped_hosts == ["api.corp.local"]

    new = [h for h in scope.hosts if h.hostname == "db.corp.local"]
    assert len(new) == 1
    assert new[0].source == "msf:default"
    assert 22 in new[0].open_ports and 5432 in new[0].open_ports


def test_enrichment_provenance_tag(tmp_path):
    """Creds pulled from MSF land in EnrichmentResult.users[*].provenance
    with method=MSF and url=msf://<workspace> so downstream filters can
    distinguish them."""
    from enricher import EnrichmentResult

    enrich = EnrichmentResult(out_dir=str(tmp_path))
    fake = FakeClient(
        creds=[MSFCred(host="10.0.0.7", service="ssh",
                       public="root", private="hunter2",
                       private_type="Password", origin="msf:default")],
    )
    res = asyncio.run(merge_msf_into_enrichment(enrich, fake, "default"))
    assert res.pulled_creds == 1
    assert "root" in enrich.users
    user = enrich.users["root"]
    assert any(p.method == "MSF" and p.url.startswith("msf://")
               for p in user.provenance)
    # Cred should round-trip via the CredentialRecord
    assert any(c.value == "hunter2" for c in user.credentials)


def test_push_idempotent(tmp_path):
    """Calling push_findings twice with the same findings appends pushed-ids
    only on the first call; the sidecar gates the second run."""
    fake = FakeClient(workspace="default")
    findings = [
        _Finding(url="https://ctf.corp.local/api/users/1", score=80, categories=["IDOR"]),
    ]
    res1 = asyncio.run(push_findings(
        fake, "https://ctf.corp.local", findings, tmp_path, min_score=50,
    ))
    assert len(res1.pushed_vulns) == 1
    sidecar = tmp_path / "msf_pushed.json"
    assert sidecar.exists()
    first_payload = json.loads(sidecar.read_text())
    assert len(first_payload) == 1

    res2 = asyncio.run(push_findings(
        fake, "https://ctf.corp.local", findings, tmp_path, min_score=50,
    ))
    assert len(res2.pushed_vulns) == 0  # second call skipped the cached entry
    # Sidecar must be unchanged
    assert json.loads(sidecar.read_text()) == first_payload
    # Fake backend saw exactly one push, not two
    assert len(fake.pushed) == 1


def test_push_min_score_gates(tmp_path):
    """Findings below push_min_score are silently skipped."""
    fake = FakeClient(workspace="default")
    findings = [
        _Finding(url="https://ctf.corp.local/low",  score=30, categories=["INFO"]),
        _Finding(url="https://ctf.corp.local/high", score=80, categories=["IDOR"]),
    ]
    res = asyncio.run(push_findings(
        fake, "https://ctf.corp.local", findings, tmp_path, min_score=50,
    ))
    assert len(res.pushed_vulns) == 1
    assert len(fake.pushed) == 1
    assert fake.pushed[0]["info"].startswith("GET https://ctf.corp.local/high")


def test_augment_handles_no_client_gracefully():
    """augment_scope_from_msf with client=None returns an empty result and
    leaves the Scope untouched."""
    from surface_mapper import Scope
    scope = Scope(seed="https://corp.local")
    res = asyncio.run(augment_scope_from_msf(scope, None, "default"))
    assert res.backend == ""
    assert res.pulled_hosts == 0
    assert len(scope.hosts) == 0


def test_merge_handles_no_client_gracefully(tmp_path):
    """merge_msf_into_enrichment with client=None is a safe no-op."""
    from enricher import EnrichmentResult
    enrich = EnrichmentResult(out_dir=str(tmp_path))
    res = asyncio.run(merge_msf_into_enrichment(enrich, None, "default"))
    assert res.pulled_creds == 0
    assert enrich.users == {}


def test_push_with_no_client_is_noop(tmp_path):
    """push_findings with client=None never touches the sidecar."""
    findings = [_Finding(url="https://x", score=99, categories=["X"])]
    res = asyncio.run(push_findings(None, "https://x", findings, tmp_path))
    assert res.pushed_vulns == []
    assert not (tmp_path / "msf_pushed.json").exists()


def test_sidecar_unprefixed_keys_auto_promote_to_vuln_namespace(tmp_path):
    """Round-1 sidecars store keys as 'cats|url' (no namespace prefix). PR1
    introduces `vuln:` / `cred:` / `loot:` / `note:` namespaces so all four
    push types can share msf_pushed.json without colliding. A pre-existing
    unprefixed sidecar must be read as if every key were `vuln:<key>`, and
    re-written in the new prefixed form on the next push."""
    sidecar = tmp_path / "msf_pushed.json"
    # Simulate a round-1 sidecar with an unprefixed entry already present.
    legacy_key = "IDOR|https://ctf.corp.local/api/users/1"
    sidecar.write_text(json.dumps({legacy_key: "v999"}))

    fake = FakeClient(workspace="default")
    findings = [
        _Finding(url="https://ctf.corp.local/api/users/1", score=80, categories=["IDOR"]),
        _Finding(url="https://ctf.corp.local/api/users/2", score=80, categories=["IDOR"]),
    ]
    res = asyncio.run(push_findings(
        fake, "https://ctf.corp.local", findings, tmp_path, min_score=50,
    ))
    # The legacy entry must dedupe the first finding; only the second is pushed.
    assert len(res.pushed_vulns) == 1
    assert len(fake.pushed) == 1
    assert fake.pushed[0]["info"].startswith("GET https://ctf.corp.local/api/users/2")

    # Sidecar must now hold both entries under the `vuln:` namespace.
    payload = json.loads(sidecar.read_text())
    assert "vuln:IDOR|https://ctf.corp.local/api/users/1" in payload
    assert "vuln:IDOR|https://ctf.corp.local/api/users/2" in payload
    # Legacy unprefixed key is gone (auto-promoted).
    assert legacy_key not in payload
