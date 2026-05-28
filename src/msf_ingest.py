"""
msf_ingest.py — Pull/push integration with a Metasploit Framework workspace.

Bridges hxxpsin into an operator's existing MSF engagement. Two backends:

  rpc  — msfrpcd (msgpack-RPC over HTTPS, /api/1.0/). Preferred.
  db   — direct PostgreSQL read of the msf database. Fallback when RPC is
         unreachable. Read-only by default; push uses the RPC client only.

Wired in at two pipeline hooks (see msf_ingest.augment_scope_from_msf and
msf_ingest.merge_msf_into_enrichment):

  Stage 0 recon — pulled hosts/services dedupe-merge into Scope.hosts
  Enrichment    — pulled creds/loot/notes attach to UserRecord/SecretRecord/
                  HostRecord with source = "msf:<workspace>"

After the report is assembled, main.py loops confirmed findings whose score
>= push_min_score and calls push_vuln() so the MSF workspace stays the
single source of truth for the engagement.

Both runtime deps are optional:
  msgpack — required for RPC; module degrades to DB-only if missing
  psycopg — required for DB; module degrades to RPC-only if missing
If both are missing OR the profile is disabled, make_msf_client() returns
None and the caller no-ops the integration.

The msf_pushed.json sidecar in the scan out dir makes push idempotent —
re-running the scan won't double-push vulns that already landed in MSF.
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Optional deps — imported lazily so disabled-by-default flow has zero cost
# ---------------------------------------------------------------------------

try:
    import msgpack  # type: ignore
    _MSGPACK_OK = True
except ImportError:
    msgpack = None  # type: ignore
    _MSGPACK_OK = False

try:
    import httpx  # already a hxxpsin dep — used for RPC over HTTPS
    _HTTPX_OK = True
except ImportError:
    httpx = None  # type: ignore
    _HTTPX_OK = False

try:
    import psycopg  # psycopg3
    _PSYCOPG_OK = True
except ImportError:
    psycopg = None  # type: ignore
    _PSYCOPG_OK = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MSFIngestError(Exception):
    """Base class for MSF ingest failures (caller logs + degrades)."""


class MSFConnectionError(MSFIngestError):
    """RPC/DB backend could not establish a connection."""


class MSFAuthError(MSFIngestError):
    """RPC/DB credentials were rejected."""


# ---------------------------------------------------------------------------
# Normalized data shapes — what both backends return / accept
# ---------------------------------------------------------------------------


@dataclass
class MSFHost:
    address: str
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_flavor: Optional[str] = None
    purpose: Optional[str] = None
    info: Optional[str] = None
    workspace: str = "default"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class MSFService:
    host: str
    port: int
    proto: str = "tcp"
    name: Optional[str] = None
    state: str = "open"
    info: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class MSFVuln:
    host: str
    name: str
    refs: list[str] = field(default_factory=list)
    service: Optional[str] = None
    info: Optional[str] = None
    msf_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, "", [])}


@dataclass
class MSFCred:
    host: Optional[str]
    service: Optional[str]
    public: Optional[str] = None        # username/email
    private: Optional[str] = None       # password/hash/key
    private_type: Optional[str] = None  # Password | NTLMHash | SSHKey | …
    realm: Optional[str] = None
    origin: Optional[str] = None        # filled by caller, e.g. "msf:<workspace>"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class MSFLoot:
    host: Optional[str]
    ltype: str
    path: Optional[str] = None
    content_type: str = "text/plain"
    info: Optional[str] = None
    data: Optional[bytes] = None  # populated when fetched inline

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("data", None)  # never serialise raw loot bytes by default
        if self.data is not None:
            d["data_bytes"] = len(self.data)
        return {k: v for k, v in d.items() if v not in (None, "")}


@dataclass
class MSFNote:
    host: Optional[str]
    ntype: str
    data: Any = None
    critical: bool = False

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class MSFSession:
    """Live MSF session (meterpreter/shell/powershell). Pulled via
    `session.list` so hxxpsin can warn the operator when MSF already owns
    the target host before we burn time scanning it."""
    id: int
    session_type: str = ""              # "meterpreter" | "shell" | "powershell"
    info: str = ""
    target_host: str = ""               # session target IP/hostname
    tunnel_peer: str = ""                # "<ip>:<port>" tunnel endpoint
    opened_at: str = ""
    via_exploit: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", 0)}


# ---------------------------------------------------------------------------
# Integration result — what gets fed to the Reporter
# ---------------------------------------------------------------------------


@dataclass
class MSFIngestResult:
    backend: str = ""                # "rpc" | "db" | ""
    workspace: str = ""
    pulled_hosts: int = 0
    pulled_services: int = 0
    pulled_vulns: int = 0
    pulled_creds: int = 0
    pulled_loot: int = 0
    pulled_notes: int = 0
    pulled_sessions: int = 0
    pushed_vulns: list[str] = field(default_factory=list)
    pushed_notes: list[str] = field(default_factory=list)
    pushed_loot: list[str] = field(default_factory=list)
    overlapped_hosts: list[str] = field(default_factory=list)
    sessions_on_target: list[dict] = field(default_factory=list)
    suggested_modules: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)  # warnings / soft errors

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Client base + concrete backends
# ---------------------------------------------------------------------------


class MSFClient:
    """Backend-agnostic surface every consumer codes against."""

    backend: str = ""
    workspace: str = "default"

    async def connect(self) -> None:
        raise NotImplementedError

    async def disconnect(self) -> None:
        return None

    # ----- pull --------------------------------------------------------
    async def fetch_hosts(self, workspace: str) -> list[MSFHost]:
        raise NotImplementedError

    async def fetch_services(self, workspace: str) -> list[MSFService]:
        raise NotImplementedError

    async def fetch_vulns(self, workspace: str) -> list[MSFVuln]:
        raise NotImplementedError

    async def fetch_credentials(self, workspace: str) -> list[MSFCred]:
        raise NotImplementedError

    async def fetch_loot(self, workspace: str) -> list[MSFLoot]:
        raise NotImplementedError

    async def fetch_notes(self, workspace: str) -> list[MSFNote]:
        raise NotImplementedError

    async def fetch_sessions(self, workspace: str) -> list[MSFSession]:
        # Default: backends that don't support live-session enumeration
        # (e.g. read-only DB on older MSF schemas) return [] gracefully.
        return []

    # ----- push --------------------------------------------------------
    async def push_vuln(self, host: str, service: Optional[str], name: str,
                        refs: list[str], info: str = "") -> str:
        raise NotImplementedError

    async def push_note(self, host: str, ntype: str, data: Any) -> str:
        raise NotImplementedError

    async def push_loot(self, host: str, ltype: str, content: bytes,
                        info: str = "", content_type: str = "text/plain") -> str:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# msfrpcd backend — msgpack-RPC over HTTPS at /api/1.0/
# ---------------------------------------------------------------------------


class MSFRPCBackend(MSFClient):
    """msfrpcd (msgpack-RPC) client. Auth flow:

        POST /api/1.0/   body = msgpack(["auth.login", user, pass])
        → response = {"result": "success", "token": "<token>"}

    Subsequent calls pass the token as the second arg (per the MSF RPC API)."""

    backend = "rpc"

    def __init__(self, host: str, port: int, user: str, password: str,
                 ssl_on: bool, workspace: str, timeout: float = 20.0,
                 db_connect_opts: Optional[dict] = None):
        if not _MSGPACK_OK:
            raise MSFIngestError("msgpack not installed — `pip install msgpack`")
        if not _HTTPX_OK:
            raise MSFIngestError("httpx not installed (should be unreachable)")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ssl_on = ssl_on
        self.workspace = workspace
        self.timeout = timeout
        # If set, MSFRPCBackend.connect() will call `db.connect` with these
        # opts after auth.login. Needed when msfrpcd hasn't autoloaded
        # database.yml (containerised deployments often hit this — the
        # autoload only fires in msfconsole, not msfrpcd, in some builds).
        # Expected keys: driver, host, port, database, username, password.
        self.db_connect_opts = db_connect_opts
        self._token: Optional[str] = None
        self._client: Optional[Any] = None  # httpx.AsyncClient

    @property
    def _endpoint(self) -> str:
        scheme = "https" if self.ssl_on else "http"
        return f"{scheme}://{self.host}:{self.port}/api/1.0/"

    async def connect(self) -> None:
        verify: Any = False if self.ssl_on else True  # msfrpcd ships self-signed by default
        try:
            self._client = httpx.AsyncClient(timeout=self.timeout, verify=verify)
            resp = await self._call("auth.login", self.user, self.password,
                                    use_token=False)
        except (httpx.HTTPError, OSError, ssl.SSLError) as exc:
            await self._safe_close_client()
            raise MSFConnectionError(f"msfrpcd unreachable at "
                                     f"{self.host}:{self.port}: {exc}") from exc
        if not isinstance(resp, dict) or resp.get("result") != "success":
            await self._safe_close_client()
            raise MSFAuthError(f"msfrpcd auth.login rejected: {resp!r}")
        token = resp.get("token")
        if not isinstance(token, str) or not token:
            await self._safe_close_client()
            raise MSFAuthError("msfrpcd returned no token")
        self._token = token

        if self.db_connect_opts:
            try:
                await self._call("db.connect", self.db_connect_opts)
            except MSFIngestError as exc:
                # Leave the client up — fetch_* will surface the underlying
                # ActiveRecord error on first use so callers can degrade
                # gracefully rather than failing the whole connect.
                pass

    async def disconnect(self) -> None:
        if self._token and self._client is not None:
            try:
                await self._call("auth.logout", self._token)
            except Exception:
                pass
        self._token = None
        await self._safe_close_client()

    async def _safe_close_client(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    async def _call(self, method: str, *args: Any, use_token: bool = True) -> Any:
        """Make one msgpack-RPC call. msfrpcd expects token as first positional
        argument after method name for all non-auth.* methods."""
        if self._client is None:
            raise MSFConnectionError("client closed")
        payload: list[Any] = [method]
        if use_token:
            if not self._token:
                raise MSFConnectionError("not authenticated")
            payload.append(self._token)
        payload.extend(args)
        body = msgpack.packb(payload, use_bin_type=True)
        try:
            r = await self._client.post(
                self._endpoint,
                content=body,
                headers={"Content-Type": "binary/message-pack"},
            )
        except httpx.HTTPError as exc:
            raise MSFConnectionError(f"RPC POST failed: {exc}") from exc
        if r.status_code >= 500:
            raise MSFConnectionError(f"RPC HTTP {r.status_code}")
        # Ruby's msgpack defaults to use_bin_type=False, so MSF's RPC server
        # packs string fields as BIN. msgpack.unpackb(raw=False) only decodes
        # the STR type to str — BIN values still come back as bytes, leaving
        # us with `{b'result': b'success'}` and silently-broken comparisons.
        # Walk the response once and best-effort-decode every bytes node.
        decoded = _decode_msgpack(msgpack.unpackb(r.content, raw=False))
        if isinstance(decoded, dict) and decoded.get("error"):
            err = decoded.get("error_message") or decoded.get("error_class") or "RPC error"
            raise MSFIngestError(f"{method}: {err}")
        return decoded

    # ----- pull ---------------------------------------------------------
    async def fetch_hosts(self, workspace: str) -> list[MSFHost]:
        out: list[MSFHost] = []
        for row in _list_from(await self._call("db.hosts", {"workspace": workspace})):
            out.append(MSFHost(
                address=_s(row, "address"),
                hostname=_s(row, "name") or None,
                os_name=_s(row, "os_name") or None,
                os_flavor=_s(row, "os_flavor") or None,
                purpose=_s(row, "purpose") or None,
                info=_s(row, "info") or None,
                workspace=workspace,
            ))
        return out

    async def fetch_services(self, workspace: str) -> list[MSFService]:
        out: list[MSFService] = []
        for row in _list_from(await self._call("db.services", {"workspace": workspace})):
            out.append(MSFService(
                host=_s(row, "host"),
                port=_i(row, "port"),
                proto=_s(row, "proto") or "tcp",
                name=_s(row, "name") or None,
                state=_s(row, "state") or "open",
                info=_s(row, "info") or None,
            ))
        return out

    async def fetch_vulns(self, workspace: str) -> list[MSFVuln]:
        out: list[MSFVuln] = []
        for row in _list_from(await self._call("db.vulns", {"workspace": workspace})):
            refs = row.get("refs") or []
            if not isinstance(refs, list):
                refs = []
            out.append(MSFVuln(
                host=_s(row, "host"),
                name=_s(row, "name"),
                refs=[str(r) for r in refs],
                service=_s(row, "service") or None,
                info=_s(row, "info") or None,
                msf_id=str(row.get("id")) if row.get("id") is not None else None,
            ))
        return out

    async def fetch_credentials(self, workspace: str) -> list[MSFCred]:
        out: list[MSFCred] = []
        # db.creds is the modern endpoint; falls back to a no-op on older
        # msfrpcd builds (the call raises MSFIngestError, we swallow & log).
        try:
            rows = _list_from(await self._call("db.creds", {"workspace": workspace}))
        except MSFIngestError:
            return out
        for row in rows:
            out.append(MSFCred(
                host=_s(row, "host") or None,
                service=_s(row, "sname") or _s(row, "service") or None,
                public=_s(row, "user") or _s(row, "public") or None,
                private=_s(row, "pass") or _s(row, "private") or None,
                private_type=_s(row, "ptype") or _s(row, "private_type") or None,
                realm=_s(row, "realm") or None,
                origin=f"msf:{workspace}",
            ))
        return out

    async def fetch_loot(self, workspace: str) -> list[MSFLoot]:
        out: list[MSFLoot] = []
        try:
            rows = _list_from(await self._call("db.loots", {"workspace": workspace}))
        except MSFIngestError:
            return out
        for row in rows:
            out.append(MSFLoot(
                host=_s(row, "host") or None,
                ltype=_s(row, "ltype") or _s(row, "type") or "unknown",
                path=_s(row, "path") or None,
                content_type=_s(row, "content_type") or _s(row, "ctype") or "text/plain",
                info=_s(row, "info") or _s(row, "name") or None,
            ))
        return out

    async def fetch_notes(self, workspace: str) -> list[MSFNote]:
        out: list[MSFNote] = []
        try:
            rows = _list_from(await self._call("db.notes", {"workspace": workspace}))
        except MSFIngestError:
            return out
        for row in rows:
            out.append(MSFNote(
                host=_s(row, "host") or None,
                ntype=_s(row, "ntype") or _s(row, "type") or "note",
                data=row.get("data"),
                critical=bool(row.get("critical")),
            ))
        return out

    async def fetch_sessions(self, workspace: str) -> list[MSFSession]:
        # session.list returns {<id>: {type, info, target_host, tunnel_peer,
        # opened_at, via_exploit, …}}. Workspace is not a filter dimension —
        # sessions are global to the msfconsole instance; we return all so
        # the caller can overlap-check against its target host.
        out: list[MSFSession] = []
        try:
            resp = await self._call("session.list")
        except MSFIngestError:
            return out
        if not isinstance(resp, dict):
            return out
        for sid, row in resp.items():
            if not isinstance(row, dict):
                continue
            try:
                sid_int = int(sid)
            except (TypeError, ValueError):
                continue
            out.append(MSFSession(
                id=sid_int,
                session_type=_s(row, "type"),
                info=_s(row, "info"),
                target_host=_s(row, "target_host") or _s(row, "session_host"),
                tunnel_peer=_s(row, "tunnel_peer"),
                opened_at=_s(row, "opened_at") or _s(row, "session_open"),
                via_exploit=_s(row, "via_exploit"),
            ))
        return out

    # ----- push ---------------------------------------------------------
    async def push_vuln(self, host: str, service: Optional[str], name: str,
                        refs: list[str], info: str = "") -> str:
        params: dict[str, Any] = {
            "workspace": self.workspace, "host": host, "name": name,
            "refs": list(refs), "info": info,
        }
        if service:
            params["service"] = service
        resp = await self._call("db.report_vuln", params)
        return _coerce_id(resp)

    async def push_note(self, host: str, ntype: str, data: Any) -> str:
        # db.report_note accepts {workspace, host, type, data}
        params = {"workspace": self.workspace, "host": host,
                  "type": ntype, "data": data}
        resp = await self._call("db.report_note", params)
        return _coerce_id(resp)

    async def push_loot(self, host: str, ltype: str, content: bytes,
                        info: str = "", content_type: str = "text/plain") -> str:
        # db.report_loot expects base64-encoded bytes in `data`
        params = {
            "workspace": self.workspace, "host": host, "type": ltype,
            "content_type": content_type, "info": info,
            "data": base64.b64encode(content).decode("ascii"),
        }
        resp = await self._call("db.report_loot", params)
        return _coerce_id(resp)


# ---------------------------------------------------------------------------
# Direct-PG fallback — read-only
# ---------------------------------------------------------------------------


class MSFDBBackend(MSFClient):
    """Read-only direct query of the msf Postgres database. Push operations
    raise MSFIngestError — set push_findings = false when this backend wins
    the auto-fallback."""

    backend = "db"

    def __init__(self, host: str, port: int, dbname: str, user: str,
                 password: str, workspace: str):
        if not _PSYCOPG_OK:
            raise MSFIngestError("psycopg not installed — `pip install psycopg[binary]`")
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password
        self.workspace = workspace
        self._conn: Optional[Any] = None

    def _dsn(self) -> str:
        return (f"host={self.host} port={self.port} dbname={self.dbname} "
                f"user={self.user} password={self.password}")

    async def connect(self) -> None:
        try:
            self._conn = await psycopg.AsyncConnection.connect(self._dsn())
        except psycopg.OperationalError as exc:
            msg = str(exc)
            if "authentication" in msg or "password" in msg.lower():
                raise MSFAuthError(f"msf db auth rejected: {exc}") from exc
            raise MSFConnectionError(f"msf db unreachable: {exc}") from exc

    async def disconnect(self) -> None:
        if self._conn is not None:
            try:
                await self._conn.close()
            except Exception:
                pass
            self._conn = None

    async def _wsid(self, workspace: str) -> Optional[int]:
        if self._conn is None:
            raise MSFConnectionError("not connected")
        async with self._conn.cursor() as cur:
            await cur.execute("SELECT id FROM workspaces WHERE name = %s", (workspace,))
            row = await cur.fetchone()
            return int(row[0]) if row else None

    # ----- pull ---------------------------------------------------------
    async def fetch_hosts(self, workspace: str) -> list[MSFHost]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFHost] = []
        async with self._conn.cursor() as cur:
            await cur.execute(
                "SELECT host(address), name, os_name, os_flavor, purpose, info "
                "FROM hosts WHERE workspace_id = %s", (wsid,),
            )
            async for row in cur:
                addr, name, os_name, os_flavor, purpose, info = row
                out.append(MSFHost(
                    address=addr, hostname=name, os_name=os_name,
                    os_flavor=os_flavor, purpose=purpose, info=info,
                    workspace=workspace,
                ))
        return out

    async def fetch_services(self, workspace: str) -> list[MSFService]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFService] = []
        async with self._conn.cursor() as cur:
            await cur.execute(
                "SELECT host(h.address), s.port, s.proto, s.name, s.state, s.info "
                "FROM services s JOIN hosts h ON h.id = s.host_id "
                "WHERE h.workspace_id = %s", (wsid,),
            )
            async for row in cur:
                addr, port, proto, name, state, info = row
                out.append(MSFService(
                    host=addr, port=int(port), proto=proto or "tcp",
                    name=name, state=state or "open", info=info,
                ))
        return out

    async def fetch_vulns(self, workspace: str) -> list[MSFVuln]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFVuln] = []
        async with self._conn.cursor() as cur:
            await cur.execute(
                "SELECT v.id, host(h.address), v.name, v.info "
                "FROM vulns v JOIN hosts h ON h.id = v.host_id "
                "WHERE h.workspace_id = %s", (wsid,),
            )
            rows = await cur.fetchall()
            ids = [r[0] for r in rows]
            refs_by_id: dict[int, list[str]] = {i: [] for i in ids}
            if ids:
                await cur.execute(
                    "SELECT vr.vuln_id, r.name FROM vulns_refs vr "
                    "JOIN refs r ON r.id = vr.ref_id WHERE vr.vuln_id = ANY(%s)",
                    (ids,),
                )
                async for vid, refname in cur:
                    refs_by_id.setdefault(vid, []).append(refname)
            for vid, addr, name, info in rows:
                out.append(MSFVuln(
                    host=addr, name=name or "", refs=refs_by_id.get(vid, []),
                    info=info, msf_id=str(vid),
                ))
        return out

    async def fetch_credentials(self, workspace: str) -> list[MSFCred]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFCred] = []
        async with self._conn.cursor() as cur:
            # MSF 5.x+ uses public/private tables joined via credentials.
            # Older versions had a single `creds` table — try both shapes.
            try:
                await cur.execute(
                    "SELECT host(h.address), s.name, pub.username, "
                    "priv.data, priv.type, r.realm_value "
                    "FROM credentials c "
                    "LEFT JOIN publics  pub  ON pub.id  = c.public_id "
                    "LEFT JOIN privates priv ON priv.id = c.private_id "
                    "LEFT JOIN realms   r    ON r.id    = c.realm_id "
                    "LEFT JOIN services s    ON s.id    = c.service_id "
                    "LEFT JOIN hosts    h    ON h.id    = s.host_id "
                    "WHERE c.workspace_id = %s", (wsid,),
                )
                async for row in cur:
                    addr, sname, public, private, ptype, realm = row
                    out.append(MSFCred(
                        host=addr, service=sname, public=public,
                        private=private, private_type=ptype,
                        realm=realm, origin=f"msf:{workspace}",
                    ))
            except psycopg.Error:
                # Older schema — best-effort, ignore missing
                pass
        return out

    async def fetch_loot(self, workspace: str) -> list[MSFLoot]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFLoot] = []
        async with self._conn.cursor() as cur:
            try:
                await cur.execute(
                    "SELECT host(h.address), l.ltype, l.path, l.content_type, l.info "
                    "FROM loots l LEFT JOIN hosts h ON h.id = l.host_id "
                    "WHERE l.workspace_id = %s", (wsid,),
                )
                async for row in cur:
                    addr, ltype, path, ctype, info = row
                    out.append(MSFLoot(
                        host=addr, ltype=ltype or "unknown", path=path,
                        content_type=ctype or "text/plain", info=info,
                    ))
            except psycopg.Error:
                pass
        return out

    async def fetch_notes(self, workspace: str) -> list[MSFNote]:
        wsid = await self._wsid(workspace)
        if wsid is None or self._conn is None:
            return []
        out: list[MSFNote] = []
        async with self._conn.cursor() as cur:
            try:
                await cur.execute(
                    "SELECT host(h.address), n.ntype, n.data, n.critical "
                    "FROM notes n LEFT JOIN hosts h ON h.id = n.host_id "
                    "WHERE n.workspace_id = %s", (wsid,),
                )
                async for row in cur:
                    addr, ntype, data, critical = row
                    out.append(MSFNote(
                        host=addr, ntype=ntype or "note", data=data,
                        critical=bool(critical),
                    ))
            except psycopg.Error:
                pass
        return out

    async def fetch_sessions(self, workspace: str) -> list[MSFSession]:
        # MSF's `sessions` table only holds historical session metadata;
        # live sessions live in the msfconsole process and are unavailable
        # via the DB backend. Best-effort: return historical rows when the
        # schema is present, else [].
        if self._conn is None:
            return []
        out: list[MSFSession] = []
        async with self._conn.cursor() as cur:
            try:
                await cur.execute(
                    "SELECT s.id, s.stype, s.desc, host(h.address), "
                    "s.opened_at, s.via_exploit "
                    "FROM sessions s LEFT JOIN hosts h ON h.id = s.host_id "
                    "ORDER BY s.id"
                )
                async for row in cur:
                    sid, stype, desc, addr, opened_at, via_exploit = row
                    out.append(MSFSession(
                        id=int(sid), session_type=stype or "",
                        info=desc or "", target_host=addr or "",
                        opened_at=str(opened_at) if opened_at else "",
                        via_exploit=via_exploit or "",
                    ))
            except psycopg.Error:
                pass
        return out

    # ----- push (not supported on direct-DB backend) --------------------
    async def push_vuln(self, host: str, service: Optional[str], name: str,
                        refs: list[str], info: str = "") -> str:
        raise MSFIngestError("push not supported on direct-DB backend "
                             "(use msfrpcd or disable push_findings)")

    async def push_note(self, host: str, ntype: str, data: Any) -> str:
        raise MSFIngestError("push not supported on direct-DB backend")

    async def push_loot(self, host: str, ltype: str, content: bytes,
                        info: str = "", content_type: str = "text/plain") -> str:
        raise MSFIngestError("push not supported on direct-DB backend")


# ---------------------------------------------------------------------------
# Constructor — RPC first, fall back to DB
# ---------------------------------------------------------------------------


async def make_msf_client(profile: Any) -> Optional[MSFClient]:
    """Build a connected MSFClient from an MSFProfile. Returns None when the
    profile is disabled OR neither backend can be reached.

    `profile` is duck-typed for the MSFProfile dataclass in auth_config.py to
    avoid an import cycle."""
    if profile is None or not getattr(profile, "enabled", False):
        return None
    workspace = getattr(profile, "workspace", "default") or "default"

    # 1. Try RPC if msgpack is available + creds are set
    rpc_pass = getattr(profile, "rpc_pass", "") or ""
    if _MSGPACK_OK and _HTTPX_OK and rpc_pass:
        # Pass DB opts so MSFRPCBackend.connect() can issue db.connect after
        # auth — covers deployments where msfrpcd doesn't autoload
        # database.yml. Only built if the profile has db credentials.
        db_pass_for_rpc = getattr(profile, "db_pass", "") or ""
        rpc_db_opts: Optional[dict] = None
        if db_pass_for_rpc:
            rpc_db_opts = {
                "driver": "postgresql",
                "host": getattr(profile, "db_host", "127.0.0.1"),
                "port": int(getattr(profile, "db_port", 5432)),
                "database": getattr(profile, "db_name", "msf"),
                "username": getattr(profile, "db_user", "msf"),
                "password": db_pass_for_rpc,
            }
        rpc = MSFRPCBackend(
            host=getattr(profile, "rpc_host", "127.0.0.1"),
            port=int(getattr(profile, "rpc_port", 55553)),
            user=getattr(profile, "rpc_user", "msf"),
            password=rpc_pass,
            ssl_on=bool(getattr(profile, "rpc_ssl", True)),
            workspace=workspace,
            db_connect_opts=rpc_db_opts,
        )
        try:
            await rpc.connect()
            return rpc
        except MSFIngestError:
            try:
                await rpc.disconnect()
            except Exception:
                pass
            # fall through to DB

    # 2. Try DB if psycopg is available + creds are set
    db_pass = getattr(profile, "db_pass", "") or ""
    if _PSYCOPG_OK and db_pass:
        db = MSFDBBackend(
            host=getattr(profile, "db_host", "127.0.0.1"),
            port=int(getattr(profile, "db_port", 5432)),
            dbname=getattr(profile, "db_name", "msf"),
            user=getattr(profile, "db_user", "msf"),
            password=db_pass,
            workspace=workspace,
        )
        try:
            await db.connect()
            return db
        except MSFIngestError:
            try:
                await db.disconnect()
            except Exception:
                pass

    raise MSFIngestError("no reachable MSF backend (RPC and DB both failed; "
                         "check msfrpcd is running and credentials are set)")


# ---------------------------------------------------------------------------
# Pipeline hooks — Stage 0 recon merge + enrichment merge
# ---------------------------------------------------------------------------


_LogCB = Optional[Callable[[str, dict], None]]


def _emit(cb: _LogCB, event: str, **fields: Any) -> None:
    if cb is None:
        return
    try:
        cb(event, dict(fields))
    except Exception:
        pass


async def augment_scope_from_msf(scope: Any, client: Optional[MSFClient],
                                 workspace: str,
                                 log_cb: _LogCB = None) -> MSFIngestResult:
    """Merge MSF workspace hosts/services into a hxxpsin Scope dataclass.

    Dedupe: skip MSF host if its hostname (or address) matches an existing
    Scope.hosts entry. Otherwise append a HostRecord with source =
    "msf:<workspace>". Open ports come from MSF service rows for the same
    address — handy for downstream port-scanning + vhost rotation.

    Returns a partially-filled MSFIngestResult — merge_msf_into_enrichment
    fills the rest."""
    res = MSFIngestResult(backend=client.backend if client else "",
                          workspace=workspace)
    if client is None:
        return res

    # Local import to avoid a hard dep at module import time
    try:
        from surface_mapper import HostRecord
    except Exception:
        return res

    try:
        msf_hosts = await client.fetch_hosts(workspace)
        msf_services = await client.fetch_services(workspace)
    except MSFIngestError as exc:
        res.notes.append(f"pull failed: {exc}")
        return res

    res.pulled_hosts = len(msf_hosts)
    res.pulled_services = len(msf_services)
    _emit(log_cb, "msf_pull",
          backend=client.backend, workspace=workspace,
          hosts=len(msf_hosts), services=len(msf_services))

    # Group services by host so each new HostRecord carries its open_ports
    svc_by_host: dict[str, list[MSFService]] = {}
    for s in msf_services:
        svc_by_host.setdefault(s.host, []).append(s)

    # Existing keys (hostname OR address) we already know about
    existing_keys: set[str] = set()
    for h in scope.hosts:
        if h.hostname:
            existing_keys.add(h.hostname.lower())
        for a in h.addresses:
            existing_keys.add(a)

    overlap: list[str] = []
    for mh in msf_hosts:
        key_host = (mh.hostname or "").lower()
        key_addr = mh.address
        if (key_host and key_host in existing_keys) or key_addr in existing_keys:
            overlap.append(mh.hostname or mh.address)
            continue
        hr = HostRecord(
            hostname=mh.hostname or mh.address,
            addresses=[mh.address] if mh.address else [],
            source=f"msf:{workspace}",
            open_ports=sorted({s.port for s in svc_by_host.get(mh.address, [])
                               if s.state == "open"}),
        )
        for s in svc_by_host.get(mh.address, []):
            if s.name:
                hr.banners[str(s.port)] = s.name
        scope.hosts.append(hr)
        existing_keys.add(hr.hostname.lower())
        if mh.address:
            existing_keys.add(mh.address)

    res.overlapped_hosts = overlap
    if overlap:
        scope.notes.append(
            f"msf:{workspace}: {len(overlap)} workspace hosts already in scope")
    return res


async def merge_msf_into_enrichment(result: Any, client: Optional[MSFClient],
                                    workspace: str,
                                    accum: Optional[MSFIngestResult] = None,
                                    log_cb: _LogCB = None) -> MSFIngestResult:
    """Pull creds/loot/notes/vulns and fold them into an EnrichmentResult.

    Creds → UserRecord.credentials with source = "msf:<workspace>".
    Loot/notes → SecretRecord with type_hint = "msf_loot"/"msf_note".
    Vulns → host's HostRecord.related_urls + a note.

    `accum` is the MSFIngestResult returned by augment_scope_from_msf —
    we mutate it in place so the Reporter sees one combined object."""
    res = accum or MSFIngestResult(backend=client.backend if client else "",
                                   workspace=workspace)
    if client is None:
        return res

    try:
        from enricher import (
            CredentialRecord, HostRecord as EnrHost, Provenance, SecretRecord,
            UserRecord,
        )
    except Exception:
        res.notes.append("merge failed: enricher symbols not importable")
        return res

    try:
        creds = await client.fetch_credentials(workspace)
        loot = await client.fetch_loot(workspace)
        notes = await client.fetch_notes(workspace)
        vulns = await client.fetch_vulns(workspace)
    except MSFIngestError as exc:
        res.notes.append(f"merge fetch failed: {exc}")
        return res

    res.pulled_creds = len(creds)
    res.pulled_loot = len(loot)
    res.pulled_notes = len(notes)
    res.pulled_vulns = len(vulns)
    _emit(log_cb, "msf_merge",
          backend=client.backend, workspace=workspace,
          creds=len(creds), loot=len(loot), notes=len(notes), vulns=len(vulns))

    origin = f"msf:{workspace}"
    prov_url = f"msf://{workspace}"

    # ----- credentials → users -----
    for c in creds:
        if not (c.public or c.private):
            continue
        # Use public identity as the canonical key
        canonical = (c.public or f"msf-cred-{id(c)}").strip()
        user = result.users.get(canonical)
        if user is None:
            user = UserRecord(canonical_id=canonical)
            result.users[canonical] = user
        if c.public:
            # Treat as username unless it looks like an email
            if "@" in c.public:
                user.emails.add(c.public)
            else:
                user.usernames.add(c.public)
        if c.private:
            algo = "plaintext"
            ptype = (c.private_type or "").lower()
            if "hash" in ptype or "ntlm" in ptype or "md5" in ptype:
                algo = ptype or "hash"
            cred_type = "password"
            if "key" in ptype:
                cred_type = "private_key"
            elif "hash" in ptype or "ntlm" in ptype:
                cred_type = "hash"
            user.credentials.append(CredentialRecord(
                cred_type=cred_type, algo=algo, value=c.private,
                source_url=prov_url,
                source_json_path=f"$.msf.creds.{c.service or 'service'}",
            ))
            if cred_type == "password" and algo == "plaintext":
                user.auth_credentials.setdefault("password", c.private)
        user.provenance.append(Provenance(
            url=prov_url, method="MSF",
            json_path=f"$.creds[{c.service or '*'}@{c.host or '*'}]",
            snippet=f"{origin} cred public={c.public or '-'} "
                    f"type={c.private_type or 'plaintext'}",
        ))

    # ----- loot → secrets -----
    for l in loot:
        token = l.path or f"{l.ltype}@{l.host or 'unknown'}"
        sha_prefix = _short_hash(token)
        sec = result.secrets.get(sha_prefix)
        if sec is None:
            sec = SecretRecord(
                sha_prefix=sha_prefix, value=token,
                type_hint=f"msf_loot:{l.ltype}", entropy=0.0,
            )
            result.secrets[sha_prefix] = sec
        if len(sec.provenance) < 50:
            sec.provenance.append(Provenance(
                url=prov_url, method="MSF",
                json_path=f"$.loot[{l.ltype}]",
                snippet=f"{origin} loot host={l.host or '-'} info={l.info or '-'}",
            ))

    # ----- notes → secrets (lightweight, type-hinted) -----
    for n in notes:
        token = f"{n.ntype}@{n.host or 'unknown'}"
        sha_prefix = _short_hash(token + json.dumps(n.data, default=str, sort_keys=True)[:200])
        sec = result.secrets.get(sha_prefix)
        if sec is None:
            sec = SecretRecord(
                sha_prefix=sha_prefix,
                value=json.dumps(n.data, default=str)[:200] if n.data is not None else token,
                type_hint=f"msf_note:{n.ntype}", entropy=0.0,
            )
            result.secrets[sha_prefix] = sec
        if len(sec.provenance) < 50:
            sec.provenance.append(Provenance(
                url=prov_url, method="MSF",
                json_path=f"$.notes[{n.ntype}]",
                snippet=f"{origin} note host={n.host or '-'} "
                        f"critical={n.critical}",
            ))

    # ----- vulns → hosts -----
    for v in vulns:
        if not v.host:
            continue
        hr = result.hosts.get(v.host)
        if hr is None:
            hr = EnrHost(hostname=v.host)
            result.hosts[v.host] = hr
        if v.refs:
            for ref in v.refs[:8]:
                hr.related_urls.add(f"msf-vuln:{ref}")
        if len(hr.provenance) < 100:
            hr.provenance.append(Provenance(
                url=prov_url, method="MSF",
                json_path=f"$.vulns[{v.name}]",
                snippet=f"{origin} vuln {v.name} refs={','.join(v.refs[:4])}",
            ))

    return res


# ---------------------------------------------------------------------------
# Live-session pull + module suggestions
# ---------------------------------------------------------------------------


# Static map from classifier.Cat string values → MSF module-name keywords.
# Kept in sync with src/classifier.py:Cat. Categories with no high-signal
# module mapping fall through to [] (no suggestion offered).
_CAT_TO_MODULE_KEYWORDS: dict[str, list[str]] = {
    "SSRF Surface":                  ["ssrf", "fetch"],
    "File Upload":                   ["upload", "file"],
    "GraphQL":                       ["graphql"],
    "WebSocket":                     ["websocket", "ws"],
    "Windows Auth (NTLM/Kerberos)":  ["ntlm", "kerberos", "smb"],
    "Open Redirect":                 ["redirect"],
    "Injection":                     ["sqli", "injection"],
    "NoSQL Injection":               ["nosql"],
    "Exposed Secrets":               ["aws", "gcp", "azure"],
    "Admin/Internal Exposure":       ["admin", "manager"],
}


async def suggest_modules(client: Optional[MSFClient], finding: Any,
                          *, limit: int = 5) -> list[str]:
    """Return up to `limit` MSF module-name keyword hints for a single
    finding, derived from its categories via _CAT_TO_MODULE_KEYWORDS.
    Returns [] when no category maps. `client` is reserved for a future
    optional `module.search` refinement; not used in PR 1."""
    cats = list(getattr(finding, "categories", []) or [])
    seen: list[str] = []
    for c in cats:
        for kw in _CAT_TO_MODULE_KEYWORDS.get(str(c), []):
            if kw not in seen:
                seen.append(kw)
            if len(seen) >= limit:
                return seen[:limit]
    return seen[:limit]


async def pull_sessions_into_result(client: Optional[MSFClient], target: str,
                                    workspace: str,
                                    result: MSFIngestResult,
                                    log_cb: _LogCB = None) -> MSFIngestResult:
    """Pull live MSF sessions and populate result.pulled_sessions +
    result.sessions_on_target (sessions whose target_host matches the
    URL's hostname). Mutates `result` in place and returns it. Soft-degrades
    on backend errors — never raises."""
    if client is None:
        return result
    try:
        sessions = await client.fetch_sessions(workspace)
    except MSFIngestError as exc:
        result.notes.append(f"sessions pull failed: {exc}")
        return result
    result.pulled_sessions = len(sessions)
    target_host = (urlparse(target).hostname or "").strip().lower()
    if target_host:
        for s in sessions:
            if (s.target_host or "").strip().lower() == target_host:
                result.sessions_on_target.append(s.to_dict())
    _emit(log_cb, "msf_pull",
          backend=client.backend, workspace=workspace,
          sessions=len(sessions),
          sessions_on_target=len(result.sessions_on_target))
    return result


# ---------------------------------------------------------------------------
# Push loop — idempotent via msf_pushed.json sidecar
# ---------------------------------------------------------------------------


async def push_findings(client: Optional[MSFClient], target: str,
                        findings: Iterable[Any], out_dir: Path,
                        min_score: int = 50,
                        accum: Optional[MSFIngestResult] = None,
                        log_cb: _LogCB = None) -> MSFIngestResult:
    """For each finding with score >= min_score, push as an MSF vuln and
    record the returned id in {out_dir}/msf_pushed.json so re-runs are
    idempotent.

    `findings` is duck-typed for classifier.Finding (or any object exposing
    .url, .score, .categories)."""
    res = accum or MSFIngestResult(backend=client.backend if client else "",
                                   workspace=getattr(client, "workspace", "") or "")
    if client is None:
        return res

    sidecar = out_dir / "msf_pushed.json"
    pushed_cache = _load_sidecar(sidecar)

    target_host = (urlparse(target).hostname or target or "").strip()
    if not target_host:
        res.notes.append("push: no target host derivable from target URL")
        return res

    new_pushed: list[str] = []
    for f in findings:
        score = int(getattr(f, "score", 0) or 0)
        if score < min_score:
            continue
        url = getattr(f, "url", "") or ""
        cats = list(getattr(f, "categories", []) or [])
        key = f"vuln:{','.join(cats) or 'finding'}|{url}"
        if key in pushed_cache:
            continue
        name = ("hxxpsin: " + ",".join(cats[:3])) if cats else "hxxpsin finding"
        info = f"{getattr(f, 'method', 'GET')} {url} (score={score})"
        try:
            vid = await client.push_vuln(
                host=target_host,
                service="http" if url.startswith("http://") else "https",
                name=name, refs=[], info=info,
            )
        except MSFIngestError as exc:
            res.notes.append(f"push {key[:80]}: {exc}")
            continue
        pushed_cache[key] = vid
        new_pushed.append(vid)
        _emit(log_cb, "msf_push", id=vid, score=score, url=url[:120])

    if new_pushed:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            sidecar.write_text(json.dumps(pushed_cache, indent=2, sort_keys=True))
        except Exception as exc:
            res.notes.append(f"sidecar write failed: {exc}")

    res.pushed_vulns.extend(new_pushed)
    return res


# ---------------------------------------------------------------------------
# Tiny utilities
# ---------------------------------------------------------------------------


def _decode_msgpack(obj: Any) -> Any:
    """Recursively coerce msgpack-decoded bytes to str. MSF's Ruby RPC server
    packs strings as BIN (use_bin_type=False), so even raw=False unpack
    leaves us with bytes in place of str. Binary blobs that aren't valid
    UTF-8 (e.g. loot data) are left as bytes."""
    if isinstance(obj, dict):
        return {_decode_msgpack(k): _decode_msgpack(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode_msgpack(x) for x in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj
    return obj


def _list_from(resp: Any) -> list[dict]:
    """msfrpcd db.* methods return either a list of dicts or a dict with a
    `hosts`/`services`/`vulns`/… key containing the list. Normalise."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if isinstance(resp, dict):
        for k in ("hosts", "services", "vulns", "creds", "credentials",
                  "loots", "notes", "records"):
            v = resp.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _s(row: dict, key: str) -> str:
    v = row.get(key)
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(v)


def _i(row: dict, key: str) -> int:
    try:
        return int(row.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _coerce_id(resp: Any) -> str:
    """msfrpcd push responses come back as {"result": "success", "id": N}
    or just {"result": "success"} on older builds — return the id when
    present, else a synthetic key the sidecar can still dedupe on."""
    if isinstance(resp, dict):
        for k in ("id", "vuln_id", "note_id", "loot_id"):
            if k in resp and resp[k] is not None:
                return str(resp[k])
        if resp.get("result") == "success":
            return "ok"
    return str(resp)[:64]


def _short_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]


_SIDECAR_PREFIXES = ("vuln:", "cred:", "loot:", "note:")


def _load_sidecar(sidecar: Path) -> dict[str, str]:
    """Load msf_pushed.json and auto-promote round-1 unprefixed keys to the
    `vuln:` namespace so PR-2 push types can share the file without colliding
    with the legacy schema. Returns {} on missing/corrupt sidecar."""
    if not sidecar.exists():
        return {}
    try:
        raw = json.loads(sidecar.read_text())
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str):
            continue
        if k.startswith(_SIDECAR_PREFIXES):
            out[k] = str(v)
        else:
            out[f"vuln:{k}"] = str(v)
    return out
