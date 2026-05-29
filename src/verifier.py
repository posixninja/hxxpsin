"""
verifier.py — Active verification of classifier findings.

Makes targeted HTTP probes to confirm whether heuristic findings represent
real vulnerabilities. Each category has a specific verification strategy:

  IDOR        — enumerate adjacent numeric IDs, check data leaks across objects
  Admin       — request the path, check status + admin-looking response content
  GraphQL     — probe introspection, check for schema data in response body
  SSRF        — inject internal vs external URL, compare status/time/body
  Mass Assign — PATCH privilege fields, check if echoed back or applied
  Injection   — SQL/SSTI/XSS payloads, check for error signatures or reflections
  Upload      — POST minimal file, check if server accepts it
  BFLA        — send privileged action without/with low-priv auth, check 200 vs 403
  Auth/Session — probe for JWT/token disclosure in unauthenticated responses

Verdicts:
  confirmed      High confidence the vulnerability is real (0.8–1.0)
  likely         Strong signal but not definitive (0.5–0.79)
  not_confirmed  Probes returned no signal (< 0.5)
  skipped        No actionable probe strategy for this finding
  error          Network / timeout error during probe
"""

import asyncio
import re
import time
from dataclasses import dataclass, field

try:
    from confidence import from_verifier_verdict, promote_verdict
except ImportError:
    from_verifier_verdict = promote_verdict = None  # type: ignore
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx

from classifier import Cat

# Paths that signal a redirect to an auth/home page rather than the real resource
_AUTH_REDIRECT_RE = re.compile(
    r"/(login|signin|sign-?in|auth|welcome|home|index|dashboard|start)(\?|$|/)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    url: str
    method: str
    categories: list[str]
    verdict: str           # confirmed | likely | not_confirmed | skipped | error
    confidence: float      # 0.0–1.0
    evidence: str
    probe_url: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    status_code: int = 0

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == "confirmed"

    @property
    def is_actionable(self) -> bool:
        return self.verdict in ("confirmed", "likely")


@dataclass
class VerifyReport:
    results: list[VerifyResult] = field(default_factory=list)

    @property
    def confirmed(self) -> list[VerifyResult]:
        return [r for r in self.results if r.verdict == "confirmed"]

    @property
    def likely(self) -> list[VerifyResult]:
        return [r for r in self.results if r.verdict == "likely"]

    @property
    def actionable(self) -> list[VerifyResult]:
        return [r for r in self.results if r.is_actionable]

    def to_dict(self) -> dict:
        return {
            "confirmed": len(self.confirmed),
            "likely": len(self.likely),
            "total_probed": len(self.results),
            "results": [
                {
                    "url": r.url, "method": r.method,
                    "categories": r.categories, "verdict": r.verdict,
                    "confidence": round(r.confidence, 2), "evidence": r.evidence,
                    "probe_url": r.probe_url, "status_code": r.status_code,
                    "response_snippet": r.response_snippet,
                }
                for r in self.results
            ],
        }


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_SQL_ERRORS = re.compile(
    r"(you have an error in your sql|syntax error|unterminated quoted|"
    r"ora-\d{4,}|sqlite_error|pg::syntax|postgresql.*error|"
    r"microsoft ole db|odbc sql server|unclosed quotation|"
    r"division by zero|invalid column name|column.*does not exist|"
    r"no such column|sqlexception|jdbcexception)",
    re.IGNORECASE,
)

_SSTI_PAYLOADS = [
    ("{{7*7}}",         "49"),
    ("${7*7}",          "49"),
    ("<%= 7*7 %>",      "49"),
    ("#{7*7}",          "49"),
    ("%{7*7}",          "49"),
]

_SSTI_ERRORS = re.compile(
    r"(jinja2\.exceptions|templatenotfound|twig_error|freemarker|"
    r"smartyexception|pebbleexception|velocity error|"
    r"expression language error|el evaluation)",
    re.IGNORECASE,
)

# XSS context probes: (payload, context_name, detection_re)
# Tests HTML body, HTML attribute breakout, and JS context separately.
# Sources: ihebski/XSS-Payloads, PortSwigger XSS cheat sheet
_XSS_PROBES: list[tuple[str, str, re.Pattern]] = [
    ("<hxxpsinX>",          "html",  re.compile(r"<hxxpsinX>",          re.I)),
    ('"><hxxpsinA>',        "attr",  re.compile(r'"><hxxpsinA>',        re.I)),
    ("</script><hxxpsinJ>", "js",    re.compile(r"</script><hxxpsinJ>", re.I)),
]

# Strong CSP blocks inline script execution — XSS is still present but not directly exploitable
_CSP_BLOCKS_INLINE = re.compile(
    r"script-src[^;]*(('none'|'nonce-[^']+'))[^;]*",
    re.IGNORECASE,
)

_ADMIN_CONTENT_RE = re.compile(
    r"(admin\s+panel|dashboard|management\s+console|user\s+list|"
    r"system\s+settings|site\s+config|access\s+control|audit\s+log|"
    r"manage\s+users?|role\s+management)",
    re.IGNORECASE,
)

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')

# Expanded SSRF internal targets — from PAT SSRF-Cloud-Instances.md + bypass techniques
_INTERNAL_IPS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",                                           # IPv6 loopback
    "http://0/",                                              # short-hand zero
    "http://127.1",                                           # CIDR short
    "http://127.0.0.1.nip.io",                               # domain-redirect bypass
    "http://169.254.169.254/latest/meta-data/",               # AWS IMDS v1
    "http://[fd00:ec2::254]/latest/meta-data/",               # AWS IMDS IPv6
    "http://metadata.google.internal/computeMetadata/v1/",   # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
    "http://100.100.100.200/latest/meta-data/",               # Alibaba Cloud
    "http://169.254.169.254/metadata/v1/",                    # Digital Ocean
    "http://kubernetes.default.svc/api/v1",                   # K8s API server
    "http://192.168.0.1",                                     # Local network gateway
]
# Replaced at runtime when canary.py is available; kept as timing-signal fallback
_SSRF_CANARY_EXTERNAL = "http://ssrf-canary.test.invalid"

# Open-redirect parameter names
_REDIRECT_PARAM_RE = re.compile(
    r"^(redirect|redirect_url|redirect_uri|next|return|return_url|return_to|"
    r"redir|rurl|target|dest|destination|goto|url|link|forward|go|continue|"
    r"callback|success|back|location|to|out)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Module-level inject helpers — importable by active_scanner.py
# ---------------------------------------------------------------------------

def inject_url_param(
    url: str,
    params: dict,
    param_name: Optional[str],
    inject_value: str,
    body: Optional[str],
    method: str,
) -> tuple[str, Optional[str]]:
    """Replace the URL-like param with inject_value; fall back to JSON body injection."""
    import json as _json
    if param_name and params:
        new_params = dict(params)
        new_params[param_name] = inject_value
        parsed = urlparse(url)
        return parsed._replace(query=urlencode(new_params)).geturl(), None
    if body:
        try:
            bd = _json.loads(body)
            for kw in ("url", "webhook", "callback", "redirect", "endpoint", "target"):
                if kw in bd:
                    bd[kw] = inject_value
                    break
            else:
                bd["url"] = inject_value
            return url, _json.dumps(bd)
        except Exception:
            pass
    return url, f'{{"url":"{inject_value}"}}'


def inject_param(
    url: str,
    params: dict,
    param_name: Optional[str],
    payload: str,
    body: Optional[str],
    method: str,
) -> tuple[str, Optional[str]]:
    """Inject payload into the named param (query string or JSON body first key)."""
    import json as _json
    if param_name and params:
        new_params = dict(params)
        new_params[param_name] = payload
        parsed = urlparse(url)
        return parsed._replace(query=urlencode(new_params)).geturl(), None
    if body:
        try:
            bd = _json.loads(body)
            if bd:
                first_key = next(iter(bd))
                bd[first_key] = payload
                return url, _json.dumps(bd)
        except Exception:
            pass
    return url, None


# ---------------------------------------------------------------------------
# Core verifier
# ---------------------------------------------------------------------------

class Verifier:
    def __init__(
        self,
        findings: list,
        auth_headers: Optional[dict] = None,
        timeout: float = 6.0,
        origin: str = "",
        max_findings: int = 40,
        canary=None,     # Optional[Canary] from canary.py — enables OOB SSRF detection
        http_cache=None,  # Optional[HttpCache] — shared probe HTTP layer
    ):
        self.findings = findings[:max_findings]
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.origin = origin
        self.canary = canary
        self.http_cache = http_cache
        # Soft-404 baseline, set by _calibrate() before the run
        self._soft404: Optional[tuple[int, str, int]] = None  # (status, location, body_len)

    async def run(self) -> VerifyReport:
        from probe_http import open_probe_client

        async with open_probe_client(
            self.http_cache,
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers=self.auth_headers,
        ) as client:
            await self._calibrate(client)
            tasks = [self._verify_one(client, f) for f in self.findings]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        report = VerifyReport()
        for r in results:
            if isinstance(r, VerifyResult):
                report.results.append(r)
        return report

    async def _calibrate(self, client: httpx.AsyncClient) -> None:
        """Establish soft-404 fingerprint using a sentinel path on the same origin."""
        if not self.findings:
            return
        base = self.origin or self.findings[0].url
        parsed = urlparse(base)
        sentinel = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}/hxxpsin-sentinel-8a3f"
        try:
            resp = await client.get(sentinel, follow_redirects=False)
            self._soft404 = (resp.status_code, resp.headers.get("location", ""), len(resp.content))
        except Exception:
            self._soft404 = None

    def _looks_like_soft404(self, resp: httpx.Response) -> bool:
        """True if the response matches the soft-404 baseline or is a login redirect."""
        if resp.status_code in (404, 410):
            return True
        # Redirect to a login/home page
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location", "")
            if _AUTH_REDIRECT_RE.search(loc):
                return True
        # Hard 404 after following redirects — check final URL
        final_path = urlparse(str(resp.url)).path
        if _AUTH_REDIRECT_RE.search(final_path) and resp.status_code == 200:
            # We landed on a login/home page after following redirects
            return True
        # Compare against soft-404 baseline
        if self._soft404:
            base_status, base_loc, base_len = self._soft404
            loc = resp.headers.get("location", "")
            if resp.status_code == base_status and loc == base_loc:
                return True
            if (resp.status_code == base_status and base_len > 0
                    and abs(len(resp.content) - base_len) / base_len < 0.05):
                return True
        return False

    async def _verify_one(self, client: httpx.AsyncClient, finding) -> VerifyResult:
        cats = finding.categories
        try:
            if Cat.GRAPHQL in cats:
                return await self._verify_graphql(client, finding)
            if Cat.ADMIN in cats:
                return await self._verify_admin(client, finding)
            if Cat.SSRF in cats:
                return await self._verify_ssrf(client, finding)
            if Cat.INJECTION in cats:
                return await self._verify_injection(client, finding)
            if Cat.MASS_ASSIGN in cats:
                return await self._verify_mass_assign(client, finding)
            if Cat.IDOR in cats:
                return await self._verify_idor(client, finding)
            if Cat.UPLOAD in cats:
                return await self._verify_upload(client, finding)
            if Cat.BFLA in cats:
                return await self._verify_bfla(client, finding)
            if Cat.AUTH in cats:
                return await self._verify_auth(client, finding)
            if Cat.RACE in cats:
                return await self._verify_race(client, finding)
            if Cat.WRITE in cats:
                return await self._verify_write(client, finding)
            if Cat.CORS in cats:
                return await self._verify_cors_finding(client, finding)
            if Cat.REDIRECT in cats:
                return await self._verify_open_redirect(client, finding)
            if Cat.NOSQL in cats:
                return await self._verify_nosql(client, finding)
            return self._skipped(finding, "no verification strategy for categories")
        except Exception as exc:
            return self._error(finding, str(exc))

    # -----------------------------------------------------------------------
    # Per-category verifiers
    # -----------------------------------------------------------------------

    async def _verify_idor(self, client, finding) -> VerifyResult:
        url = finding.url
        parsed = urlparse(url)

        resp = await self._get(client, url)
        if resp is None:
            return self._error(finding, "request failed")
        if self._looks_like_soft404(resp):
            return self._not_confirmed(
                finding, f"endpoint returns {resp.status_code} or redirects to login — does not exist", resp
            )
        if resp.status_code not in (200, 201):
            return self._not_confirmed(
                finding, f"status {resp.status_code} — endpoint not accessible", resp
            )

        # Find a numeric ID segment to enumerate
        id_match = re.search(r"/(\d{1,10})(?:/|$|\?)", parsed.path)
        if not id_match:
            return self._likely(
                finding,
                f"endpoint returns {resp.status_code} but no numeric ID to enumerate",
                resp, url,
            )

        original_id = int(id_match.group(1))
        baseline_body = resp.content
        baseline_len = len(baseline_body)
        hits: list[int] = []

        for delta in (1, -1, 2, 10, 100):
            adj_id = original_id + delta
            if adj_id <= 0:
                continue
            adj_url = url.replace(f"/{original_id}", f"/{adj_id}", 1)
            adj = await self._get(client, adj_url)
            if adj is None or adj.status_code != 200 or len(adj.content) < 30:
                continue
            # Body must differ from baseline — identical bodies mean the server
            # returns the same generic response for any ID (not a data leak).
            if adj.content == baseline_body:
                continue
            # Reject if the adjacent response looks like a soft-404 / error page
            # (much smaller than baseline or contains error patterns).
            if self._looks_like_soft404(adj):
                continue
            hits.append(adj_id)
            if len(hits) >= 2:
                break

        if hits:
            return self._confirmed(
                finding,
                f"ID enumeration: IDs {hits} return 200 with distinct data ({baseline_len}B baseline)",
                resp, url,
            )
        return self._likely(
            finding,
            f"endpoint returns 200 ({baseline_len}B) — adjacent IDs returned no distinct data",
            resp, url,
        )

    async def _verify_admin(self, client, finding) -> VerifyResult:
        url = finding.url
        resp = await self._get(client, url)
        if resp is None:
            return self._error(finding, "request failed")
        if self._looks_like_soft404(resp):
            return self._not_confirmed(
                finding, f"path returns {resp.status_code} or redirects to login — does not exist", resp
            )

        if resp.status_code == 200:
            body = resp.text[:2000]
            if _ADMIN_CONTENT_RE.search(body):
                return self._confirmed(
                    finding,
                    f"admin path returns 200 with admin-looking content",
                    resp, url,
                )
            return self._likely(
                finding,
                f"admin path returns 200 ({len(resp.content)}B) — review content manually",
                resp, url,
            )

        if resp.status_code == 403:
            return self._likely(
                finding,
                "admin path returns 403 — endpoint exists but requires higher privilege",
                resp, url,
            )

        return self._not_confirmed(
            finding, f"admin path returns {resp.status_code}", resp
        )

    async def _verify_graphql(self, client, finding) -> VerifyResult:
        url = finding.url
        # Pre-flight: confirm the endpoint exists before sending introspection
        pre = await self._get(client, url)
        if pre is not None and self._looks_like_soft404(pre):
            return self._not_confirmed(finding, f"GraphQL path returns {pre.status_code} — does not exist", pre)
        introspection = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
        try:
            resp = await client.post(
                url,
                content=introspection,
                headers={**self.auth_headers, "Content-Type": "application/json"},
            )
        except Exception as exc:
            return self._error(finding, str(exc))

        body = resp.text[:1000]
        if "__schema" in body or "queryType" in body:
            return self._confirmed(
                finding,
                "GraphQL introspection enabled — full schema exposed",
                resp, url,
            )
        if '"errors"' in body and "introspection" in body.lower():
            return self._likely(
                finding,
                "GraphQL endpoint active but introspection disabled — mutation/query fuzzing still applicable",
                resp, url,
            )
        if resp.status_code == 200 and '"data"' in body:
            return self._likely(
                finding, "GraphQL endpoint returns data", resp, url,
            )
        return self._not_confirmed(finding, f"status {resp.status_code}, no schema data", resp)

    async def _verify_ssrf(self, client, finding) -> VerifyResult:
        url = finding.url
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        url_param = self._find_url_param(finding, params)
        if not url_param and not finding.body:
            return self._skipped(finding, "cannot identify URL parameter to inject")

        # Use OOB canary URL if available, otherwise fall back to timing-signal URL
        canary_url = (self.canary.generate("ssrf") if self.canary and self.canary.available else "") or _SSRF_CANARY_EXTERNAL

        results: dict[str, tuple[int, float, int]] = {}
        probes = [("internal_loopback", "http://127.0.0.1:80"),
                  ("aws_imds",          "http://169.254.169.254/latest/meta-data/"),
                  ("external_canary",   canary_url)]

        for label, inject_url in probes:
            probe_req_url, probe_body = self._inject_url_param(
                url, params, url_param, inject_url, finding.body, finding.method
            )
            t0 = time.monotonic()
            try:
                r = await client.request(
                    finding.method, probe_req_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                elapsed = time.monotonic() - t0
                results[label] = (r.status_code, elapsed, len(r.content))
            except Exception:
                results[label] = (-1, 0.0, 0)

        internal = results.get("internal_loopback", (-1, 0, 0))
        external = results.get("external_canary", (-1, 0, 0))

        # Internal got a real response but external failed = server made the request
        if internal[0] in (200, 403, 401) and external[0] == -1:
            return self._confirmed(
                finding,
                f"SSRF: 127.0.0.1 → {internal[0]}, external canary → connection error (server made the request)",
                None, url,
            )
        # Significantly different response bodies
        if internal[0] > 0 and external[0] > 0 and abs(internal[2] - external[2]) > 100:
            return self._likely(
                finding,
                f"SSRF: internal response {internal[2]}B vs external {external[2]}B — server fetches URLs",
                None, url,
            )
        if results.get("aws_imds", (-1,))[0] == 200:
            return self._confirmed(
                finding, "SSRF: AWS IMDS (169.254.169.254) returned 200", None, url
            )

        # OOB canary check — if interactsh, wait briefly for callback
        if self.canary and self.canary.available:
            hits = await self.canary.poll(timeout=5.0)
            if hits:
                return self._confirmed(
                    finding,
                    f"SSRF confirmed via OOB callback ({hits[0].protocol}) from {hits[0].remote_address}",
                    None, url,
                    oob_hit=True,
                )

        return self._not_confirmed(finding, "internal and external URL probes returned similar responses", None)

    async def _verify_mass_assign(self, client, finding) -> VerifyResult:
        url = finding.url
        priv_body = '{"role":"admin","is_admin":true,"plan":"enterprise","status":"active"}'

        try:
            resp = await client.request(
                finding.method, url,
                content=priv_body,
                headers={**self.auth_headers, "Content-Type": "application/json"},
            )
        except Exception as exc:
            return self._error(finding, str(exc))

        body = resp.text[:500]
        if resp.status_code in (200, 201, 204):
            # Check if privilege fields were echoed back
            if any(kw in body.lower() for kw in ('"role"', '"is_admin"', '"admin"', '"plan"')):
                return self._confirmed(
                    finding,
                    f"Mass assignment: privilege fields echoed in {resp.status_code} response",
                    resp, url,
                )
            return self._likely(
                finding,
                f"Endpoint accepts {finding.method} with privilege fields (status {resp.status_code}) — verify if applied",
                resp, url,
            )

        return self._not_confirmed(
            finding, f"Server returned {resp.status_code} — request rejected", resp
        )

    async def _verify_injection(self, client, finding) -> VerifyResult:
        url = finding.url
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        pre = await self._get(client, url)
        if pre is not None and self._looks_like_soft404(pre):
            return self._not_confirmed(finding, f"endpoint returns {pre.status_code} — does not exist", pre)

        # Find the injectable param
        inj_param = self._find_inject_param(finding, params)

        # SQL injection probe
        for payload in ("'", '"', "' OR '1'='1"):
            probe_url, probe_body = self._inject_param(
                url, params, inj_param, payload, finding.body, finding.method
            )
            try:
                r = await client.request(
                    finding.method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                body = r.text[:2000]
                if _SQL_ERRORS.search(body):
                    return self._confirmed(
                        finding,
                        f"SQL injection: payload {payload!r} triggered error in response",
                        r, probe_url,
                    )
            except Exception:
                pass

        # SSTI probe
        for payload, expected in _SSTI_PAYLOADS:
            probe_url, probe_body = self._inject_param(
                url, params, inj_param, payload, finding.body, finding.method
            )
            try:
                r = await client.request(
                    finding.method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                body = r.text[:2000]
                if expected in body:
                    return self._confirmed(
                        finding,
                        f"SSTI: payload {payload!r} evaluated to {expected!r} in response",
                        r, probe_url,
                    )
                if _SSTI_ERRORS.search(body):
                    return self._confirmed(
                        finding,
                        f"SSTI: template engine error triggered by {payload!r}",
                        r, probe_url,
                    )
            except Exception:
                pass

        # XSS reflection probes — context-aware
        # Three probes: HTML body, HTML attribute breakout, JS context escape.
        # Only flag as confirmed when response is text/html and angle brackets reflect raw.
        for xss_payload, context, detection_re in _XSS_PROBES:
            probe_url, probe_body = self._inject_param(
                url, params, inj_param, xss_payload, finding.body, finding.method
            )
            try:
                r = await client.request(
                    finding.method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if not detection_re.search(r.text):
                    continue
                ct = r.headers.get("content-type", "")
                is_html = "text/html" in ct or "application/xhtml" in ct
                csp = r.headers.get("content-security-policy", "")
                csp_blocks = bool(csp and _CSP_BLOCKS_INLINE.search(csp) and "unsafe-inline" not in csp)
                evidence_base = f"XSS ({context} context): {xss_payload!r} reflected unescaped"
                if is_html:
                    if csp_blocks:
                        return self._likely(
                            finding,
                            evidence_base + " — CSP present, may limit exploitability",
                            r, probe_url,
                        )
                    return self._confirmed(
                        finding,
                        evidence_base + " in HTML response (no blocking CSP)",
                        r, probe_url,
                    )
                # Non-HTML: lower confidence — JSONP or content sniffing may still apply
                return self._likely(
                    finding,
                    evidence_base + f" in non-HTML response ({ct or 'unknown content-type'})",
                    r, probe_url,
                )
            except Exception:
                pass

        return self._not_confirmed(finding, "injection probes triggered no error or reflection", None)

    async def _verify_upload(self, client, finding) -> VerifyResult:
        url = finding.url
        # POST a minimal plain-text file — safe, easily cleaned up
        boundary = "hxxpsinboundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"hxxpsin probe\r\n"
            f"--{boundary}--\r\n"
        ).encode()

        try:
            resp = await client.post(
                url,
                content=body,
                headers={**self.auth_headers,
                          "Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
        except Exception as exc:
            return self._error(finding, str(exc))

        if resp.status_code in (200, 201, 202):
            return self._confirmed(
                finding,
                f"File upload accepted (status {resp.status_code})",
                resp, url,
            )
        if resp.status_code in (400, 415, 422):
            return self._likely(
                finding,
                f"Server processed upload request (status {resp.status_code}) — may need different field name or type",
                resp, url,
            )
        return self._not_confirmed(finding, f"upload returned {resp.status_code}", resp)

    async def _verify_bfla(self, client, finding) -> VerifyResult:
        url = finding.url
        # Send the privileged action WITHOUT auth headers to check if it's enforced
        try:
            resp_unauthed = await httpx.AsyncClient(
                verify=False, timeout=self.timeout, follow_redirects=True
            ).request(
                finding.method, url,
                content=finding.body or "{}",
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            return self._error(finding, str(exc))

        if resp_unauthed.status_code in (200, 201, 204):
            return self._confirmed(
                finding,
                f"BFLA: privileged endpoint accessible without authentication (status {resp_unauthed.status_code})",
                resp_unauthed, url,
            )
        if resp_unauthed.status_code == 403:
            return self._not_confirmed(
                finding, "endpoint correctly returns 403 without auth", resp_unauthed
            )
        return self._likely(
            finding,
            f"BFLA: endpoint returned {resp_unauthed.status_code} without auth — investigate",
            resp_unauthed, url,
        )

    async def _verify_auth(self, client, finding) -> VerifyResult:
        url = finding.url
        resp = await self._get(client, url)
        if resp is None:
            return self._error(finding, "request failed")
        if self._looks_like_soft404(resp):
            return self._not_confirmed(
                finding, f"endpoint returns {resp.status_code} or redirects to login — does not exist", resp
            )

        body = resp.text[:1000]
        jwt = _JWT_RE.search(body)
        if jwt:
            return self._confirmed(
                finding,
                f"JWT token exposed in response body: {jwt.group(0)[:40]}...",
                resp, url,
            )
        if "set-cookie" in resp.headers:
            cookies = resp.headers.get("set-cookie", "")
            flags_missing = []
            if "httponly" not in cookies.lower():
                flags_missing.append("HttpOnly")
            if "secure" not in cookies.lower():
                flags_missing.append("Secure")
            if flags_missing:
                return self._likely(
                    finding,
                    f"Session cookie missing flags: {', '.join(flags_missing)}",
                    resp, url,
                )

        return self._not_confirmed(finding, "no token exposure or cookie issues detected", resp)

    async def _verify_race(self, client, finding) -> VerifyResult:
        url = finding.url
        body = finding.body or "{}"
        CONCURRENCY = 10

        async def _one():
            async with httpx.AsyncClient(
                verify=False, timeout=self.timeout, follow_redirects=True,
                headers={**self.auth_headers, "Content-Type": "application/json"},
            ) as c:
                return await c.request(finding.method, url, content=body)

        responses = await asyncio.gather(*[_one() for _ in range(CONCURRENCY)], return_exceptions=True)
        valid = [r for r in responses if isinstance(r, httpx.Response)]
        if not valid:
            return self._error(finding, "all concurrent requests failed")

        statuses = [r.status_code for r in valid]
        bodies   = [r.text[:200] for r in valid]
        ok_count = sum(1 for s in statuses if s in (200, 201, 204))
        unique_bodies = len(set(bodies))

        if ok_count > 1 and unique_bodies > 1:
            return self._confirmed(
                finding,
                f"Race: {ok_count}/{CONCURRENCY} succeeded with {unique_bodies} distinct responses — state inconsistency",
                valid[0], url,
            )
        if ok_count > 1:
            return self._confirmed(
                finding,
                f"Race: {ok_count}/{CONCURRENCY} concurrent requests all returned success — not idempotency-protected",
                valid[0], url,
            )
        if ok_count == 1:
            return self._not_confirmed(finding, f"1/{CONCURRENCY} succeeded — likely rate-limited correctly", valid[0])
        status_summary = ", ".join(str(s) for s in sorted(set(statuses)))
        return self._not_confirmed(finding, f"all returned {status_summary}", valid[0])

    async def _verify_write(self, client, finding) -> VerifyResult:
        url = finding.url
        # Non-destructive auth enforcement check: send empty body, inspect status only
        try:
            resp = await httpx.AsyncClient(
                verify=False, timeout=self.timeout, follow_redirects=True
            ).request(
                finding.method, url,
                content="{}",
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            return self._error(finding, str(exc))

        if resp.status_code in (200, 201, 204):
            return self._confirmed(
                finding,
                f"Write endpoint accessible without authentication ({finding.method} → {resp.status_code})",
                resp, url,
            )
        if resp.status_code == 405:
            return self._not_confirmed(finding, "405 Method Not Allowed — method not valid for this path", resp)
        if resp.status_code in (400, 422):
            return self._likely(
                finding,
                f"Write endpoint processes unauthenticated request ({resp.status_code}) — auth enforced at validation layer, not auth layer",
                resp, url,
            )
        return self._not_confirmed(finding, f"{finding.method} → {resp.status_code} — auth enforced", resp)

    async def _verify_open_redirect(self, client, finding) -> VerifyResult:
        """Quick open-redirect check for REDIRECT-classified findings."""
        import payloads as _payloads
        canary = "evil.hxxpsin.invalid"
        url = finding.url
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        redirect_param = next((p for p in params if _REDIRECT_PARAM_RE.match(p)), None)
        if not redirect_param:
            return self._skipped(finding, "no redirect param found in URL")

        # Use a small targeted subset for quick verification
        test_payloads = [f"//{canary}", f"https://{canary}", f"//{canary}/%2f..", f"javascript:alert(1)"]
        for payload in test_payloads:
            new_params = dict(params)
            new_params[redirect_param] = payload
            probe_url = urlparse(url)._replace(query=urlencode(new_params)).geturl()
            try:
                r = await client.request(finding.method, probe_url, headers=self.auth_headers,
                                         follow_redirects=False)
                location = r.headers.get("location", "")
                if re.match(r"javascript:", location, re.I):
                    return self._confirmed(finding, f"Open redirect: javascript: URI in Location", r, probe_url)
                if canary in location:
                    return self._confirmed(finding, f"Open redirect: Location → {location}", r, probe_url)
                if location and r.status_code in range(300, 400):
                    loc_host = urlparse(location).netloc
                    own_host = parsed.netloc
                    if loc_host and loc_host not in own_host:
                        return self._likely(finding, f"Open redirect to external host: {location}", r, probe_url)
            except Exception:
                pass
        return self._not_confirmed(finding, "open redirect payloads did not produce external Location", None)

    async def _verify_nosql(self, client, finding) -> VerifyResult:
        """Quick NoSQL operator injection check for NOSQL-classified findings."""
        from nosql_probe import _inject as _nosql_inject, _NOSQL_ERRORS
        import json as _json
        url = finding.url
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        param = next(iter(params), None)

        try:
            baseline = await client.request(finding.method, url, headers=self.auth_headers)
            baseline_status = baseline.status_code
        except Exception:
            return self._error(finding, "baseline request failed")

        for payload_str, label in [('{"$ne": 1}', "$ne"), ('{"$gt": ""}', "$gt"), ('[$ne]=1', "array")]:
            probe_url, probe_body = _nosql_inject(url, params, param, payload_str, finding.body, finding.method, json_value=True)
            try:
                r = await client.request(
                    finding.method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if _NOSQL_ERRORS.search(r.text[:2000]):
                    return self._confirmed(finding, f"NoSQL error triggered by {label} operator", r, probe_url)
                if baseline_status in (401, 403) and r.status_code < 300:
                    return self._confirmed(finding, f"NoSQL auth bypass: {baseline_status}→{r.status_code} via {label}", r, probe_url)
            except Exception:
                pass
        return self._not_confirmed(finding, "NoSQL operator probes returned no signal", None)

    async def _verify_cors_finding(self, client, finding) -> VerifyResult:
        """Verifier for single findings classified as Cat.CORS."""
        return (await verify_cors([finding.url], self.auth_headers, self.timeout)
                or [self._not_confirmed(finding, "no CORS misconfiguration detected", None)])[0]

    # -----------------------------------------------------------------------
    # Helpers — param injection
    # -----------------------------------------------------------------------

    def _find_url_param(self, finding, params: dict) -> Optional[str]:
        """Return the name of the most likely URL/webhook parameter."""
        url_keywords = ("url", "webhook", "callback", "redirect", "next",
                        "return", "endpoint", "target", "fetch", "src", "dest")
        for k in params:
            if any(kw in k.lower() for kw in url_keywords):
                return k
        # Fall back to any param
        if params:
            return next(iter(params))
        return None

    def _find_inject_param(self, finding, params: dict) -> Optional[str]:
        """Return the most likely injectable param name."""
        inject_keywords = ("q", "query", "search", "filter", "sort", "order",
                           "where", "expr", "cmd", "id", "name", "value", "input")
        for k in params:
            if any(kw == k.lower() for kw in inject_keywords):
                return k
        if params:
            return next(iter(params))
        return None

    def _inject_url_param(self, url, params, param_name, inject_value, body, method):
        return inject_url_param(url, params, param_name, inject_value, body, method)

    def _inject_param(self, url, params, param_name, payload, body, method):
        return inject_param(url, params, param_name, payload, body, method)

    # -----------------------------------------------------------------------
    # Helpers — HTTP
    # -----------------------------------------------------------------------

    async def _get(self, client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
        try:
            return await client.get(url)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Helpers — result constructors
    # -----------------------------------------------------------------------

    def _resp_snippet(self, resp: Optional[httpx.Response]) -> str:
        if resp is None:
            return ""
        try:
            return resp.text[:300].replace("\n", " ").strip()
        except Exception:
            return ""

    def _make(
        self, finding, verdict, confidence, evidence, resp, probe_url,
        *, oob_hit: bool = False,
    ) -> VerifyResult:
        if from_verifier_verdict is not None:
            label = from_verifier_verdict(verdict, confidence)
            if promote_verdict is not None:
                label = promote_verdict(label, oob_hit=oob_hit)
            verdict = label.verdict.value
            confidence = label.confidence
        return VerifyResult(
            url=finding.url,
            method=finding.method,
            categories=finding.categories,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence + (" [OOB correlated]" if oob_hit else ""),
            probe_url=probe_url or finding.url,
            response_snippet=self._resp_snippet(resp),
            status_code=resp.status_code if resp else 0,
        )

    def _confirmed(self, f, evidence, resp, probe_url, *, oob_hit: bool = False) -> VerifyResult:
        return self._make(f, "confirmed", 0.9, evidence, resp, probe_url, oob_hit=oob_hit)

    def _likely(self, f, evidence, resp, probe_url) -> VerifyResult:
        return self._make(f, "likely", 0.6, evidence, resp, probe_url)

    def _not_confirmed(self, f, evidence, resp) -> VerifyResult:
        return self._make(f, "not_confirmed", 0.1, evidence, resp, f.url)

    def _skipped(self, f, reason) -> VerifyResult:
        return self._make(f, "skipped", 0.0, reason, None, f.url)

    def _error(self, f, msg) -> VerifyResult:
        return self._make(f, "error", 0.0, msg, None, f.url)


# ---------------------------------------------------------------------------
# Standalone verification passes (called from main pipeline separately)
# ---------------------------------------------------------------------------

async def verify_cors(
    urls: list[str],
    auth_headers: Optional[dict] = None,
    timeout: float = 5.0,
) -> list[VerifyResult]:
    """
    Check CORS policy on a deduplicated set of API URLs.
    Deduplicates by (netloc, first 2 path segments) to avoid redundant checks.
    """
    auth_headers = auth_headers or {}
    EVIL_ORIGIN = "https://evil.test.invalid"

    seen: set[str] = set()
    deduped: list[str] = []
    for url in urls:
        p = urlparse(url)
        parts = [seg for seg in p.path.split("/") if seg]
        prefix = "/" + "/".join(parts[:2]) if len(parts) >= 2 else p.path
        key = f"{p.netloc}{prefix}"
        if key not in seen:
            seen.add(key)
            deduped.append(url)

    results: list[VerifyResult] = []
    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=True
    ) as client:
        for url in deduped[:25]:
            try:
                resp = await client.get(url, headers={**auth_headers, "Origin": EVIL_ORIGIN})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()
                if not acao:
                    continue
                if acao == EVIL_ORIGIN:
                    verdict, conf, note = "confirmed", 0.95, "origin reflected exactly"
                elif acao == "*" and acac == "true":
                    verdict, conf, note = "confirmed", 0.95, "wildcard origin with credentials allowed"
                elif acao == "*":
                    verdict, conf, note = "likely", 0.5, "wildcard origin — check if sensitive data returned"
                else:
                    continue
                results.append(VerifyResult(
                    url=url, method="GET", categories=[Cat.CORS],
                    verdict=verdict, confidence=conf,
                    evidence=f"CORS: Access-Control-Allow-Origin: {acao!r} ({note})",
                    probe_url=url,
                    response_snippet=f"ACAO: {acao} | ACAC: {acac or 'not set'}",
                    status_code=resp.status_code,
                ))
            except Exception:
                pass

    return results


async def verify_js_findings(
    js_result,
    origin: str,
    auth_headers: Optional[dict] = None,
    timeout: float = 5.0,
) -> list[VerifyResult]:
    """
    Verify JS deep analyzer findings: hardcoded secrets and exposed source maps.
    Returns VerifyResult entries suitable for inclusion in the verify report.
    """
    auth_headers = auth_headers or {}
    results: list[VerifyResult] = []

    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=True
    ) as client:

        # ── Source maps ────────────────────────────────────────────────────
        for sm in js_result.source_maps:
            if sm.has_content:
                # Analyzer already fetched and parsed it — confirmed
                results.append(VerifyResult(
                    url=sm.map_url, method="GET",
                    categories=["Source Map Exposure"],
                    verdict="confirmed", confidence=0.95,
                    evidence=(
                        f"Source map served with {len(sm.sources)} original source files — "
                        f"full pre-minification source code exposed"
                    ),
                    probe_url=sm.map_url,
                    response_snippet=str(sm.sources[:5]),
                    status_code=200,
                ))
            else:
                try:
                    resp = await client.get(sm.map_url)
                    if resp.status_code == 200 and (
                        '"sources":' in resp.text or '"sourcesContent":' in resp.text
                    ):
                        results.append(VerifyResult(
                            url=sm.map_url, method="GET",
                            categories=["Source Map Exposure"],
                            verdict="confirmed", confidence=0.9,
                            evidence="Source map accessible — original source file paths exposed",
                            probe_url=sm.map_url,
                            response_snippet=resp.text[:200],
                            status_code=200,
                        ))
                except Exception:
                    pass

        # ── Hardcoded secrets ──────────────────────────────────────────────
        for secret in js_result.secrets:
            if secret.public_by_design:
                continue

            confidence = 0.75 if secret.severity == "critical" else 0.55
            evidence_base = (
                f"Hardcoded {secret.kind} in {secret.source_file} — "
                f"value: {secret.value}... [{secret.severity}]"
            )

            # For JWT-shaped values, try against the target's common auth endpoints
            if "jwt" in secret.kind.lower() or secret.value.startswith("eyJ"):
                for auth_path in ("/api/me", "/api/user", "/api/v1/me", "/rest/user/whoami"):
                    try:
                        r = await client.get(
                            urljoin(origin, auth_path),
                            headers={**auth_headers, "Authorization": f"Bearer {secret.value}"},
                        )
                        if r.status_code == 200:
                            confidence = 0.92
                            evidence_base = (
                                f"Hardcoded JWT accepted by {auth_path} (200) — "
                                f"live credential exposed in JS bundle"
                            )
                            break
                    except Exception:
                        pass

            results.append(VerifyResult(
                url=secret.source_file,
                method="GET",
                categories=[f"Secret: {secret.kind}"],
                verdict="confirmed" if confidence >= 0.8 else "likely",
                confidence=confidence,
                evidence=evidence_base,
                probe_url=secret.source_file,
                response_snippet="",
                status_code=0,
            ))

    return results
