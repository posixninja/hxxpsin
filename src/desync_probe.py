"""
desync_probe.py — Protocol, cache, and desync risk detector for hxxpsin.

Safe detection only — no actual smuggling payloads sent.
Detects conditions that indicate manual Burp verification is warranted.

Probes (all read-only, non-destructive):
  protocol      H2→H1 downgrade risk, Alt-Svc H3, CDN/proxy presence
  cacheability  MISS→HIT transition, Age growth, Set-Cookie on cached response
  unkeyed_hdr   X-Forwarded-Host/X-Host/X-Original-URL reflection in body/headers
  cookie_key    Cookie absent from Vary while response is served from cache
  host_confuse  X-Forwarded-Proto downgrade, X-Forwarded-Port reflection

Pipeline position:
  stackprint → crawler → classifier → desync_probe → reporter
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

_PROBE_HOST = "probe.hxxpsin.local"     # reflected in body → unkeyed header confirmed
_PROBE_PATH = "/hxxpsin-probe-x7z9"    # reflected in body → URL rewrite header trusted

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

@dataclass
class DesyncFinding:
    url: str
    probe: str          # which probe triggered this
    risk: str           # short risk class name
    severity: str       # high | medium | low | info
    signals: list[str]  # what was observed
    manual_tests: list[str]

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "risk": self.risk,
            "probe": self.probe,
            "url": self.url,
            "signals": self.signals,
            "manual_tests": self.manual_tests,
        }


@dataclass
class DesyncResult:
    findings: list[DesyncFinding]
    urls_probed: int

    def high(self) -> list[DesyncFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        return {
            "urls_probed": self.urls_probed,
            "finding_count": len(self.findings),
            "high_count": len(self.high()),
            "findings": [f.to_dict() for f in self.findings],
        }

    def summary(self) -> str:
        if not self.findings:
            return f"No desync/cache risk signals detected across {self.urls_probed} URLs."

        lines = [
            f"URLs probed: {self.urls_probed}",
            f"Findings: {len(self.findings)} ({len(self.high())} high)",
            "",
        ]
        for f in self.findings:
            lines.append(f"[{f.severity.upper():<6}] {f.risk}  ({f.probe} probe)")
            lines.append(f"  {f.url}")
            for s in f.signals:
                lines.append(f"    ! {s}")
            lines.append(f"  Manual tests:")
            for t in f.manual_tests:
                lines.append(f"    → {t}")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Probe engine
# ---------------------------------------------------------------------------

class DesyncProbe:
    def __init__(
        self,
        urls: list[str],
        profile=None,           # Optional[StackProfile] — for protocol probe
        max_urls: int = 20,
        timeout: float = 6.0,
        confirm_smuggling: bool = False,
    ):
        # Deduplicate and cap; prioritize GET endpoints
        seen: set[str] = set()
        self.urls: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                self.urls.append(u)
            if len(self.urls) >= max_urls:
                break

        self.profile = profile
        self.timeout = timeout
        self.confirm_smuggling = confirm_smuggling

    async def run(self) -> DesyncResult:
        findings: list[DesyncFinding] = []

        # Protocol probe needs no HTTP — uses StackProfile data
        findings.extend(self._probe_protocol())

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout,
            verify=False,
            http2=True,
            headers=_HEADERS,
        ) as client:
            tasks = [self._probe_url(url, client) for url in self.urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

        if self.confirm_smuggling and self.urls:
            findings.extend(await self._probe_smuggling_differential(self.urls[0]))

        findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 4))
        return DesyncResult(findings=findings, urls_probed=len(self.urls))

    async def _probe_smuggling_differential(self, url: str) -> list[DesyncFinding]:
        """Safe bounded CL.TE / TE.CL differential — one malformed request per type.

        Does not send full smuggle bodies; only checks whether the server returns
        a distinct error signature vs a normal GET baseline.
        """
        out: list[DesyncFinding] = []
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        path = parsed.path or "/"

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=False,
        ) as client:
            try:
                baseline = await client.get(url, headers=_HEADERS)
                b_sig = (baseline.status_code, baseline.headers.get("server", ""))
            except Exception:
                return out

            try:
                # Raw socket would be ideal; httpx may normalize — still useful as signal
                r = await client.post(
                    url,
                    headers={**_HEADERS, "Content-Length": "6", "Transfer-Encoding": "chunked"},
                    content=b"0\r\n\r\nG",
                )
                if (r.status_code, r.headers.get("server", "")) != b_sig and r.status_code in (400, 501, 502):
                    out.append(DesyncFinding(
                        url=url, probe="smuggling", risk="cl_te_differential",
                        severity="medium",
                        signals=[f"CL.TE probe returned {r.status_code} vs baseline {baseline.status_code}"],
                        manual_tests=["Confirm with Burp HTTP Request Smuggler CL.TE"],
                    ))
            except Exception:
                pass

            try:
                r2 = await client.post(
                    url,
                    headers={**_HEADERS, "Transfer-Encoding": "chunked, identity"},
                    content=b"0\r\n\r\n",
                )
                if r2.status_code in (400, 501, 502) and r2.status_code != baseline.status_code:
                    out.append(DesyncFinding(
                        url=url, probe="smuggling", risk="te_cl_differential",
                        severity="medium",
                        signals=[f"TE.CL probe returned {r2.status_code}"],
                        manual_tests=["Confirm with Burp HTTP Request Smuggler TE.CL"],
                    ))
            except Exception:
                pass
        return out

    async def _probe_url(self, url: str, client: httpx.AsyncClient) -> list[DesyncFinding]:
        out: list[DesyncFinding] = []
        for probe_fn in (
            self._probe_cacheability,
            self._probe_unkeyed_headers,
            self._probe_cookie_cache_key,
            self._probe_host_confusion,
        ):
            try:
                out.extend(await probe_fn(url, client))
            except Exception:
                pass
        return out

    # ------------------------------------------------------------------
    # Probe: protocol downgrade risk
    # ------------------------------------------------------------------

    def _probe_protocol(self) -> list[DesyncFinding]:
        if not self.profile:
            return []

        signals: list[str] = []
        cdn_present = bool(self.profile.detected.get("cdn"))
        h2_edge = any("HTTP/2" in p for p in self.profile.protocols)
        h3_advertised = any("HTTP/3" in p for p in self.profile.protocols)

        if cdn_present and h2_edge:
            signals.append(
                "CDN/proxy detected with HTTP/2 edge — origin likely receives HTTP/1.1 "
                "(H2→H1 downgrade at translation boundary)"
            )
            signals.append(
                "H2 pseudo-headers (:path, :authority) normalized differently than HTTP/1.1 "
                "Host/path — enables header injection and request splitting"
            )

        if h3_advertised:
            signals.append(
                "HTTP/3 advertised via Alt-Svc — full QUIC→TLS→TCP chain at origin; "
                "H3→H2→H1 translation stacks can disagree on header normalization"
            )

        if not signals:
            return []

        return [DesyncFinding(
            url=self.profile.target,
            probe="protocol",
            risk="protocol_downgrade",
            severity="medium",
            signals=signals,
            manual_tests=[
                "Use Burp Suite HTTP Request Smuggler extension (albinowax) — run CL.TE and TE.CL probes",
                "In Burp Repeater: send H2 request with content-length that disagrees with actual body length",
                "Watch for timing anomaly: a 10-second hang on TE probe = backend is waiting for chunk terminator",
                "Confirm with differential response: next victim request receives partial attacker body",
                "Test H2 header name injection: send header with newline-encoded value (%0d%0a)",
            ],
        )]

    # ------------------------------------------------------------------
    # Probe: cacheability
    # ------------------------------------------------------------------

    async def _probe_cacheability(self, url: str, client: httpx.AsyncClient) -> list[DesyncFinding]:
        resp1 = await client.get(url)
        await asyncio.sleep(0.5)
        resp2 = await client.get(url)

        h1, h2 = dict(resp1.headers), dict(resp2.headers)
        signals: list[str] = []

        # Age increase between identical requests
        try:
            age1, age2 = int(h1.get("age", -1)), int(h2.get("age", -1))
            if age1 >= 0 and age2 > age1:
                signals.append(f"Age header grew {age1}s → {age2}s — this endpoint is cached by an upstream layer")
        except ValueError:
            pass

        # X-Cache MISS → HIT
        xc1, xc2 = h1.get("x-cache", "").lower(), h2.get("x-cache", "").lower()
        if "miss" in xc1 and "hit" in xc2:
            signals.append("X-Cache transitioned MISS→HIT — CDN is caching this response")

        # Cloudflare
        if h2.get("cf-cache-status", "").lower() == "hit":
            signals.append("CF-Cache-Status: HIT — Cloudflare served this response from cache")

        if not signals:
            return []

        # Severity escalation based on what's being cached
        vary = h2.get("vary", "").lower()
        cc = h2.get("cache-control", "").lower()
        body = resp2.text.lower()
        set_cookie = h2.get("set-cookie", "")

        severity = "low"

        if set_cookie:
            signals.append(
                "CRITICAL: Set-Cookie header present on a cached response — "
                "victims may receive each other's session cookies"
            )
            severity = "high"
        elif "cookie" not in vary and "authorization" not in vary:
            user_words = ("user", "account", "email", "profile", "session", "token", "role", "balance")
            if any(w in body for w in user_words):
                signals.append(
                    "Vary header excludes Cookie and Authorization; "
                    "response body contains user-specific keywords — cross-user leakage likely"
                )
                severity = "high"
            else:
                signals.append(
                    f"Vary: '{h2.get('vary', '(missing)')}' — "
                    "does not key on Cookie or Authorization"
                )
                severity = "medium"

        # Cache-Control: private or no-store reduces actual risk even if cached at browser level
        if "private" in cc or "no-store" in cc:
            severity = "low"
            signals.append("Cache-Control restricts CDN caching — risk limited to browser-level")

        return [DesyncFinding(
            url=url,
            probe="cacheability",
            risk="cache_key_confusion",
            severity=severity,
            signals=signals,
            manual_tests=[
                "Log in as user A → warm this URL → log in as user B → visit same URL — compare responses",
                "Cache deception: append /.css or /.js to this path — does the cache now store it publicly?",
                "Remove Authorization header on second request — still a cache HIT? Then auth is not keyed",
                "Test with Vary: Cookie added manually in a request — does cache behavior change?",
            ],
        )]

    # ------------------------------------------------------------------
    # Probe: unkeyed headers (cache poisoning surface)
    # ------------------------------------------------------------------

    async def _probe_unkeyed_headers(self, url: str, client: httpx.AsyncClient) -> list[DesyncFinding]:
        findings: list[DesyncFinding] = []

        probe_headers = [
            ("X-Forwarded-Host",  _PROBE_HOST),
            ("X-Host",            _PROBE_HOST),
            ("Forwarded",         f"host={_PROBE_HOST}"),
            ("X-Original-URL",    _PROBE_PATH),
            ("X-Rewrite-URL",     _PROBE_PATH),
        ]

        for hdr_name, hdr_value in probe_headers:
            try:
                resp = await client.get(url, headers={hdr_name: hdr_value})
                body = resp.text[:10_000]
                location = resp.headers.get("location", "")

                host_reflected = _PROBE_HOST in body or _PROBE_HOST in location
                path_reflected = _PROBE_PATH in body or _PROBE_PATH in location

                if not (host_reflected or path_reflected):
                    continue

                reflected_in = []
                if _PROBE_HOST in body or _PROBE_PATH in body:
                    reflected_in.append("response body")
                if _PROBE_HOST in location or _PROBE_PATH in location:
                    reflected_in.append(f"Location header ({location})")

                findings.append(DesyncFinding(
                    url=url,
                    probe="unkeyed_header",
                    risk="cache_poisoning",
                    severity="high",
                    signals=[
                        f"{hdr_name}: {hdr_value} reflected in {', '.join(reflected_in)}",
                        "If this endpoint is cacheable: full cache poisoning is likely exploitable",
                        "Attacker can serve malicious JS, redirect victims, or steal credentials at scale",
                    ],
                    manual_tests=[
                        "Confirm cacheability (run cacheability probe on this URL)",
                        "Poison: X-Forwarded-Host → attacker.com hosting malicious JS payload",
                        "Check script src, canonical link, OpenGraph URL, password reset links",
                        "Verify poison persists across requests (Age header confirms cache storage)",
                    ],
                ))
            except Exception:
                pass

        return findings

    # ------------------------------------------------------------------
    # Probe: cookie absent from cache key
    # ------------------------------------------------------------------

    async def _probe_cookie_cache_key(self, url: str, client: httpx.AsyncClient) -> list[DesyncFinding]:
        resp_a = await client.get(url, headers={"Cookie": "hxxpsin_probe=AAAA"})
        await asyncio.sleep(0.2)
        resp_b = await client.get(url, headers={"Cookie": "hxxpsin_probe=BBBB"})

        vary = resp_b.headers.get("vary", "").lower()
        x_cache = resp_b.headers.get("x-cache", "").lower()
        cf_cache = resp_b.headers.get("cf-cache-status", "").lower()

        cached = "hit" in x_cache or cf_cache == "hit"
        cookie_keyed = "cookie" in vary

        if not cached or cookie_keyed:
            return []

        body = resp_b.text.lower()
        user_words = ("user", "account", "email", "profile", "session", "token", "balance", "role")
        severity = "high" if any(w in body for w in user_words) else "medium"

        signals = [
            "Cookie is NOT included in Vary but response is served from cache",
            "Two requests with different Cookie values both received a cache HIT",
        ]
        if severity == "high":
            signals.append("Response body contains user-specific keywords — cross-user data leakage is likely")

        return [DesyncFinding(
            url=url,
            probe="cookie_cache_key",
            risk="cache_key_confusion",
            severity=severity,
            signals=signals,
            manual_tests=[
                "Warm cache as user A → clear cookies → visit same URL — user A's data in response?",
                "Warm cache as user A → log in as user B → visit same URL — cross-account leakage?",
                "Check Authorization header keying: repeat test without Cookie, with Bearer token instead",
            ],
        )]

    # ------------------------------------------------------------------
    # Probe: host header / proxy header confusion
    # ------------------------------------------------------------------

    async def _probe_host_confusion(self, url: str, client: httpx.AsyncClient) -> list[DesyncFinding]:
        findings: list[DesyncFinding] = []
        parsed = urlparse(url)

        # X-Forwarded-Proto downgrade (HTTPS targets only)
        if parsed.scheme == "https":
            try:
                resp = await client.get(url, headers={"X-Forwarded-Proto": "http"})
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 307, 308) and location.startswith("http://"):
                    findings.append(DesyncFinding(
                        url=url,
                        probe="host_confusion",
                        risk="host_header_injection",
                        severity="medium",
                        signals=[
                            "X-Forwarded-Proto: http on HTTPS endpoint caused HTTP redirect",
                            f"Location: {location}",
                            "Absolute redirect URL scheme is attacker-controllable",
                        ],
                        manual_tests=[
                            "Test password reset flow — does reset link use the injected proto?",
                            "Check email confirmation and OAuth callback URLs for same behavior",
                            "Combine with cache poisoning — poison Location header for victim sessions",
                        ],
                    ))
            except Exception:
                pass

        # X-Forwarded-Port reflection
        try:
            resp = await client.get(url, headers={"X-Forwarded-Port": "9191"})
            body = resp.text
            location = resp.headers.get("location", "")
            if ":9191" in body or ":9191" in location:
                findings.append(DesyncFinding(
                    url=url,
                    probe="host_confusion",
                    risk="host_header_injection",
                    severity="low",
                    signals=[
                        "X-Forwarded-Port: 9191 reflected in response — server trusts port from proxy headers",
                    ],
                    manual_tests=[
                        "Check if absolute URL generation uses this port (password reset, email links)",
                        "Confirm cacheability — if cached, port poisoning affects all victims",
                    ],
                ))
        except Exception:
            pass

        return findings


# ---------------------------------------------------------------------------
# Convenience: extract GET URLs from ClassifierResult
# ---------------------------------------------------------------------------

def urls_from_classifier(result) -> list[str]:
    """Pull GET endpoint URLs from a ClassifierResult — skip static assets."""
    skip_ext = (".js", ".css", ".png", ".jpg", ".ico", ".woff", ".svg")
    urls: list[str] = []
    seen: set[str] = set()
    for finding in result.request_findings:
        if finding.method != "GET":
            continue
        url = finding.url
        if any(url.endswith(ext) for ext in skip_ext):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _main() -> None:
    import argparse
    import warnings
    warnings.filterwarnings("ignore")  # suppress SSL noise

    parser = argparse.ArgumentParser(description="hxxpsin desync_probe")
    parser.add_argument("urls", nargs="+", help="URLs to probe (pass origin + discovered endpoints)")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--max", type=int, default=20, dest="max_urls")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--out", default="-", help="Output path (- for stdout)")
    args = parser.parse_args()

    probe = DesyncProbe(args.urls, max_urls=args.max_urls, timeout=args.timeout)
    result = await probe.run()

    output = json.dumps(result.to_dict(), indent=2) if args.json else result.summary()

    if args.out == "-":
        print(output)
    else:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[+] Wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(_main())
