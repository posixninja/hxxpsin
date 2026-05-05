"""
crlf_probe.py — CRLF injection / HTTP response splitting detection.

Injects 17 CRLF sequences from PAT into URL params and checks whether the
server echoes the injected Set-Cookie header in its response headers,
indicating HTTP response splitting.

Detection:
  - "crlf=injection" appearing in response Set-Cookie header
  - Any injected header value (X-CRLF-Test) reflected in response headers
  - Content-Type header changed to text/html when it was JSON (response splitting)

All payloads use the template: <crlf_sequence>Set-Cookie:crlf=injection
or <crlf_sequence>X-CRLF-Test:hxxpsin

Pipeline position: after desync_probe. Always-on (read-only: no writes, safe probes).

Sources: PAT CRLF Injection/Files/crlfinjection.txt (17 payloads)
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

import payloads

_CRLF_MARKER = "crlf=injection"
_CUSTOM_HDR = "x-crlf-test"
_CUSTOM_VAL = "hxxpsin"

# Detection patterns in response headers
_COOKIE_INJECT_RE = re.compile(r"crlf=injection", re.IGNORECASE)


@dataclass
class CRLFFinding:
    url: str
    payload: str
    verdict: str        # confirmed | likely
    confidence: float
    evidence: str
    injected_header: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "payload": self.payload,
            "verdict": self.verdict, "confidence": round(self.confidence, 2),
            "evidence": self.evidence, "injected_header": self.injected_header,
        }


@dataclass
class CRLFResult:
    urls_tested: int = 0
    findings: list[CRLFFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[CRLFFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "urls_tested": self.urls_tested,
            "confirmed": len(self.confirmed),
            "findings": [f.to_dict() for f in self.findings],
        }


class CRLFProbe:
    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 8.0,
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout

    async def run(self, urls: list[str]) -> CRLFResult:
        result = CRLFResult(urls_tested=len(urls))
        if not urls:
            return result

        crlf_seqs = payloads.crlf_payloads()

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,  # don't follow — check raw response headers
            timeout=self.timeout,
            headers=self.auth_headers,
        ) as client:
            tasks = [self._probe_url(client, url, crlf_seqs) for url in urls]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)
        return result

    async def _probe_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        crlf_seqs: list[str],
    ) -> list[CRLFFinding]:
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # Need at least one query param to inject into
        if not params:
            # Try appending a synthetic param
            params = {"x": "test"}

        param = next(iter(params))

        for seq in crlf_seqs:
            # Build two probe variants:
            # 1. Classic: value + CRLF_seq + Set-Cookie:crlf=injection
            # 2. Custom header: value + CRLF_seq + X-CRLF-Test:hxxpsin
            for header_suffix in [
                f"{seq}Set-Cookie:{_CRLF_MARKER}",
                f"{seq}X-CRLF-Test:{_CUSTOM_VAL}",
            ]:
                new_params = dict(params)
                new_params[param] = header_suffix
                probe_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                try:
                    r = await client.get(probe_url, headers=self.auth_headers)
                    finding = _check_response(url, header_suffix, r)
                    if finding:
                        return [finding]
                except Exception:
                    pass

        return []


def _check_response(url: str, payload: str, r: httpx.Response) -> Optional[CRLFFinding]:
    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    # 1. crlf=injection in Set-Cookie
    set_cookie = headers_lower.get("set-cookie", "")
    if _COOKIE_INJECT_RE.search(set_cookie):
        return CRLFFinding(
            url=url, payload=payload,
            verdict="confirmed", confidence=0.95,
            evidence=f"CRLF injection: Set-Cookie header injected (crlf=injection found)",
            injected_header=f"set-cookie: {set_cookie[:100]}",
        )

    # 2. Custom marker in any header value
    if headers_lower.get(_CUSTOM_HDR, "") == _CUSTOM_VAL:
        return CRLFFinding(
            url=url, payload=payload,
            verdict="confirmed", confidence=0.92,
            evidence=f"CRLF injection: X-CRLF-Test header injected (value: {_CUSTOM_VAL})",
            injected_header=f"x-crlf-test: {_CUSTOM_VAL}",
        )

    # 3. Heuristic: Content-Type changed to text/html on a previously-JSON endpoint
    ct = headers_lower.get("content-type", "")
    if "text/html" in ct and r.status_code == 200 and _CRLF_MARKER in r.text:
        return CRLFFinding(
            url=url, payload=payload,
            verdict="likely", confidence=0.65,
            evidence="CRLF: injected marker found in body, Content-Type: text/html",
            injected_header="",
        )

    return None
