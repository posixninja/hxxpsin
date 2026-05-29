"""
Content-type confusion probe for hxxpsin.

Problem: browsers apply CORS preflight only to "non-simple" requests. A POST
with Content-Type application/json triggers a preflight; the same POST with
Content-Type text/plain does not. If a JSON API endpoint accepts the body
regardless of Content-Type, an attacker can submit it cross-origin via a plain
HTML form — bypassing CORS entirely and making the CSRF exploitable without
any custom header.

What we test for each candidate XHR finding:

  1. Baseline  — original Content-Type, original body → capture status + body
  2. text/plain  confusion — replace header, keep body → same status = confused
  3. form-urlencoded confusion — replace header, keep body → same status = confused
  4. no Content-Type  — omit the header entirely → same status = confused

"Same status" means the server returned a 2xx in both cases (or identical
non-2xx in both — the endpoint behaves identically regardless of Content-Type).

Candidates: Finding objects from the classifier where resource_type is xhr/fetch,
method is POST/PUT/PATCH/DELETE, and the original Content-Type was application/json.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CTFinding:
    method: str
    url: str
    original_ct: str
    confused_ct: str
    baseline_status: int
    confused_status: int
    evidence: str
    severity: str = "medium"

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "original_ct": self.original_ct,
            "confused_ct": self.confused_ct,
            "baseline_status": self.baseline_status,
            "confused_status": self.confused_status,
            "evidence": self.evidence,
            "severity": self.severity,
        }


@dataclass
class CTProbeResult:
    endpoints_tested: int = 0
    requests_sent: int = 0
    findings: list[CTFinding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def confirmed(self) -> list[CTFinding]:
        return self.findings  # every entry is a confirmed confusion

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "requests_sent": self.requests_sent,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

# Content-Types that are "simple" per Fetch spec — no preflight triggered.
# Sending one of these cross-origin bypasses CORS entirely.
_SIMPLE_CONTENT_TYPES = [
    "text/plain",
    "application/x-www-form-urlencoded",
]
# No Content-Type header at all also avoids preflight in some browsers
_NO_CT_SENTINEL = "__none__"

# Patterns that clearly indicate a server-side parse error — the server
# DID check the Content-Type and rejected the body, so no confusion.
_ERROR_BODY_RE = re.compile(
    r"(unsupported.media.type|invalid.content.type|only.application/json"
    r"|content.type.must.be|expected.json|parse.error|syntax.error"
    r"|unexpected.token|json.parse|unmarshal|decode)",
    re.IGNORECASE,
)

# 415 Unsupported Media Type — server explicitly checks Content-Type
_REJECTION_STATUSES = {415}


class CTProbe:
    def __init__(self, auth_headers: dict = None, timeout: float = 8.0, http_cache=None):
        self._auth = auth_headers or {}
        self._timeout = timeout
        self.http_cache = http_cache

    async def run(self, findings) -> CTProbeResult:
        """findings: list of classifier Finding objects."""
        result = CTProbeResult()

        candidates = _select_candidates(findings)
        if not candidates:
            return result

        from probe_http import open_probe_client

        async with open_probe_client(
            self.http_cache,
            verify=False,
            follow_redirects=False,
            timeout=self._timeout,
            headers=self._auth,
        ) as client:
            tasks = [
                self._probe_one(client, f, result)
                for f in candidates[:20]
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    async def _probe_one(self, client: httpx.AsyncClient, finding, result: CTProbeResult) -> None:
        result.endpoints_tested += 1
        method = finding.method
        url = finding.url
        body = finding.body or ""
        original_ct = finding.headers.get("content-type", finding.headers.get("Content-Type", "application/json"))

        # Baseline: send with original Content-Type
        baseline_status, baseline_body = await self._send(
            client, method, url, body, original_ct,
        )
        result.requests_sent += 1

        if baseline_status is None or baseline_status in _REJECTION_STATUSES:
            # Endpoint itself is broken or unreachable — skip mutations
            return
        if not _is_success(baseline_status) and not _is_auth_error(baseline_status):
            # Non-2xx that isn't auth-related means this path returns errors by
            # default; mutations would be noise.
            return

        # Mutations
        for confused_ct in _SIMPLE_CONTENT_TYPES + [_NO_CT_SENTINEL]:
            confused_status, confused_body = await self._send(
                client, method, url, body,
                None if confused_ct == _NO_CT_SENTINEL else confused_ct,
            )
            result.requests_sent += 1

            if confused_status is None or confused_status in _REJECTION_STATUSES:
                continue
            if _looks_like_error(confused_body):
                continue

            # Confusion confirmed: server returned same success class regardless
            # of Content-Type — body was processed without a type check.
            if _same_success_class(baseline_status, confused_status):
                display_ct = "no Content-Type" if confused_ct == _NO_CT_SENTINEL else confused_ct
                result.findings.append(CTFinding(
                    method=method,
                    url=url,
                    original_ct=original_ct,
                    confused_ct=display_ct,
                    baseline_status=baseline_status,
                    confused_status=confused_status,
                    evidence=(
                        f"{method} {url} returns {confused_status} with "
                        f"'{display_ct}' (originally '{original_ct}'). "
                        f"Body is processed regardless of Content-Type — "
                        f"cross-origin form submission can bypass CORS preflight."
                    ),
                    severity="high" if confused_ct == "text/plain" else "medium",
                ))
                # One confirmed mutation is enough to flag the endpoint
                break

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        body: str,
        content_type: Optional[str],
    ) -> tuple[Optional[int], str]:
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        try:
            resp = await client.request(
                method, url,
                content=body.encode("utf-8", errors="replace") if body else b"",
                headers=headers,
            )
            return resp.status_code, resp.text[:2000]
        except Exception as exc:
            return None, str(exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _select_candidates(findings) -> list:
    """Return findings that are XHR JSON state-changes — the surface we probe."""
    out = []
    seen: set[str] = set()
    for f in findings:
        if f.method not in ("POST", "PUT", "PATCH", "DELETE"):
            continue
        if getattr(f, "resource_type", None) not in ("xhr", "fetch"):
            continue
        ct = (f.headers.get("content-type") or f.headers.get("Content-Type") or "").lower()
        if "application/json" not in ct:
            continue
        key = f"{f.method}:{f.url}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _is_auth_error(status: int) -> bool:
    return status in (401, 403)


def _same_success_class(a: int, b: int) -> bool:
    """Both 2xx, or both the same auth-error code (401/403 both ways means
    the endpoint rejected both but for the same reason — not confusion)."""
    return _is_success(a) and _is_success(b)


def _looks_like_error(body: str) -> bool:
    if not body:
        return False
    return bool(_ERROR_BODY_RE.search(body))
