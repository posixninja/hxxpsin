"""
dom_xss_probe.py — Verify DOM XSS candidates with a real browser.

js_deep_analyzer already finds source→sink patterns in fetched JS bundles
(JSDomXss findings). What it doesn't do is *prove* exploitability: a regex
match could be a false positive (escaped, sanitized, behind a feature flag).

This module takes those candidates plus the BrowserVerifier and:
  1. For each source type that we can drive from the URL (location.hash,
     location.search, URLSearchParams), builds a probe URL with a canary
     payload embedded
  2. Hands the URL to BrowserVerifier.verify_xss
  3. Promotes the candidate to "confirmed" only when the browser actually
     fires the canary

Pipeline position: after JS deep analysis, before the verifier step.
Always-on when BrowserVerifier is available.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin


# Sources we can drive directly from the request URL. Other sources
# (window.name, postMessage, document.cookie, *Storage) need a multi-step
# setup; out of scope for the first pass.
_PROBEABLE_SOURCES = {
    "location.hash":   "hash",
    "location.search": "query",
    "URLSearchParams": "query",
    # location.href contains both — try both shapes
    "location.href":   "both",
    # document.URL is an alias for location.href
    "document.URL":    "both",
}

# Common query-param names a SPA might read from location.search / URLSearchParams.
# The actual source name doesn't tell us *which* param the JS is reading, so we
# probe several common ones. Each multiplies the navigation count, so keep small.
_COMMON_QUERY_PARAMS = ("q", "query", "search", "id", "redirect", "url", "name", "msg")


@dataclass
class DOMXSSFinding:
    source: str            # e.g. location.hash
    sink: str              # e.g. innerHTML
    source_file: str       # JS bundle that contained the pattern
    probe_url: str         # the URL we navigated to verify
    verdict: str           # confirmed | likely | not_confirmed | skipped | error
    confidence: float
    evidence: str
    signal: str = ""       # canary | dialog | csp | none

    def to_dict(self) -> dict:
        return {
            "source": self.source, "sink": self.sink,
            "source_file": self.source_file, "probe_url": self.probe_url,
            "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence, "signal": self.signal,
        }


@dataclass
class DOMXSSResult:
    candidates_total: int = 0       # raw JSDomXss count from the analyzer
    candidates_probed: int = 0      # how many had probeable source types
    findings: list[DOMXSSFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[DOMXSSFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def likely(self) -> list[DOMXSSFinding]:
        return [f for f in self.findings if f.verdict == "likely"]

    def to_dict(self) -> dict:
        return {
            "candidates_total": self.candidates_total,
            "candidates_probed": self.candidates_probed,
            "confirmed": len(self.confirmed),
            "likely": len(self.likely),
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


class DOMXSSProbe:
    """Verifies static DOM XSS candidates by driving the source from the URL
    and checking for execution in a real browser."""

    def __init__(
        self,
        browser_verifier,
        timeout: float = 8.0,
        max_probes: int = 25,
    ):
        self.browser_verifier = browser_verifier
        self.timeout = timeout
        self.max_probes = max_probes

    async def run(
        self,
        target: str,
        js_dom_xss_findings,        # list[JSDomXss] from JSAnalysisResult
        auth_headers: Optional[dict] = None,
    ) -> DOMXSSResult:
        result = DOMXSSResult()
        result.candidates_total = len(js_dom_xss_findings) if js_dom_xss_findings else 0

        if not self.browser_verifier or not self.browser_verifier.available:
            result.notes.append("skipped: BrowserVerifier unavailable")
            return result
        if not js_dom_xss_findings:
            result.notes.append("no DOM XSS candidates from static analysis")
            return result

        # Dedup by (source, sink) so we don't re-probe identical patterns
        # found in multiple chunks of the same bundle.
        seen: set[tuple[str, str]] = set()
        unique: list = []
        for c in js_dom_xss_findings:
            key = (c.source, c.sink)
            if key in seen:
                continue
            seen.add(key)
            unique.append(c)

        # Order high-priority candidates first
        unique.sort(key=lambda c: 0 if getattr(c, "priority", "medium") == "high" else 1)

        target_root = target.rstrip("/") + "/"
        probes_done = 0

        for cand in unique:
            if probes_done >= self.max_probes:
                result.notes.append(f"probe cap reached ({self.max_probes})")
                break

            source_kind = _PROBEABLE_SOURCES.get(cand.source)
            if source_kind is None:
                # Source is real but not driveable from the URL alone
                # (window.name, postMessage, *Storage, document.cookie).
                result.notes.append(
                    f"skipped {cand.source}→{cand.sink}: source not URL-driveable"
                )
                continue

            result.candidates_probed += 1

            # Build the probe URL(s) — try hash and/or query depending on source
            probe_urls = self._build_probe_urls(target_root, source_kind)

            # Try each variant; first confirmed wins
            best: Optional[DOMXSSFinding] = None
            for probe_url in probe_urls:
                if probes_done >= self.max_probes:
                    break
                probes_done += 1
                bv = await self.browser_verifier.verify_xss(probe_url, auth_headers=auth_headers)
                finding = DOMXSSFinding(
                    source=cand.source, sink=cand.sink,
                    source_file=getattr(cand, "source_file", ""),
                    probe_url=probe_url,
                    verdict=bv.verdict, confidence=bv.confidence,
                    evidence=bv.evidence, signal=bv.signal,
                )
                # Promote the best verdict we've seen for this candidate
                if best is None or _verdict_rank(finding.verdict) > _verdict_rank(best.verdict):
                    best = finding
                if finding.verdict == "confirmed":
                    break

            if best is not None:
                result.findings.append(best)

        return result

    @staticmethod
    def _build_probe_urls(target_root: str, source_kind: str) -> list[str]:
        """Construct one or more probe URLs that put a canary XSS payload in
        the right URL position for `source_kind`."""
        from browser_verifier import BrowserVerifier
        # Use the html-context payload — the OWASP polyglot variants are too
        # noisy for this targeted test.
        canary_payload = BrowserVerifier.xss_payloads("html")[0]  # <svg/onload=...>

        urls: list[str] = []
        if source_kind in ("hash", "both"):
            # Hash sources read everything after #. Two shapes:
            #   /#<payload>     — naked
            #   /#/foo?x=<payload>  — common SPA hash-route + query
            urls.append(target_root + "#" + canary_payload)
            urls.append(target_root + "#/x?q=" + canary_payload)

        if source_kind in ("query", "both"):
            from urllib.parse import quote
            encoded = quote(canary_payload, safe="")
            for pname in _COMMON_QUERY_PARAMS:
                urls.append(f"{target_root}?{pname}={encoded}")

        return urls[:6]  # cap variants per candidate


def _verdict_rank(v: str) -> int:
    """Higher is better — used to pick the best result across probe variants."""
    return {
        "confirmed": 4,
        "likely": 3,
        "not_confirmed": 2,
        "skipped": 1,
        "error": 0,
    }.get(v, 0)
