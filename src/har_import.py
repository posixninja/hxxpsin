"""
har_import.py — Import HTTP Archive (HAR) files from Burp / ZAP / DevTools.

When the operator already has authenticated traffic captured in their proxy of
choice (Burp Suite, OWASP ZAP, Chrome DevTools "Save all as HAR with content"),
they can pass `--har file.har` to skip the live Playwright crawler entirely.
The full request+response data — including bodies — is reconstituted directly
into the Collector, and the rest of the pipeline runs unchanged.

Bonus: scrapes representative authenticated headers (Authorization, Cookie,
X-Auth-Token) from the HAR so downstream probes (verifier, idor, active-scan)
can run as the authenticated user without an extra `--auth-headers` flag.

HAR spec reference: http://www.softwareishard.com/blog/har-12-spec/
All three tools (Burp, ZAP, DevTools) emit HAR 1.2 compliant files.
"""

import base64
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from collector import CapturedRequest


# Headers that carry authentication and should be harvested into auth_headers.
# Keep case-insensitive (HTTP headers are CI per RFC 7230).
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-auth-token", "x-access-token",
    "x-api-token", "x-id-token", "x-session-token", "x-jwt",
    "auth-token", "x-api-key", "api-key",
}

# Map response Content-Type prefixes to Playwright-style resource_type values.
# Mirrors the resource_type the Playwright crawler would have assigned.
_CT_TO_RESOURCE_TYPE = (
    ("application/json",       "xhr"),
    ("application/xml",        "xhr"),
    ("application/graphql",    "xhr"),
    ("text/event-stream",      "xhr"),
    ("text/html",              "document"),
    ("text/xml",               "xhr"),
    ("text/css",               "stylesheet"),
    ("text/javascript",        "script"),
    ("application/javascript", "script"),
    ("image/",                 "image"),
    ("font/",                  "font"),
    ("application/font-woff",  "font"),
    ("audio/",                 "media"),
    ("video/",                 "media"),
)


def _resource_type_from_content_type(ct: str) -> str:
    if not ct:
        return "other"
    ct = ct.lower().split(";", 1)[0].strip()
    for prefix, rt in _CT_TO_RESOURCE_TYPE:
        if ct.startswith(prefix):
            return rt
    return "other"


def _decode_body(content: dict) -> Optional[str]:
    """Pull the body text out of a HAR `request.postData` or `response.content`.
    Handles base64-encoded binary (HAR spec for non-text responses)."""
    if not isinstance(content, dict):
        return None
    text = content.get("text")
    if not text:
        return None
    encoding = content.get("encoding", "")
    if encoding == "base64":
        try:
            decoded = base64.b64decode(text)
            try:
                return decoded.decode("utf-8")
            except UnicodeDecodeError:
                # Binary body — return a placeholder so the downstream
                # consumer knows there WAS a body even if it wasn't text
                return f"<binary, {len(decoded)} bytes>"
        except Exception:
            return None
    return text


def _harvest_auth_headers(entries: list) -> dict[str, str]:
    """Walk all entries and return the most common value for each known auth
    header name. Most-common-wins handles cases where the user logged out
    mid-capture and the later entries have stale tokens."""
    by_name: dict[str, Counter] = {}
    for entry in entries:
        req = entry.get("request", {})
        for h in req.get("headers", []):
            name = (h.get("name") or "").lower()
            value = h.get("value") or ""
            if name in _AUTH_HEADER_NAMES and value:
                by_name.setdefault(name, Counter())[value] += 1
    out: dict[str, str] = {}
    for name, counter in by_name.items():
        most_common_value, _count = counter.most_common(1)[0]
        # Use canonical capitalization for the well-known names
        canonical = {"authorization": "Authorization", "cookie": "Cookie"}.get(name, name)
        out[canonical] = most_common_value
    return out


@dataclass
class HARImportResult:
    """Returned from HARImporter.load — gives the caller everything needed
    to populate the Collector and the auth-header bag."""
    requests: list[CapturedRequest] = field(default_factory=list)
    auth_headers: dict[str, str] = field(default_factory=dict)
    source_tool: str = ""        # "Burp", "ZAP", "DevTools", or generic
    source_version: str = ""     # creator.version
    entries_total: int = 0       # raw entry count from HAR
    entries_skipped_other_origin: int = 0
    entries_skipped_unparseable: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_tool": self.source_tool,
            "source_version": self.source_version,
            "entries_total": self.entries_total,
            "requests_imported": len(self.requests),
            "entries_skipped_other_origin": self.entries_skipped_other_origin,
            "entries_skipped_unparseable": self.entries_skipped_unparseable,
            "auth_headers_harvested": list(self.auth_headers.keys()),
            "notes": self.notes,
        }


class HARImporter:
    """Reads a HAR file and produces CapturedRequest entries that the rest of
    the pipeline (classifier, verifier, IDOR, active scan, reporter) consumes
    identically to crawler-captured requests."""

    def __init__(
        self,
        path: str,
        scope_origin: Optional[str] = None,
        include_assets: bool = False,
    ):
        self.path = Path(path)
        # If set, only entries whose URL hostname matches this origin are kept
        self.scope_origin = scope_origin
        # If False, drop image/css/font/media to keep the request set focused
        self.include_assets = include_assets

    def load(self) -> HARImportResult:
        result = HARImportResult()
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            result.notes.append(f"file not found: {self.path}")
            return result
        except json.JSONDecodeError as exc:
            result.notes.append(f"invalid JSON: {exc}")
            return result

        log = data.get("log") if isinstance(data, dict) else None
        if not isinstance(log, dict):
            result.notes.append("missing 'log' object — not a HAR file")
            return result

        creator = log.get("creator") or {}
        result.source_tool = self._identify_tool(creator)
        result.source_version = (creator.get("version") or "")[:32]

        entries = log.get("entries") or []
        result.entries_total = len(entries)
        if not entries:
            result.notes.append("HAR has zero entries")
            return result

        # Auth-header harvest from the full entry list so we get the most-common
        # token across the whole capture (handles login-then-actions flows).
        result.auth_headers = _harvest_auth_headers(entries)

        scope_host = urlparse(self.scope_origin).netloc if self.scope_origin else ""

        skip_resource_types = set() if self.include_assets else {
            "image", "font", "stylesheet", "media",
        }

        for entry in entries:
            try:
                req = entry.get("request") or {}
                resp = entry.get("response") or {}
                url = req.get("url") or ""
                method = (req.get("method") or "GET").upper()
                if not url or not url.startswith(("http://", "https://")):
                    result.entries_skipped_unparseable += 1
                    continue

                if scope_host:
                    parsed = urlparse(url)
                    if parsed.netloc != scope_host:
                        result.entries_skipped_other_origin += 1
                        continue

                # Headers — flatten name/value pairs into a dict (last write wins)
                headers = {h["name"]: h["value"]
                           for h in req.get("headers", [])
                           if isinstance(h, dict) and "name" in h}

                req_body = _decode_body(req.get("postData") or {})
                resp_body = _decode_body(resp.get("content") or {})

                # Resource type — derive from response content-type when present;
                # fall back to "xhr" for API-shaped paths and "document" otherwise
                resp_headers = {h["name"]: h["value"]
                                for h in resp.get("headers", [])
                                if isinstance(h, dict) and "name" in h}
                ct = ""
                for k, v in resp_headers.items():
                    if k.lower() == "content-type":
                        ct = v
                        break
                rtype = _resource_type_from_content_type(ct)

                if rtype in skip_resource_types:
                    continue

                cr = CapturedRequest(
                    method=method, url=url, headers=headers,
                    body=req_body, resource_type=rtype,
                    response_status=resp.get("status"),
                    response_headers=resp_headers,
                    response_body=resp_body,
                )
                result.requests.append(cr)
            except Exception as exc:
                result.entries_skipped_unparseable += 1
                # Log the first few parse failures for debugging
                if len(result.notes) < 5:
                    result.notes.append(f"entry parse error: {type(exc).__name__}: {exc}")

        return result

    @staticmethod
    def _identify_tool(creator: dict) -> str:
        """Best-effort identification of the proxy that produced the HAR."""
        name = (creator.get("name") or "").lower()
        if "burp" in name:
            return "Burp Suite"
        if "zap" in name or "owasp" in name:
            return "OWASP ZAP"
        if "webinspector" in name or "chrome" in name or "devtools" in name:
            return "Chrome DevTools"
        if "firefox" in name:
            return "Firefox DevTools"
        if "fiddler" in name:
            return "Fiddler"
        if "charles" in name:
            return "Charles Proxy"
        if "mitmproxy" in name:
            return "mitmproxy"
        return creator.get("name") or "unknown"


# ---------------------------------------------------------------------------
# CLI entry point — standalone use / smoke testing
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Import a HAR file and print a summary")
    p.add_argument("har_file")
    p.add_argument("--scope", help="Only keep entries from this origin")
    p.add_argument("--include-assets", action="store_true",
                   help="Don't drop images/CSS/fonts")
    args = p.parse_args()

    importer = HARImporter(args.har_file, scope_origin=args.scope,
                           include_assets=args.include_assets)
    result = importer.load()
    print(json.dumps(result.to_dict(), indent=2))
    print(f"\nFirst 5 imported requests:", file=sys.stderr)
    for r in result.requests[:5]:
        body_preview = (r.response_body or "")[:80].replace("\n", " ")
        print(f"  {r.method:6} {r.url[:60]:60}  status={r.response_status}  body={body_preview!r}",
              file=sys.stderr)


if __name__ == "__main__":
    _main()
