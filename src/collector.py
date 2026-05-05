"""
Stores and deduplicates everything the crawler captures.
Classifier and reporter consume this data.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


@dataclass
class CapturedCookie:
    name: str
    value: str
    source_url: str          # URL of the response that set this cookie
    http_only: bool = False
    secure: bool = False
    same_site: str = ""      # Strict | Lax | None | ""
    max_age: Optional[int] = None
    domain: str = ""
    path: str = "/"

    @property
    def is_jwt(self) -> bool:
        return bool(_JWT_RE.match(self.value))

    @property
    def issues(self) -> list[str]:
        found = []
        if not self.http_only:
            found.append("missing HttpOnly — accessible via document.cookie (XSS session theft)")
        if not self.secure:
            found.append("missing Secure — sent over plaintext HTTP")
        if self.same_site.lower() not in ("strict", "lax"):
            found.append(f"SameSite={self.same_site or 'not set'} — CSRF risk on cross-site requests")
        if self.is_jwt:
            found.append("value looks like JWT — inspect alg header and check weak secret")
        if self.max_age is not None and self.max_age > 86_400 * 30:
            found.append(f"long-lived cookie (Max-Age={self.max_age}s) — persistent session risk")
        return found

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_url": self.source_url,
            "http_only": self.http_only,
            "secure": self.secure,
            "same_site": self.same_site,
            "max_age": self.max_age,
            "is_jwt": self.is_jwt,
            "issues": self.issues,
        }


def parse_set_cookie(header_value: str, source_url: str) -> Optional["CapturedCookie"]:
    """Parse a single Set-Cookie header value into a CapturedCookie."""
    parts = [p.strip() for p in header_value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    name = name.strip()
    value = value.strip()
    if not name:
        return None

    cookie = CapturedCookie(name=name, value=value, source_url=source_url)
    for attr in parts[1:]:
        al = attr.lower()
        if al == "httponly":
            cookie.http_only = True
        elif al == "secure":
            cookie.secure = True
        elif al.startswith("samesite="):
            cookie.same_site = attr.split("=", 1)[1].strip()
        elif al.startswith("max-age="):
            try:
                cookie.max_age = int(attr.split("=", 1)[1].strip())
            except ValueError:
                pass
        elif al.startswith("domain="):
            cookie.domain = attr.split("=", 1)[1].strip()
        elif al.startswith("path="):
            cookie.path = attr.split("=", 1)[1].strip()
    return cookie


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: dict
    body: Optional[str]
    resource_type: str
    # Response fields — populated when the scanner or crawler captures the reply
    response_status: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[str] = None


@dataclass
class CapturedWebSocket:
    url: str
    messages_sent: list = field(default_factory=list)
    messages_received: list = field(default_factory=list)


class Collector:
    def __init__(self, origin: str):
        self.origin = origin
        self._requests: list[CapturedRequest] = []
        self._response_meta: dict[str, dict] = {}   # url -> {status, headers}
        self._cookies: list[CapturedCookie] = []
        self._seen_cookie_names: set[str] = set()
        self._websockets: list[CapturedWebSocket] = []
        self._js_bundle_urls: list[str] = []
        self._js_routes: set[str] = set()
        self._js_constants: list[dict] = []
        self._errors: list[dict] = []
        self._seen_req_keys: set[str] = set()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def add_request(self, req: CapturedRequest) -> None:
        key = self._req_key(req)
        if key in self._seen_req_keys:
            return
        self._seen_req_keys.add(key)
        self._requests.append(req)

    def add_response_meta(self, url: str, status: int, headers: dict,
                          body: Optional[str] = None) -> None:
        self._response_meta[url] = {"status": status, "headers": headers, "body": body}
        # Back-fill response fields on the matching captured request
        for req in self._requests:
            if req.url == url and req.response_status is None:
                req.response_status = status
                req.response_headers = headers
                req.response_body = body
                break
        # Parse Set-Cookie headers
        for hdr_name, hdr_val in headers.items():
            if hdr_name.lower() == "set-cookie":
                self._ingest_set_cookie(hdr_val, url)

    def set_response_body(self, url: str, body: str) -> bool:
        """Backfill the response body for a previously-captured request.
        Used by the crawler's async body-capture path (where headers/status
        are recorded synchronously but body is awaited later).

        Returns True if a matching request was found and updated.
        Idempotent — last-write-wins for repeated URLs."""
        # Find the most recent matching request that doesn't already have a body
        for req in reversed(self._requests):
            if req.url == url and req.response_body is None:
                req.response_body = body
                return True
        # Fall back: update the most recent matching request even if body exists
        for req in reversed(self._requests):
            if req.url == url:
                req.response_body = body
                return True
        # Also update the response_meta cache so it's visible on dump
        if url in self._response_meta:
            self._response_meta[url]["body"] = body
            return True
        return False

    def _ingest_set_cookie(self, header_value: str, source_url: str) -> None:
        cookie = parse_set_cookie(header_value, source_url)
        if cookie and cookie.name not in self._seen_cookie_names:
            self._seen_cookie_names.add(cookie.name)
            self._cookies.append(cookie)

    def add_cookie(self, cookie: "CapturedCookie") -> None:
        if cookie.name not in self._seen_cookie_names:
            self._seen_cookie_names.add(cookie.name)
            self._cookies.append(cookie)

    def add_websocket(self, ws: CapturedWebSocket) -> None:
        self._websockets.append(ws)

    def add_js_bundle_url(self, url: str) -> None:
        if url not in self._js_bundle_urls:
            self._js_bundle_urls.append(url)

    def add_js_discovered_route(self, route: str) -> None:
        self._js_routes.add(route)

    def add_js_constant(self, full_text: str, value: str) -> None:
        self._js_constants.append({"text": full_text, "value": value})

    def log_error(self, url: str, message: str) -> None:
        self._errors.append({"url": url, "error": message})

    # ------------------------------------------------------------------
    # Query helpers for classifier
    # ------------------------------------------------------------------

    @property
    def requests(self) -> list[CapturedRequest]:
        return self._requests

    @property
    def cookies(self) -> list[CapturedCookie]:
        return self._cookies

    @property
    def cookies_with_issues(self) -> list[CapturedCookie]:
        return [c for c in self._cookies if c.issues]

    @property
    def websockets(self) -> list[CapturedWebSocket]:
        return self._websockets

    @property
    def js_routes(self) -> list[str]:
        return sorted(self._js_routes)

    @property
    def js_constants(self) -> list[dict]:
        return self._js_constants

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "requests": [self._req_to_dict(r) for r in self._requests],
            "response_meta": self._response_meta,
            "cookies": [c.to_dict() for c in self._cookies],
            "cookie_issues": [c.to_dict() for c in self.cookies_with_issues],
            "websockets": [self._ws_to_dict(w) for w in self._websockets],
            "js_bundle_urls": self._js_bundle_urls,
            "js_discovered_routes": sorted(self._js_routes),
            "js_constants": self._js_constants,
            "errors": self._errors,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _req_key(req: CapturedRequest) -> str:
        p = urlparse(req.url)
        path_key = f"{req.method}:{p.scheme}://{p.netloc}{p.path}"
        return path_key

    @staticmethod
    def _req_to_dict(req: CapturedRequest) -> dict:
        d: dict = {
            "method": req.method,
            "url": req.url,
            "headers": req.headers,
            "body": req.body,
            "resource_type": req.resource_type,
        }
        if req.response_status is not None:
            d["response"] = {
                "status": req.response_status,
                "headers": req.response_headers or {},
                "body": req.response_body,
            }
        return d

    @staticmethod
    def _ws_to_dict(ws: CapturedWebSocket) -> dict:
        return {
            "url": ws.url,
            "messages_sent": ws.messages_sent,
            "messages_received": ws.messages_received,
        }
