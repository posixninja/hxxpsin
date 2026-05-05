"""Rule-based probe advisor.

Given a selected request and current AppState, returns a ranked list of
Suggestion objects — each with a probe name, display label, confidence
(0.0–1.0), and a short human-readable reason.

Rules are additive: multiple rules can fire for the same probe, and their
confidence values are capped at 1.0.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from .state import AppState


@dataclass
class Suggestion:
    probe: str          # key matching _PROBE_STEPS in app.py
    label: str          # display name
    confidence: float   # 0.0–1.0
    reasons: list[str] = field(default_factory=list)

    @property
    def confidence_bar(self) -> str:
        filled = round(self.confidence * 8)
        return "█" * filled + "░" * (8 - filled)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

# Each rule: (probe_key, label, confidence_delta, reason_fn)
# reason_fn(req, state) -> str | None  — returns reason text or None if rule doesn't fire

_ID_PATH_RE = re.compile(r"/\d{1,10}(?:/|$)|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}")
_SQL_ERROR_RE = re.compile(r"sql|syntax error|ORA-\d+|mysql_fetch|pg_query|sqlite", re.IGNORECASE)
_REDIRECT_PARAM_RE = re.compile(r"[?&](next|return|redirect|url|to|dest|location|goto)=", re.IGNORECASE)
_UPLOAD_PATH_RE = re.compile(r"/upload|/import|/file|/attachment|/media|/image|/avatar|/photo", re.IGNORECASE)
_ADMIN_PATH_RE = re.compile(r"/admin|/manage|/dashboard|/backoffice|/superuser|/staff|/operator", re.IGNORECASE)
_AUTH_PATH_RE = re.compile(r"/login|/signin|/auth|/token|/oauth|/session|/password|/register|/signup", re.IGNORECASE)
_GRAPHQL_RE = re.compile(r"/graphql|/gql|/query", re.IGNORECASE)
_CRLF_PARAM_RE = re.compile(r"[?&][a-z_-]+=", re.IGNORECASE)


def _url(req: dict) -> str:
    return req.get("url", "")

def _method(req: dict) -> str:
    return req.get("method", "GET").upper()

def _headers(req: dict) -> dict:
    return req.get("headers", {}) or {}

def _body(req: dict) -> str:
    return req.get("body") or ""

def _response_body(req: dict) -> str:
    resp = req.get("response") or {}
    return req.get("response_body") or resp.get("body") or ""

def _response_status(req: dict) -> int:
    resp = req.get("response") or {}
    return int(req.get("response_status") or resp.get("status") or 0)

def _all_text(req: dict) -> str:
    return _url(req) + " " + _body(req) + " " + _response_body(req)

def _stack(state: AppState) -> dict:
    return state.stackprint.get("detected", {})


# ---------------------------------------------------------------------------
# Rule table: (probe, label, delta, test_fn) → reason string or None
# ---------------------------------------------------------------------------

def _rules(req: dict, state: AppState) -> list[tuple[str, str, float, str]]:
    """Return (probe, label, delta, reason) tuples for all firing rules."""
    fired: list[tuple[str, str, float, str]] = []

    url = _url(req)
    method = _method(req)
    body = _body(req)
    resp_body = _response_body(req)
    status = _response_status(req)
    hdrs = {k.lower(): v for k, v in _headers(req).items()}
    stack = _stack(state)

    parsed = urlparse(url)
    path = parsed.path or "/"
    qs = parsed.query or ""

    # ── IDOR ────────────────────────────────────────────────────────────
    if _ID_PATH_RE.search(path):
        fired.append(("idor", "IDOR probe", 0.7, "numeric/UUID segment in path"))
    if method == "GET" and qs and re.search(r"[?&](id|user_?id|account|uid)=\d+", url, re.I):
        fired.append(("idor", "IDOR probe", 0.5, "user ID in query string"))
    if method in ("PUT", "PATCH") and _ID_PATH_RE.search(path):
        fired.append(("idor", "IDOR probe", 0.4, "write to resource with ID — check ownership"))

    # ── JWT ─────────────────────────────────────────────────────────────
    auth_hdr = hdrs.get("authorization", "")
    if auth_hdr.lower().startswith("bearer ") and _JWT_RE.search(auth_hdr):
        fired.append(("jwt", "JWT attack", 0.9, "Bearer JWT in request Authorization header"))
    if _JWT_RE.search(resp_body):
        fired.append(("jwt", "JWT attack", 0.6, "JWT token in response body"))
    if "set-cookie" in hdrs and "token" in hdrs.get("set-cookie", "").lower():
        fired.append(("jwt", "JWT attack", 0.4, "token-like cookie in response"))

    # ── Auth bypass ──────────────────────────────────────────────────────
    if _AUTH_PATH_RE.search(path):
        fired.append(("active", "Auth bypass", 0.8, "login/auth endpoint"))
    if status in (401, 403):
        fired.append(("active", "Auth bypass", 0.6, f"{status} response — may be bypassable"))

    # ── SQL injection ────────────────────────────────────────────────────
    if method == "POST" and ("application/json" in hdrs.get("content-type", "") or body):
        fired.append(("active", "SQLi (active scan)", 0.5, "POST with body — injectable fields"))
    if _SQL_ERROR_RE.search(resp_body):
        fired.append(("active", "SQLi (active scan)", 0.85, "SQL error string in response"))
    langs = stack.get("language", [])
    if any(l in ("PHP", "Java") for l in langs):
        fired.append(("active", "SQLi (active scan)", 0.3, f"{'/'.join(langs)} stack — historically SQLi-prone"))

    # ── NoSQL ────────────────────────────────────────────────────────────
    dbs = stack.get("database", [])
    if any("mongo" in d.lower() for d in dbs):
        fired.append(("nosql", "NoSQL probe", 0.8, "MongoDB detected in stackprint"))
    if any("express" in f.lower() for f in stack.get("framework", [])):
        fired.append(("nosql", "NoSQL probe", 0.4, "Express.js — often paired with MongoDB"))

    # ── BFLA / admin ────────────────────────────────────────────────────
    if _ADMIN_PATH_RE.search(path):
        fired.append(("active", "BFLA / admin access", 0.75, "admin/management path"))
    if method in ("DELETE", "PUT", "PATCH") and not _ID_PATH_RE.search(path):
        fired.append(("active", "BFLA / admin access", 0.4, f"{method} on non-resource path"))

    # ── Upload ───────────────────────────────────────────────────────────
    if _UPLOAD_PATH_RE.search(path):
        fired.append(("upload", "Upload probe", 0.85, "upload/file path detected"))
    if "multipart/form-data" in hdrs.get("content-type", ""):
        fired.append(("upload", "Upload probe", 0.9, "multipart body — file upload endpoint"))

    # ── Open redirect ────────────────────────────────────────────────────
    if _REDIRECT_PARAM_RE.search(url):
        fired.append(("active", "Open redirect", 0.8, "redirect parameter in URL"))
    if status in (301, 302, 307, 308):
        fired.append(("active", "Open redirect", 0.5, f"{status} redirect response"))

    # ── CRLF ────────────────────────────────────────────────────────────
    if qs:
        fired.append(("crlf", "CRLF probe", 0.4, "URL has query parameters"))
    if method == "GET" and _CRLF_PARAM_RE.search(url):
        fired.append(("crlf", "CRLF probe", 0.3, "multiple query params — injection surface"))

    # ── Desync ──────────────────────────────────────────────────────────
    servers = stack.get("server", [])
    if any(s in ("nginx", "Apache", "HAProxy", "Varnish") for s in servers):
        fired.append(("desync", "Desync probe", 0.5, f"{'/'.join(servers[:2])} — desync-prone server"))
    if "transfer-encoding" in hdrs or "content-length" in hdrs:
        fired.append(("desync", "Desync probe", 0.35, "CL/TE headers present"))

    # ── Param miner ──────────────────────────────────────────────────────
    if method == "GET" and not qs:
        fired.append(("param", "Param miner", 0.5, "GET endpoint with no params — hidden params likely"))
    if _ADMIN_PATH_RE.search(path):
        fired.append(("param", "Param miner", 0.4, "admin path — debug/internal params worth mining"))

    # ── GraphQL ──────────────────────────────────────────────────────────
    if _GRAPHQL_RE.search(path) or "application/graphql" in hdrs.get("content-type", ""):
        fired.append(("active", "GraphQL introspection", 0.9, "GraphQL endpoint detected"))

    # ── WebSocket ────────────────────────────────────────────────────────
    if state.probe_results.get("ws") or any(
        "websocket" in str(r).lower() for r in state.requests[:5]
    ):
        fired.append(("ws", "WebSocket probe", 0.5, "WebSocket traffic observed"))

    # ── Enrichment ───────────────────────────────────────────────────────
    if resp_body and any(k in resp_body.lower() for k in ("email", "password", "token", "secret", "user")):
        fired.append(("enrichment", "Enrichment", 0.7, "response contains identity/credential fields"))

    return fired


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def suggest(req: dict, state: AppState) -> list[Suggestion]:
    """Return probe suggestions for a single request, ranked by confidence."""
    acc: dict[str, Suggestion] = {}
    for probe, label, delta, reason in _rules(req, state):
        if probe not in acc:
            acc[probe] = Suggestion(probe=probe, label=label, confidence=0.0)
        s = acc[probe]
        s.confidence = min(1.0, s.confidence + delta)
        if reason not in s.reasons:
            s.reasons.append(reason)

    ranked = sorted(acc.values(), key=lambda s: -s.confidence)
    return [s for s in ranked if s.confidence >= 0.3]
