"""
Risk classifier for hxxpsin.

Scores captured requests against known vulnerability patterns.
Each check is an independent function — easy to add new ones.
Output is a sorted list of Finding objects plus grouped category views
for the reporter.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse

from collector import Collector, CapturedRequest, CapturedWebSocket, CapturedCookie

# ---------------------------------------------------------------------------
# Bug categories (used as tags on findings)
# ---------------------------------------------------------------------------

class Cat:
    IDOR        = "IDOR/BOLA"
    BFLA        = "BFLA"
    ADMIN       = "Admin/Internal Exposure"
    GRAPHQL     = "GraphQL"
    WEBSOCKET   = "WebSocket"
    UPLOAD      = "File Upload"
    SSRF        = "SSRF Surface"
    MASS_ASSIGN = "Mass Assignment"
    RACE        = "Race Condition"
    AUTH        = "Auth/Session"
    INJECTION   = "Injection"
    WRITE       = "State-Changing"
    CORS        = "CORS Misconfiguration"
    CSRF        = "CSRF"
    REDIRECT    = "Open Redirect"
    NOSQL       = "NoSQL Injection"
    PROTO_POLL  = "Prototype Pollution"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    method: str
    url: str
    score: int
    categories: list[str]
    evidence: list[str]
    body: Optional[str] = None             # request body
    headers: Optional[dict] = None         # request headers
    # Response data — populated when the source (crawler / HAR) captured it.
    # Lets verifier + idor_probe skip refetch when present.
    response_status: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "method": self.method,
            "url": self.url,
            "categories": self.categories,
            "evidence": self.evidence,
            "body": self.body,
        }


@dataclass
class WebSocketFinding:
    url: str
    score: int
    evidence: list[str]
    keys_observed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "url": self.url,
            "evidence": self.evidence,
            "keys_observed": self.keys_observed,
        }


@dataclass
class CookieFinding:
    name: str
    source_url: str
    issues: list[str]
    is_jwt: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_url": self.source_url,
            "issues": self.issues,
            "is_jwt": self.is_jwt,
        }


@dataclass
class ClassifierResult:
    request_findings: list[Finding]
    websocket_findings: list[WebSocketFinding]
    js_route_findings: list[dict]
    js_constants: list[dict]
    by_category: dict[str, list[Finding]]
    cookie_findings: list[CookieFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

# Path segments that indicate admin/internal exposure
_ADMIN_PATH_RE = re.compile(
    r"/(admin|internal|debug|actuator|phpmyadmin|wp-admin|\.env|console"
    r"|manage|management|backstage|staff|superuser|sysadmin|devtools?)",
    re.IGNORECASE,
)

# Lower-severity exposure paths (monitoring/server-info disclosure).
# Removed: openapi, swagger, graphiql, api-docs — these are intended public
# documentation surfaces in modern APIs and produced overwhelming false
# positives. They're still discovered by stackprint and listed under
# Discovery, just not flagged as "Admin/Internal Exposure".
_EXPOSURE_PATH_RE = re.compile(
    r"/(metrics|monitoring|server-status|server-info|env|trace|heapdump|threaddump)",
    re.IGNORECASE,
)

# API paths worth probing for CORS misconfiguration
_CORS_API_PATH_RE = re.compile(
    r"/(api|v\d+|graphql|rest|auth|user|account|admin|data|me|profile)",
    re.IGNORECASE,
)

# Object-ID patterns in URL path segments
_PATH_ID_RE = re.compile(
    r"/(?P<seg>\d{1,20}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?:/|$|\?)",
    re.IGNORECASE,
)

# Field names that represent object ownership / identity
_IDOR_FIELD_RE = re.compile(
    r"\b(user_?id|account_?id|owner_?id|org_?id|tenant_?id|customer_?id"
    r"|invoice_?id|order_?id|document_?id|file_?id|record_?id|resource_?id"
    r"|project_?id|team_?id|member_?id|profile_?id|session_?id|uid)\b",
    re.IGNORECASE,
)

# Field names that influence privilege / role
_PRIV_FIELD_RE = re.compile(
    r"\b(role|is_?admin|is_?staff|is_?superuser|permission|scope|plan|tier"
    r"|feature_?flag|approved|verified|active|enabled|status|group|access_?level"
    r"|balance|credit|quota|limit|ban|privilege|rank|subscription)\b",
    re.IGNORECASE,
)

# Write endpoints on user/account resources → mass-assignment probe targets
_MASS_ASSIGN_PATH_RE = re.compile(
    r"/(users?|accounts?|profile|me|settings|members?|customers?|tenants?|orgs?)"
    r"(/\w+)*(/|$|\?)",
    re.IGNORECASE,
)

# Registration / creation paths where mass assignment is commonly introduced
_MASS_ASSIGN_CREATE_RE = re.compile(
    r"/(register|signup|sign.?up|create.?account|new.?user|enroll)",
    re.IGNORECASE,
)

# Auth bypass surface — password reset / account recovery flows
_AUTH_BYPASS_PATH_RE = re.compile(
    r"/(forgot|reset|recover|change.?password|password.?reset|account.?recovery"
    r"|unlock|resend|magic.?link|otp|mfa|2fa)",
    re.IGNORECASE,
)

# URL-fetching / webhook parameters → SSRF surface
_SSRF_FIELD_RE = re.compile(
    r"\b(url|webhook|callback|redirect|next|return_?url|endpoint|target"
    r"|fetch|import|src|source|dest|destination|feed|proxy|image_?url"
    r"|avatar_?url|logo_?url|icon_?url|link|href)\b",
    re.IGNORECASE,
)

_SSRF_PATH_RE = re.compile(
    # Require path segment to end at a boundary (/, ?, end) so /Feedbacks doesn't match /feed
    r"/(webhook|fetch|preview|screenshot|pdf|render|proxy"
    r"|thumbnail|og|opengraph|oembed|rss"
    r"|feed|import_?url|import_?paste)(?:/|$|\?)",
    re.IGNORECASE,
)

# Paths that commonly serve file upload — word-boundary anchor so /logout != /logo
_UPLOAD_PATH_RE = re.compile(
    r"/(upload|attach|attachment|file|media|document|image"
    r"|avatar|logo|asset|blob)(?:/|$|\?|-|_)",
    re.IGNORECASE,
)

# Paths / fields typical of race-condition targets
# Use word boundaries so /users doesn't match via /use
_RACE_PATH_RE = re.compile(
    r"/(coupon|promo|redeem|transfer|pay|purchase|checkout|apply|claim"
    r"|subscribe|confirm|activate|vote|like|follow|refer|invite)(?:/|$|\?)",
    re.IGNORECASE,
)

# Injection probe surface: params whose values go into queries/templates.
# Tightened — generic search params (q, search, filter, sort, order) moved to
# _SEARCH_PARAM_RE below because they were producing false positives on every
# search box. The remaining names are either dangerous-by-shape (cmd, eval,
# exec, template) or auth fields where injection IS routinely present.
_INJECT_FIELD_RE = re.compile(
    r"\b(where|expr|template|cmd|command|exec|eval|run|script"
    r"|lang|locale|format|action|op|operation"
    r"|username|email|login|password)\b",
    re.IGNORECASE,
)

# Search-shaped params — discoverable surface but very weak injection signal.
# Kept separate so _check_injection_params can score them lower (or skip).
_SEARCH_PARAM_RE = re.compile(r"\b(q|search|filter|sort|order|find|query)\b", re.IGNORECASE)

# Self-service path prefixes — endpoints where the user is allowed to act on
# their OWN account/profile. BFLA tagging on /<self>/disable etc. is a noise
# generator; require an /admin segment or a different-user-id signal instead.
_SELF_SERVICE_PATH_RE = re.compile(
    r"/(2fa|profile|account|settings|preferences|self|me)(?:/|$|\?)",
    re.IGNORECASE,
)

# Open redirect: parameters that commonly control redirect destination
_REDIRECT_PARAM_RE = re.compile(
    r"^(redirect|redirect_url|redirect_uri|next|return|return_url|return_to|"
    r"redir|rurl|target|dest|destination|goto|url|link|forward|go|continue|"
    r"callback|success|back|location|to|out)$",
    re.IGNORECASE,
)

# NoSQL: params that suggest MongoDB-style field access
_NOSQL_PARAM_RE = re.compile(
    r"\b(filter|find|where|aggregate|pipeline|selector|match)\b",
    re.IGNORECASE,
)

# NoSQL: MongoDB operators in request body
_NOSQL_BODY_RE = re.compile(r'\$(?:ne|gt|lt|gte|lte|in|nin|regex|where|exists|type)', re.IGNORECASE)

# NoSQL: error strings in response (used by classifier heuristic)
_NOSQL_ERROR_RE = re.compile(r'(BSONTypeError|MongoError|CastError|E11000|bad operator)', re.IGNORECASE)

# Prototype pollution: magic params in JSON keys or URL params
_PROTO_POLL_RE = re.compile(r'(__proto__|constructor\.prototype|prototype\[)', re.IGNORECASE)

# CSRF-absent heuristic — only applies to traditional form submissions, not REST/JSON APIs
_CSRF_BODY_KEYS_RE = re.compile(r"csrf|_token|authenticity_token|xsrf", re.IGNORECASE)
_FORM_CT_RE = re.compile(r"application/x-www-form-urlencoded|multipart/form-data", re.IGNORECASE)

# GraphQL tell-tales in body
_GQL_BODY_RE = re.compile(r'"(query|mutation|subscription)"\s*:', re.IGNORECASE)

# WebSocket message keys of interest
_WS_KEY_RE = re.compile(
    r'"(room_?id|channel_?id|user_?id|account_?id|event|type|action|topic'
    r'|subscribe|join|message|data|payload|auth|token)"',
    re.IGNORECASE,
)

# JS routes that are high-interest when discovered in bundles
_JS_ROUTE_SCORE_RE = re.compile(
    r"/(admin|internal|debug|graphql|api|v\d+|dashboard|settings|account"
    r"|user|profile|billing|invoice|payment|transfer|webhook|export|import)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Per-request checks
# Each check returns (score_delta, category, evidence_string) or None.
# ---------------------------------------------------------------------------

def _check_admin_path(req: CapturedRequest, path: str, params: dict):
    # JS/CSS/image files served from an /admin path are just SPA assets, not endpoints
    if req.resource_type in _STATIC_RESOURCE_TYPES:
        return None
    m = _ADMIN_PATH_RE.search(path)
    if m:
        return 6, Cat.ADMIN, f"admin/internal path segment: /{m.group(1)}"
    m2 = _EXPOSURE_PATH_RE.search(path)
    if m2:
        return 3, Cat.ADMIN, f"schema/monitoring exposure: /{m2.group(1)}"


def _check_graphql(req: CapturedRequest, path: str, params: dict):
    if "/graphql" in path.lower():
        return 6, Cat.GRAPHQL, "GraphQL endpoint"
    body = req.body or ""
    if _GQL_BODY_RE.search(body):
        return 5, Cat.GRAPHQL, "GraphQL operation in request body"


def _check_state_changing(req: CapturedRequest, path: str, params: dict):
    if req.method in ("DELETE", "PUT", "PATCH"):
        score = 5 if req.method == "DELETE" else 4
        return score, Cat.WRITE, f"{req.method} request"
    if req.method == "POST":
        return 2, Cat.WRITE, "POST request"


def _check_idor_path(req: CapturedRequest, path: str, params: dict):
    if _PATH_ID_RE.search(path):
        return 5, Cat.IDOR, "object ID in URL path (numeric or UUID)"


def _check_idor_fields(req: CapturedRequest, path: str, params: dict):
    haystack = _body_and_params(req.body, params)
    m = _IDOR_FIELD_RE.search(haystack)
    if m:
        return 4, Cat.IDOR, f"ownership field in request: {m.group(0)}"


def _check_priv_fields(req: CapturedRequest, path: str, params: dict):
    haystack = _body_and_params(req.body, params)
    m = _PRIV_FIELD_RE.search(haystack)
    if m:
        return 5, Cat.MASS_ASSIGN, f"privilege field in request: {m.group(0)}"


def _check_mass_assign_endpoint(req: CapturedRequest, path: str, params: dict):
    # PATCH/PUT on a user/account resource → flag as mass-assignment probe target
    # even when no privilege field is visible in the observed body (passive gap)
    if req.method in ("PATCH", "PUT") and _MASS_ASSIGN_PATH_RE.search(path):
        return 4, Cat.MASS_ASSIGN, f"write endpoint on user/account resource: {req.method} {path}"
    # POST on registration/creation paths — common mass-assignment sink
    if req.method == "POST" and _MASS_ASSIGN_CREATE_RE.search(path):
        return 3, Cat.MASS_ASSIGN, f"registration endpoint — test extra privilege fields: {path}"


def _check_ssrf_fields(req: CapturedRequest, path: str, params: dict):
    haystack = _body_and_params(req.body, params)
    m = _SSRF_FIELD_RE.search(haystack)
    if m:
        return 4, Cat.SSRF, f"URL-like field: {m.group(0)}"


def _check_ssrf_path(req: CapturedRequest, path: str, params: dict):
    m = _SSRF_PATH_RE.search(path)
    if m:
        return 4, Cat.SSRF, f"SSRF-prone path: /{m.group(1)}"


def _check_upload(req: CapturedRequest, path: str, params: dict):
    ct = req.headers.get("content-type", "")
    if "multipart/form-data" in ct:
        return 5, Cat.UPLOAD, "multipart/form-data upload"
    if _UPLOAD_PATH_RE.search(path):
        return 3, Cat.UPLOAD, "upload-related path segment"
    body = req.body or ""
    if "filename=" in body.lower():
        return 4, Cat.UPLOAD, "filename= in request body"


def _check_race(req: CapturedRequest, path: str, params: dict):
    m = _RACE_PATH_RE.search(path)
    if not (req.method in ("POST", "PUT") and m):
        return None
    # The path keyword alone produced too many false positives (every
    # POST /checkout was tagged as racy even when it had no race surface).
    # Require ALSO either: a numeric ID in the path (per-resource state) OR
    # a body field that looks transactional (amount/quantity/code/qty).
    has_id = bool(_PATH_ID_RE.search(path))
    body_looks_transactional = False
    if req.body:
        body_looks_transactional = bool(re.search(
            r'"(amount|quantity|qty|count|code|coupon|times|points|balance|stake)"',
            req.body, re.IGNORECASE,
        ))
    if has_id or body_looks_transactional:
        return 4, Cat.RACE, f"race-condition-prone path: /{m.group(1)}"
    return None


def _check_injection_params(req: CapturedRequest, path: str, params: dict):
    # Skip GraphQL request bodies — {"query":"..."} is not an injection surface via this check;
    # GraphQL injection is handled separately through active probing.
    if _GQL_BODY_RE.search(req.body or ""):
        return None
    haystack = _body_and_params(req.body, params)
    # Strong-signal injection field names (cmd, eval, template, login fields, etc.)
    m = _INJECT_FIELD_RE.search(haystack)
    if m:
        return 2, Cat.INJECTION, f"injection-prone parameter: {m.group(0)}"
    # Weaker signal — generic search params. Score=1 (lower priority) so they
    # surface in the recon list but don't dominate the injection findings.
    s = _SEARCH_PARAM_RE.search(haystack)
    if s:
        return 1, Cat.INJECTION, f"search-shaped parameter: {s.group(0)} (low-confidence injection signal)"
    return None


def _check_auth_headers(req: CapturedRequest, path: str, params: dict):
    auth = req.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1] if " " in auth else ""
        evidence = "Bearer token present"
        # Decode JWT header (no signature check) to flag alg confusion surface
        if token.count(".") == 2:
            try:
                hdr_b64 = token.split(".")[0]
                padding = (4 - len(hdr_b64) % 4) % 4
                hdr = json.loads(base64.urlsafe_b64decode(hdr_b64 + "=" * padding))
                alg = hdr.get("alg", "unknown")
                evidence = f"JWT Bearer token (alg={alg}) — test alg:none confusion and weak secret"
            except Exception:
                pass
        return 2, Cat.AUTH, evidence
    if req.headers.get("x-api-key"):
        return 2, Cat.AUTH, "X-API-Key header present"


def _check_csrf_surface(req: CapturedRequest, path: str, params: dict):
    # Only flag traditional form submissions — REST/JSON APIs are CSRF-safe via SameSite + CORS.
    if req.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    ct = req.headers.get("content-type", "")
    if not _FORM_CT_RE.search(ct):
        return None  # JSON, multipart-not-form, or no content-type → not a CSRF surface
    body = req.body or ""
    if not body:
        return None
    if not _CSRF_BODY_KEYS_RE.search(body) and not _CSRF_BODY_KEYS_RE.search(
        " ".join(params.keys())
    ):
        return 3, Cat.CSRF, f"form submission without csrf token: {req.method} {path}"


_CSRF_PROTECTION_HEADERS = frozenset({
    "x-csrf-token", "x-xsrf-token", "x-requested-with", "x-csrftoken",
    "csrf-token", "anti-forgery-token", "x-csrf", "requestverificationtoken",
})


def _check_csrf_xhr(req: CapturedRequest, path: str, params: dict):
    """Flag state-changing XHR/fetch requests that carry a JSON body but no
    custom CSRF-mitigation header. These endpoints rely entirely on CORS for
    CSRF protection — a wildcard ACAO or misconfigured trusted-origin header
    makes them immediately exploitable without any extra bypass."""
    if req.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if req.resource_type not in ("xhr", "fetch"):
        return None
    ct = req.headers.get("content-type", "").lower()
    # Only care about JSON — form-encoded is already caught by _check_csrf_surface
    if "application/json" not in ct:
        return None
    headers_lower = {k.lower(): v for k, v in req.headers.items()}
    if any(h in headers_lower for h in _CSRF_PROTECTION_HEADERS):
        return None
    body = req.body or ""
    if _CSRF_BODY_KEYS_RE.search(body):
        return None
    return 4, Cat.CSRF, (
        f"XHR {req.method} with JSON body and no CSRF protection header — "
        "relies on CORS policy alone; pair with ct_probe to check content-type confusion"
    )


def _check_auth_bypass_path(req: CapturedRequest, path: str, params: dict):
    m = _AUTH_BYPASS_PATH_RE.search(path)
    if m:
        return 4, Cat.AUTH, f"auth bypass surface: {path}"


def _check_cors(req: CapturedRequest, path: str, params: dict):
    if _CORS_API_PATH_RE.search(path) and req.method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        return 2, Cat.CORS, "API endpoint — probe CORS origin policy"


def _check_open_redirect(req: CapturedRequest, path: str, params: dict):
    for param in params:
        if _REDIRECT_PARAM_RE.match(param):
            return 3, Cat.REDIRECT, f"redirect-prone parameter: {param}"
    # Also catch redirect params in POST body
    if req.body:
        m = _REDIRECT_PARAM_RE.search(req.body)
        if m:
            return 2, Cat.REDIRECT, f"redirect param in request body: {m.group(0)}"


def _check_nosql(req: CapturedRequest, path: str, params: dict):
    # Param name suggests MongoDB field
    for param in params:
        if _NOSQL_PARAM_RE.search(param):
            return 3, Cat.NOSQL, f"NoSQL-prone parameter name: {param}"
    # Request body contains MongoDB operators
    if req.body and _NOSQL_BODY_RE.search(req.body):
        return 4, Cat.NOSQL, "MongoDB operator in request body"


def _check_proto_pollution(req: CapturedRequest, path: str, params: dict):
    haystack = " ".join(params.keys())
    if req.body:
        haystack += " " + req.body
    if _PROTO_POLL_RE.search(haystack):
        return 3, Cat.PROTO_POLL, "prototype pollution parameter detected"


def _check_bfla(req: CapturedRequest, path: str, params: dict):
    # Paths that suggest function-level endpoints (admin actions via API)
    if re.search(r"/(approve|reject|grant|revoke|promote|demote|ban|unban|lock|unlock"
                 r"|enable|disable|suspend|restore|reset|assign|unassign)",
                 path, re.IGNORECASE):
        # Self-service paths (/2fa/disable, /profile/reset, /account/lock) are
        # legitimate user-on-own-account actions, not BFLA. Lower the score
        # significantly so they appear as informational rather than dominating
        # the BFLA findings list.
        if _SELF_SERVICE_PATH_RE.search(path):
            return 2, Cat.BFLA, "function-level action on self-service path (likely legitimate user action)"
        return 5, Cat.BFLA, "function-level action endpoint"


# Ordered check list — applied to every request
_REQUEST_CHECKS = [
    _check_admin_path,
    _check_graphql,
    _check_state_changing,
    _check_idor_path,
    _check_idor_fields,
    _check_priv_fields,
    _check_mass_assign_endpoint,
    _check_ssrf_fields,
    _check_ssrf_path,
    _check_upload,
    _check_race,
    _check_injection_params,
    _check_auth_headers,
    _check_csrf_surface,
    _check_csrf_xhr,
    _check_auth_bypass_path,
    _check_bfla,
    _check_cors,
    _check_open_redirect,
    _check_nosql,
    _check_proto_pollution,
]


# ---------------------------------------------------------------------------
# WebSocket checks
# ---------------------------------------------------------------------------

def _classify_websocket(ws: CapturedWebSocket) -> WebSocketFinding:
    score = 4  # base: any WS connection is worth inspecting
    evidence = ["WebSocket connection observed"]
    keys: set[str] = set()

    all_frames = ws.messages_sent + ws.messages_received
    for frame in all_frames:
        raw = frame.get("raw", "") if isinstance(frame, dict) else str(frame)
        for m in _WS_KEY_RE.finditer(raw):
            keys.add(m.group(1))

    if any(k in keys for k in ("room_id", "channel_id", "channel")):
        score += 3
        evidence.append("room/channel ID in messages — test channel IDOR")
    if any(k in keys for k in ("user_id", "account_id")):
        score += 4
        evidence.append("user/account ID in messages — test authorization per message")
    if any(k in keys for k in ("auth", "token")):
        score += 2
        evidence.append("auth/token key in messages")
    if any(k in keys for k in ("subscribe", "join")):
        score += 3
        evidence.append("subscribe/join event — test unauthorized subscription")

    return WebSocketFinding(
        url=ws.url,
        score=score,
        evidence=evidence,
        keys_observed=sorted(keys),
    )


# ---------------------------------------------------------------------------
# JS route scoring
# ---------------------------------------------------------------------------

def _score_js_route(route: str) -> dict:
    score = 1
    if _JS_ROUTE_SCORE_RE.search(route):
        score += 3
    if _ADMIN_PATH_RE.search(route):
        score += 4
    if "/graphql" in route.lower():
        score += 4
    return {"route": route, "score": score}


# ---------------------------------------------------------------------------
# Main classify function
# ---------------------------------------------------------------------------

_STATIC_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                      ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                      ".map", ".webp", ".avif"}

_STATIC_RESOURCE_TYPES = {"script", "stylesheet", "image", "font", "media", "other"}


def classify(collector: Collector, origin: str = "") -> ClassifierResult:
    """
    Score all captured requests.

    Args:
        collector: populated Collector instance
        origin:    if set, skip requests that don't match this host
                   (filters cross-origin noise from browser crawls)
    """
    request_findings: list[Finding] = []
    origin_host = urlparse(origin).netloc if origin else ""

    for req in collector.requests:
        parsed = urlparse(req.url)
        path = parsed.path
        params = parse_qs(parsed.query)

        # Skip cross-origin requests when an origin filter is set
        if origin_host and parsed.netloc != origin_host:
            continue

        # Skip static assets — they can't contain exploitable logic
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext in _STATIC_EXTENSIONS:
            continue
        if req.resource_type in _STATIC_RESOURCE_TYPES and ext in _STATIC_EXTENSIONS:
            continue

        total_score = 0
        categories: list[str] = []
        evidence: list[str] = []

        for check in _REQUEST_CHECKS:
            result = check(req, path, params)
            if result is None:
                continue
            delta, cat, ev = result
            total_score += delta
            if cat not in categories:
                categories.append(cat)
            evidence.append(ev)

        if total_score > 0:
            request_findings.append(Finding(
                method=req.method,
                url=req.url,
                score=total_score,
                categories=categories,
                evidence=evidence,
                body=req.body,
                headers=req.headers,
                # Plumb cached response data from CapturedRequest so verifier
                # and idor_probe can skip refetch when bodies are present.
                response_status=req.response_status,
                response_headers=req.response_headers,
                response_body=req.response_body,
            ))

    request_findings.sort(key=lambda f: f.score, reverse=True)

    ws_findings = [_classify_websocket(ws) for ws in collector.websockets]
    ws_findings.sort(key=lambda f: f.score, reverse=True)

    js_route_findings = [_score_js_route(r) for r in collector.js_routes]
    js_route_findings.sort(key=lambda r: r["score"], reverse=True)

    # Group request findings by category
    by_cat: dict[str, list[Finding]] = {}
    for f in request_findings:
        for cat in f.categories:
            by_cat.setdefault(cat, []).append(f)

    # Cookie security analysis
    cookie_findings = [
        CookieFinding(
            name=c.name,
            source_url=c.source_url,
            issues=c.issues,
            is_jwt=c.is_jwt,
        )
        for c in collector.cookies_with_issues
    ]

    return ClassifierResult(
        request_findings=request_findings,
        websocket_findings=ws_findings,
        js_route_findings=js_route_findings,
        js_constants=collector.js_constants,
        by_category=by_cat,
        cookie_findings=cookie_findings,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _body_and_params(body: Optional[str], params: dict) -> str:
    parts = [body or ""]
    for key, vals in params.items():
        parts.append(key)
        parts.extend(vals)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from collector import Collector, CapturedRequest, CapturedWebSocket

    col = Collector("http://localhost")

    col.add_request(CapturedRequest(
        method="GET", url="http://localhost/api/invoices/1042",
        headers={"authorization": "Bearer abc"}, body=None, resource_type="xhr"
    ))
    col.add_request(CapturedRequest(
        method="PATCH", url="http://localhost/api/users/99",
        headers={}, body='{"role":"admin","is_admin":true}', resource_type="xhr"
    ))
    col.add_request(CapturedRequest(
        method="POST", url="http://localhost/api/webhook/test",
        headers={}, body='{"url":"http://internal/"}', resource_type="xhr"
    ))
    col.add_request(CapturedRequest(
        method="POST", url="http://localhost/api/upload",
        headers={"content-type": "multipart/form-data; boundary=x"}, body="filename=evil.svg",
        resource_type="xhr"
    ))

    ws = CapturedWebSocket(url="wss://localhost/cable")
    ws.messages_sent.append({"raw": '{"action":"subscribe","channel_id":"room_42","user_id":7}'})
    col.add_websocket(ws)

    col.add_js_discovered_route("/api/v2/admin/users")
    col.add_js_discovered_route("/graphql")
    col.add_js_discovered_route("/internal/metrics")

    result = classify(col)

    print("=== Top request findings ===")
    for f in result.request_findings[:10]:
        print(f"  [{f.score:>3}] {f.method} {f.url}")
        for ev in f.evidence:
            print(f"         - {ev}")

    print("\n=== WebSocket findings ===")
    for w in result.websocket_findings:
        print(f"  [{w.score:>3}] {w.url}  keys={w.keys_observed}")

    print("\n=== JS routes ===")
    for r in result.js_route_findings:
        print(f"  [{r['score']:>3}] {r['route']}")
