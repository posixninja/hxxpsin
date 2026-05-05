"""
js_deep_analyzer.py — Deep JavaScript bundle analysis for hxxpsin.

Downloads JS bundles → beautifies → extracts attack surface → generates test cases.

Detects:
  endpoints, GraphQL ops, WebSocket URLs, hardcoded secrets, auth provider configs,
  client-side authorization checks, DOM XSS source/sink patterns,
  localStorage/sessionStorage token usage, source maps, feature flags.

Pipeline position: after crawler (feeds collector's js_bundle_urls), before reporter.
"""

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

try:
    import jsbeautifier as _jsb
    _HAS_BEAUTIFIER = True
except ImportError:
    _HAS_BEAUTIFIER = False

_MAX_BUNDLE_BYTES = 2 * 1024 * 1024   # 2 MB per bundle
_BEAUTIFY_THRESHOLD = 500             # avg chars/line above this = minified
_BEAUTIFY_MAX_BYTES = 300_000         # only beautify bundles smaller than this

# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

_ENDPOINT_RE = re.compile(
    r'''(?:["'`])((?:/api/|/rest/|/v\d+/|/graphql|/admin|/internal|/webhook|/auth/|/oauth|/oidc)[^"'`\s<>{}\[\]\\^~|]{0,150})(?:["'`])''',
    re.IGNORECASE,
)

_FETCH_METHOD_RE = re.compile(
    r'''(?:fetch|axios|http|request|api)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`\s]{3,120})["'`]''',
    re.IGNORECASE,
)

_GQL_OP_RE = re.compile(
    r'''(?:^|[\s=(,])(?:gql\s*`\s*)?(query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]{1,60})\s*[\({]''',
    re.IGNORECASE | re.MULTILINE,
)

_GQL_VAR_RE = re.compile(r'\$([A-Za-z][A-Za-z0-9_]{0,40})\s*:', re.IGNORECASE)

_WS_URL_RE = re.compile(r'''["'`](wss?://[^"'`\s]{4,200})["'`]''')

_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=(\S+\.map\S*)', re.MULTILINE)

_SUSPICIOUS_COMMENT_RE = re.compile(
    r'//[^\n]*(TODO|FIXME|HACK|SECURITY|VULN|AUTH|PASSWORD|SECRET|KEY|TOKEN|BYPASS|DANGER)[^\n]*',
    re.IGNORECASE,
)

_STORAGE_RE = re.compile(
    r'(localStorage|sessionStorage)\s*\.\s*(getItem|setItem)\s*\(\s*["\'`]([^"\'`]{1,80})["\'`]',
    re.IGNORECASE,
)

_AUTH_SMELL_RE = re.compile(
    r'''(?:if|&&|\|\|)\s*\(?\s*\w+\.?\s*(?:role|isAdmin|is_admin|admin|permissions?|scope|groups?|access_level|tier|plan)\s*'''
    r'''(?:===|==|!==|\.includes?\s*\(|\.has\s*\()\s*["'`]([A-Za-z_]\w{0,30})["'`]''',
    re.IGNORECASE,
)

_FEATURE_FLAG_RE = re.compile(
    r'''(?:featureFlag|feature_flag|FEATURE_|isEnabled|enabledFeature)\s*[=:,\[("'`]+\s*["'`]?([A-Za-z][A-Za-z0-9_]{2,40})["'`]?''',
    re.IGNORECASE,
)

_DEBUG_RE = re.compile(
    r'''(?:DEBUG|isDev|isDebug|devMode|dev_mode|__DEV__)\s*[=:]\s*(true|1)(?!\d)''',
    re.IGNORECASE,
)

# Auth provider configs
_FIREBASE_RE = re.compile(
    r'''(?:apiKey|authDomain|projectId|storageBucket|appId)\s*:\s*["'`]([^"'`]{6,120})["'`]''',
    re.IGNORECASE,
)
_AUTH0_RE = re.compile(r'''["'`]([a-zA-Z0-9\-]+\.auth0\.com)["'`]''', re.IGNORECASE)
_COGNITO_RE = re.compile(
    r'''(?:UserPoolId|cognitoUserPoolId)\s*[:=]\s*["'`]([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{5,})["'`]''',
    re.IGNORECASE,
)
_CLERK_RE = re.compile(r'pk_(?:test|live)_[A-Za-z0-9]{20,}')

# Secrets — (pattern, severity, public_by_design)
_SECRET_PATTERNS: list[tuple] = [
    ("aws_access_key",  re.compile(r'AKIA[0-9A-Z]{16}'),                    "critical", False),
    ("github_token",    re.compile(r'ghp_[A-Za-z0-9_]{36,}'),               "critical", False),
    ("gitlab_token",    re.compile(r'glpat-[A-Za-z0-9\-_]{20}'),            "critical", False),
    ("stripe_live",     re.compile(r'sk_live_[A-Za-z0-9]{20,}'),            "critical", False),
    ("private_key",     re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY'), "critical", False),
    ("slack_token",     re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),      "high",     False),
    ("sendgrid",        re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'), "high", False),
    ("jwt_secret",      re.compile(r'''(?:secret|signing_key|jwt_secret)\s*[:=]\s*["'`]([A-Za-z0-9+/=_\-]{20,})["'`]''', re.IGNORECASE), "high", False),
    ("stripe_test",     re.compile(r'sk_test_[A-Za-z0-9]{20,}'),            "low",      True),
    ("google_maps",     re.compile(r'AIza[0-9A-Za-z\-_]{35}'),              "medium",   True),
]

# DOM XSS sinks
_SINKS = [
    ("innerHTML",              r'\.innerHTML\s*[+]?='),
    ("outerHTML",              r'\.outerHTML\s*[+]?='),
    ("insertAdjacentHTML",     r'insertAdjacentHTML\s*\('),
    ("document.write",         r'document\.write[ln]*\s*\('),
    ("dangerouslySetInnerHTML",r'dangerouslySetInnerHTML'),
    ("eval",                   r'\beval\s*\('),
    ("new Function",           r'\bnew\s+Function\s*\('),
    ("location.href=",         r'location\.href\s*='),
    ("setTimeout-str",         r'setTimeout\s*\(\s*["\']'),
]

_SOURCES_LIST = [
    ("location.search",   r'location\.search'),
    ("location.hash",     r'location\.hash'),
    ("document.referrer", r'document\.referrer'),
    ("window.name",       r'window\.name'),
    ("postMessage.data",  r'event\.data'),
    ("localStorage",      r'localStorage\.getItem'),
    ("sessionStorage",    r'sessionStorage\.getItem'),
    ("URLSearchParams",   r'URLSearchParams'),
]


# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class JSEndpoint:
    path: str
    method_hint: str     # GET, POST, unknown
    risks: list[str]
    reasons: list[str]
    source_file: str

    def to_dict(self) -> dict:
        return {"path": self.path, "method_hint": self.method_hint,
                "risks": self.risks, "reasons": self.reasons, "source_file": self.source_file}


@dataclass
class JSGraphQLOp:
    op_type: str         # query | mutation | subscription
    name: str
    variables: list[str]
    risk: str
    source_file: str

    def to_dict(self) -> dict:
        return {"op_type": self.op_type, "name": self.name, "variables": self.variables,
                "risk": self.risk, "source_file": self.source_file}


@dataclass
class JSSecret:
    kind: str
    value: str           # truncated after first 8 chars
    severity: str
    public_by_design: bool
    source_file: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "severity": self.severity,
                "public_by_design": self.public_by_design, "source_file": self.source_file}


@dataclass
class JSDomXss:
    source: str
    sink: str
    source_file: str
    priority: str = "medium"

    def to_dict(self) -> dict:
        return {"source": self.source, "sink": self.sink,
                "priority": self.priority, "source_file": self.source_file}


@dataclass
class JSAuthSmell:
    matched_code: str
    role_value: str
    source_file: str

    def to_dict(self) -> dict:
        return {"matched_code": self.matched_code[:120],
                "role_value": self.role_value, "source_file": self.source_file}


@dataclass
class JSStorageUsage:
    storage_type: str
    key: str
    operation: str
    source_file: str

    def to_dict(self) -> dict:
        return {"storage_type": self.storage_type, "key": self.key,
                "operation": self.operation, "source_file": self.source_file}


@dataclass
class JSSourceMap:
    map_url: str
    sources: list[str]
    suspicious_comments: list[str]
    has_content: bool

    def to_dict(self) -> dict:
        return {"map_url": self.map_url, "sources": self.sources[:20],
                "suspicious_comments": self.suspicious_comments[:10],
                "has_content": self.has_content}


@dataclass
class JSConfig:
    kind: str            # firebase | auth0 | cognito | clerk
    values: list[str]
    source_file: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "values": self.values, "source_file": self.source_file}


@dataclass
class JSAnalysisResult:
    endpoints: list[JSEndpoint] = field(default_factory=list)
    graphql_ops: list[JSGraphQLOp] = field(default_factory=list)
    secrets: list[JSSecret] = field(default_factory=list)
    dom_xss: list[JSDomXss] = field(default_factory=list)
    auth_smells: list[JSAuthSmell] = field(default_factory=list)
    storage_usage: list[JSStorageUsage] = field(default_factory=list)
    source_maps: list[JSSourceMap] = field(default_factory=list)
    configs: list[JSConfig] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    feature_flags: list[str] = field(default_factory=list)
    debug_flags: list[str] = field(default_factory=list)
    files_analyzed: int = 0

    def to_dict(self) -> dict:
        return {
            "files_analyzed": self.files_analyzed,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graphql_ops": [g.to_dict() for g in self.graphql_ops],
            "secrets": [s.to_dict() for s in self.secrets],
            "dom_xss": [d.to_dict() for d in self.dom_xss],
            "auth_smells": [a.to_dict() for a in self.auth_smells],
            "storage_usage": [s.to_dict() for s in self.storage_usage],
            "source_maps": [s.to_dict() for s in self.source_maps],
            "configs": [c.to_dict() for c in self.configs],
            "websocket_urls": self.websocket_urls,
            "feature_flags": self.feature_flags[:30],
            "debug_flags": self.debug_flags,
            "test_cases": generate_test_cases(self),
        }

    def summary(self) -> str:
        lines = [
            f"Files analyzed:    {self.files_analyzed}",
            f"Endpoints:         {len(self.endpoints)}",
            f"GraphQL ops:       {len(self.graphql_ops)}",
            f"Secrets:           {len(self.secrets)} ({sum(1 for s in self.secrets if s.severity == 'critical')} critical)",
            f"DOM XSS signals:   {len(self.dom_xss)}",
            f"Auth smells:       {len(self.auth_smells)}",
            f"Storage usage:     {len(self.storage_usage)}",
            f"Source maps:       {len(self.source_maps)}",
            f"WebSocket URLs:    {len(self.websocket_urls)}",
            f"Debug flags:       {len(self.debug_flags)}",
        ]

        if self.secrets:
            lines += ["", "Secrets:"]
            for s in self.secrets:
                flag = " (PUBLIC BY DESIGN)" if s.public_by_design else ""
                lines.append(f"  [{s.severity.upper()}] {s.kind}: {s.value}{flag}")

        if self.source_maps:
            lines += ["", "Source maps:"]
            for sm in self.source_maps:
                lines.append(f"  {sm.map_url} ({len(sm.sources)} sources, {len(sm.suspicious_comments)} suspicious comments)")

        if self.auth_smells:
            lines += ["", "Auth smells (client-side checks — test server enforcement):"]
            for a in self.auth_smells:
                lines.append(f"  role={a.role_value}  in {a.source_file}")

        if self.dom_xss:
            lines += ["", "DOM XSS signals:"]
            for d in self.dom_xss:
                lines.append(f"  [{d.priority}] {d.source} → {d.sink}  ({d.source_file})")

        tc = generate_test_cases(self)
        if tc:
            lines += ["", f"Test cases generated: {len(tc)}"]
            for t in tc[:8]:
                lines.append(f"  [{t['priority'].upper()}] {t['title']}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class JSDeepAnalyzer:
    def __init__(
        self,
        urls: list[str],
        timeout: float = 10.0,
        max_bundle_bytes: int = _MAX_BUNDLE_BYTES,
    ):
        self.urls = list(dict.fromkeys(u for u in urls if u.endswith(".js") or ".js?" in u or "/chunks/" in u or "_next" in u))
        self.timeout = timeout
        self.max_bundle_bytes = max_bundle_bytes

    @classmethod
    def from_collector(cls, collector, base_url: str) -> "JSDeepAnalyzer":
        """Build from a Collector — uses bundle URLs discovered during crawl."""
        urls = list(collector._js_bundle_urls)
        # Also add any JS routes discovered in bundles
        for route in collector.js_routes:
            if route.endswith(".js"):
                urls.append(urljoin(base_url, route))
        return cls(urls)

    async def run(self) -> JSAnalysisResult:
        result = JSAnalysisResult()

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=True
        ) as client:
            tasks = [self._analyze_bundle(url, client, result) for url in self.urls]
            await asyncio.gather(*tasks, return_exceptions=True)

        _deduplicate(result)
        return result

    # ------------------------------------------------------------------
    # Bundle download + dispatch
    # ------------------------------------------------------------------

    async def _analyze_bundle(self, url: str, client: httpx.AsyncClient, result: JSAnalysisResult) -> None:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return
            raw = resp.content
            if len(raw) > self.max_bundle_bytes:
                raw = raw[:self.max_bundle_bytes]
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return

        fname = urlparse(url).path.split("/")[-1] or url

        # Beautify if minified and small enough
        content = _maybe_beautify(content, fname)
        result.files_analyzed += 1

        # Run all extractors
        result.endpoints.extend(_extract_endpoints(content, fname))
        result.graphql_ops.extend(_extract_graphql(content, fname))
        result.secrets.extend(_extract_secrets(content, fname))
        result.dom_xss.extend(_detect_dom_xss(content, fname))
        result.auth_smells.extend(_detect_auth_smells(content, fname))
        result.storage_usage.extend(_detect_storage(content, fname))
        result.websocket_urls.extend(_extract_websockets(content))
        result.feature_flags.extend(_extract_feature_flags(content))
        result.debug_flags.extend(_extract_debug_flags(content, fname))
        result.configs.extend(_extract_configs(content, fname))

        # Source map (async — needs http client). Also yields routes/endpoints
        # extracted from the unminified source files (sourcesContent[]) and
        # from the sources[] path hints (e.g. webpack:///./src/pages/admin.tsx).
        maps, sm_endpoints = await _fetch_sourcemaps(content, url, client)
        result.source_maps.extend(maps)
        result.endpoints.extend(sm_endpoints)
        # Analyze sourcemap content too
        for sm in maps:
            if sm.has_content:
                result.suspicious_comments = getattr(result, "suspicious_comments", [])


# ---------------------------------------------------------------------------
# Extractors (pure functions — easy to test in isolation)
# ---------------------------------------------------------------------------

def _maybe_beautify(content: str, fname: str) -> str:
    if not _HAS_BEAUTIFIER:
        return content
    lines = content.split("\n")
    if not lines:
        return content
    avg_len = len(content) / max(len(lines), 1)
    if avg_len < _BEAUTIFY_THRESHOLD:
        return content  # not minified
    if len(content) > _BEAUTIFY_MAX_BYTES:
        return content  # too large to beautify quickly
    try:
        opts = _jsb.BeautifierOptions()
        opts.indent_size = 2
        opts.max_preserve_newlines = 1
        return _jsb.beautify(content, opts)
    except Exception:
        return content


def _extract_endpoints(content: str, fname: str) -> list[JSEndpoint]:
    found: list[JSEndpoint] = []
    seen: set[str] = set()

    # Method-hinted: fetch.get("/api/users") or fetch.get(`${host}/rest/basket/${id}`)
    for m in _FETCH_METHOD_RE.finditer(content):
        method, raw_path = m.group(1).upper(), m.group(2)
        path = _normalize_path(raw_path)
        if not _is_valid_path(path):
            continue
        key = f"{method}:{path}"
        if key in seen:
            continue
        seen.add(key)
        risks, reasons = _score_endpoint(path)
        found.append(JSEndpoint(path=path, method_hint=method, risks=risks, reasons=reasons, source_file=fname))

    # Plain string matches
    for m in _ENDPOINT_RE.finditer(content):
        raw_path = m.group(1)
        path = _normalize_path(raw_path)
        if not _is_valid_path(path) or path in seen:
            continue
        seen.add(path)
        risks, reasons = _score_endpoint(path)
        found.append(JSEndpoint(path=path, method_hint="unknown", risks=risks, reasons=reasons, source_file=fname))

    return found


_TEMPLATE_HOST_RE = re.compile(r'^\$\{[^}]+\}')
_TEMPLATE_VAR_RE  = re.compile(r'/\$\{[^}]+\}')
_TEMPLATE_ANY_RE  = re.compile(r'\$\{[^}]+\}')


def _normalize_path(path: str) -> str:
    """Strip template-literal host prefix and replace param expressions with {id}."""
    # Remove leading ${this.host}/ or ${this.hostServer}/ etc.
    path = _TEMPLATE_HOST_RE.sub("", path)
    # Replace /${varname} template slots with /{id}
    path = _TEMPLATE_VAR_RE.sub("/{id}", path)
    # Remove any remaining bare template expressions
    path = _TEMPLATE_ANY_RE.sub("{id}", path)
    return path.strip()


def _is_valid_path(path: str) -> bool:
    if len(path) < 4 or len(path) > 150:
        return False
    # Must look like a URL path
    if not path.startswith("/"):
        return False
    # A path that's just /{id} with no route structure isn't useful
    if re.fullmatch(r'/\{id\}', path):
        return False
    # Skip asset files
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in ("js", "css", "png", "jpg", "svg", "ico", "woff", "map", "ts", "tsx"):
        return False
    return True


def _score_endpoint(path: str) -> tuple[list[str], list[str]]:
    risks: list[str] = []
    reasons: list[str] = []
    pl = path.lower()

    if any(x in pl for x in ("/admin", "/internal", "/debug", "/actuator")):
        risks.append("admin_exposure")
        reasons.append("admin/internal path — test without auth")

    if re.search(r'/:?\w*id\b|/\{[^}]+\}', pl):
        risks.append("idor_candidate")
        reasons.append("ID parameter in path — test with other users' IDs")

    if "/role" in pl or "/permission" in pl or "/grant" in pl or "/promote" in pl:
        risks.append("bfla_candidate")
        reasons.append("privilege-related path — test function-level auth")

    if "/webhook" in pl or "/callback" in pl or "/redirect" in pl:
        risks.append("ssrf_candidate")
        reasons.append("URL-accepting path — test SSRF")

    if "/upload" in pl or "/file" in pl or "/attachment" in pl:
        risks.append("upload_candidate")
        reasons.append("file-handling path — test upload bypass")

    return risks, reasons


def _extract_graphql(content: str, fname: str) -> list[JSGraphQLOp]:
    found: list[JSGraphQLOp] = []
    seen: set[str] = set()

    for m in _GQL_OP_RE.finditer(content):
        op_type, name = m.group(1).lower(), m.group(2)
        key = f"{op_type}:{name}"
        if key in seen:
            continue
        seen.add(key)

        # Find variables in surrounding context (~400 chars after match)
        ctx = content[m.start():m.start() + 400]
        variables = list(dict.fromkeys(v.group(1) for v in _GQL_VAR_RE.finditer(ctx)))

        risk = "low"
        risk_vars = {"role", "admin", "userid", "accountid", "ownerid", "permission", "scope", "tenant"}
        if op_type == "mutation":
            risk = "authorization_candidate"
        if any(v.lower() in risk_vars for v in variables):
            risk = "high_priority_auth_candidate"

        found.append(JSGraphQLOp(
            op_type=op_type, name=name, variables=variables[:10],
            risk=risk, source_file=fname,
        ))

    return found


def _extract_secrets(content: str, fname: str) -> list[JSSecret]:
    found: list[JSSecret] = []
    seen: set[str] = set()

    for kind, pattern, severity, public_by_design, *_ in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            raw = m.group(0)
            # Use first group if available (for context-based patterns)
            try:
                raw = m.group(1)
            except IndexError:
                pass
            truncated = raw[:8] + "…" if len(raw) > 8 else raw
            key = f"{kind}:{truncated}"
            if key in seen:
                continue
            seen.add(key)
            found.append(JSSecret(
                kind=kind, value=truncated, severity=severity,
                public_by_design=public_by_design, source_file=fname,
            ))

    return found


def _detect_dom_xss(content: str, fname: str) -> list[JSDomXss]:
    found: list[JSDomXss] = []

    present_sources = [name for name, pat in _SOURCES_LIST if re.search(pat, content)]
    if not present_sources:
        return found

    for sink_name, sink_pat in _SINKS:
        for sm in re.finditer(sink_pat, content):
            # Check if any source is within ±800 chars of this sink
            start = max(0, sm.start() - 800)
            end = min(len(content), sm.end() + 800)
            window = content[start:end]

            for src_name, src_pat in _SOURCES_LIST:
                if re.search(src_pat, window):
                    priority = "high" if sink_name in ("eval", "new Function", "innerHTML", "document.write") else "medium"
                    found.append(JSDomXss(source=src_name, sink=sink_name, source_file=fname, priority=priority))
                    break  # one source per sink occurrence is enough

    return found


def _detect_auth_smells(content: str, fname: str) -> list[JSAuthSmell]:
    found: list[JSAuthSmell] = []
    seen: set[str] = set()

    for m in _AUTH_SMELL_RE.finditer(content):
        role_val = m.group(1)
        key = role_val.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(JSAuthSmell(
            matched_code=m.group(0), role_value=role_val, source_file=fname,
        ))

    return found


def _detect_storage(content: str, fname: str) -> list[JSStorageUsage]:
    found: list[JSStorageUsage] = []
    seen: set[str] = set()

    for m in _STORAGE_RE.finditer(content):
        storage, op, key = m.group(1), m.group(2), m.group(3)
        k = f"{storage}:{key}"
        if k in seen:
            continue
        seen.add(k)
        found.append(JSStorageUsage(storage_type=storage, key=key, operation=op, source_file=fname))

    return found


def _extract_websockets(content: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _WS_URL_RE.finditer(content)))


def _extract_feature_flags(content: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _FEATURE_FLAG_RE.finditer(content)))[:20]


def _extract_debug_flags(content: str, fname: str) -> list[str]:
    matches = []
    for m in _DEBUG_RE.finditer(content):
        matches.append(f"{m.group(0).strip()} in {fname}")
    return matches


def _extract_configs(content: str, fname: str) -> list[JSConfig]:
    found: list[JSConfig] = []

    firebase_vals = list(dict.fromkeys(m.group(1) for m in _FIREBASE_RE.finditer(content)))
    if len(firebase_vals) >= 2:  # need at least 2 fields to be confident
        found.append(JSConfig(kind="firebase", values=firebase_vals[:6], source_file=fname))

    auth0_vals = list(dict.fromkeys(m.group(1) for m in _AUTH0_RE.finditer(content) if m.group(1)))
    if auth0_vals:
        found.append(JSConfig(kind="auth0", values=auth0_vals, source_file=fname))

    cognito_vals = list(dict.fromkeys(m.group(1) for m in _COGNITO_RE.finditer(content)))
    if cognito_vals:
        found.append(JSConfig(kind="cognito", values=cognito_vals, source_file=fname))

    clerk_vals = list(dict.fromkeys(m.group(0) for m in _CLERK_RE.finditer(content)))
    if clerk_vals:
        found.append(JSConfig(kind="clerk", values=[v[:12] + "…" for v in clerk_vals], source_file=fname))

    return found


async def _fetch_sourcemaps(content: str, bundle_url: str, client: httpx.AsyncClient) -> tuple[list[JSSourceMap], list[JSEndpoint]]:
    """Fetch + parse sourcemaps. Returns (source_maps, endpoints) — endpoints
    are extracted from the sources/sourcesContent arrays to seed the crawler."""
    found_maps: list[JSSourceMap] = []
    found_endpoints: list[JSEndpoint] = []

    for m in _SOURCEMAP_RE.finditer(content):
        map_ref = m.group(1).strip()
        map_url = map_ref if map_ref.startswith("http") else urljoin(bundle_url, map_ref)

        try:
            resp = await client.get(map_url, timeout=6.0)
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue

        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        has_content = bool(sources_content)

        # Extract suspicious comments from source content
        suspicious: list[str] = []
        for src_text in sources_content[:20]:
            if not src_text:
                continue
            for cm in _SUSPICIOUS_COMMENT_RE.finditer(src_text):
                suspicious.append(cm.group(0).strip()[:120])

        found_maps.append(JSSourceMap(
            map_url=map_url, sources=sources[:30],
            suspicious_comments=list(dict.fromkeys(suspicious))[:15],
            has_content=has_content,
        ))

        # Extract routes / endpoints from the unminified source content
        # using the SPA route patterns. Far more reliable than regex on the
        # minified bundle.
        try:
            from spa_router import extract_routes_from_text
        except ImportError:
            continue

        seen_paths: set[str] = set()

        # 1. sources[] paths often reveal page routes:
        #    "webpack:///./src/pages/admin/users.tsx" → "/admin/users"
        for src_path in sources:
            if not isinstance(src_path, str):
                continue
            # Pull the meaningful tail after src/pages/ or src/routes/ or app/
            for marker in ("/pages/", "/routes/", "/app/", "/views/"):
                idx = src_path.find(marker)
                if idx == -1:
                    continue
                tail = src_path[idx + len(marker):]
                # Strip extension
                tail = re.sub(r"\.(tsx?|jsx?|vue|svelte)$", "", tail)
                # /index, index → /
                if tail in ("index",) or tail.endswith("/index"):
                    tail = re.sub(r"/?index$", "", tail) or "/"
                if not tail.startswith("/"):
                    tail = "/" + tail
                # Skip private files (_app, _document) and dynamic segments are fine
                if "/_" in tail or tail.lstrip("/").startswith("_"):
                    break
                if tail in seen_paths or len(tail) > 200:
                    break
                seen_paths.add(tail)
                found_endpoints.append(JSEndpoint(
                    path=tail, method_hint="GET",
                    risks=[], reasons=["from sourcemap sources[]"],
                    source_file=map_url.rsplit("/", 1)[-1],
                ))
                break

        # 2. Walk sourcesContent[] with the SPA route regex
        for src_text in sources_content[:20]:
            if not isinstance(src_text, str) or len(src_text) < 50:
                continue
            for route in extract_routes_from_text(src_text):
                if route in seen_paths:
                    continue
                seen_paths.add(route)
                found_endpoints.append(JSEndpoint(
                    path=route, method_hint="unknown",
                    risks=[], reasons=["from sourcemap sourcesContent"],
                    source_file=map_url.rsplit("/", 1)[-1],
                ))

    return found_maps, found_endpoints


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(result: JSAnalysisResult) -> None:
    seen_ep: set[str] = set()
    eps = []
    for e in result.endpoints:
        k = e.path.lower().rstrip("/")
        if k not in seen_ep:
            seen_ep.add(k)
            eps.append(e)
    result.endpoints = sorted(eps, key=lambda e: len(e.risks), reverse=True)

    seen_gql: set[str] = set()
    gqls = []
    for g in result.graphql_ops:
        k = f"{g.op_type}:{g.name}"
        if k not in seen_gql:
            seen_gql.add(k)
            gqls.append(g)
    result.graphql_ops = sorted(gqls, key=lambda g: g.risk == "high_priority_auth_candidate", reverse=True)

    result.websocket_urls = list(dict.fromkeys(result.websocket_urls))
    result.feature_flags = list(dict.fromkeys(result.feature_flags))
    result.debug_flags = list(dict.fromkeys(result.debug_flags))


# ---------------------------------------------------------------------------
# Test case generator
# ---------------------------------------------------------------------------

def generate_test_cases(result: JSAnalysisResult) -> list[dict]:
    cases: list[dict] = []

    for ep in result.endpoints:
        if "admin_exposure" in ep.risks:
            cases.append({
                "priority": "high", "title": f"Admin route: {ep.method_hint} {ep.path}",
                "steps": [
                    f"{ep.method_hint} {ep.path} with no Authorization header",
                    f"{ep.method_hint} {ep.path} with regular-user JWT",
                    f"Test IDOR: increment any numeric ID in path",
                ],
            })
        if "idor_candidate" in ep.risks:
            cases.append({
                "priority": "high", "title": f"IDOR candidate: {ep.path}",
                "steps": [
                    f"Request {ep.path} — replace ID with another user's object ID",
                    f"Log in as user A, note IDs; log in as user B, request user A's IDs",
                ],
            })
        if "ssrf_candidate" in ep.risks:
            cases.append({
                "priority": "medium", "title": f"SSRF surface: {ep.path}",
                "steps": [
                    f"POST to {ep.path} with url=http://127.0.0.1/",
                    f"POST to {ep.path} with url=http://169.254.169.254/latest/meta-data/",
                ],
            })

    for gql in result.graphql_ops:
        if gql.risk in ("authorization_candidate", "high_priority_auth_candidate"):
            cases.append({
                "priority": "high", "title": f"GraphQL {gql.op_type}: {gql.name}",
                "steps": [
                    f"Send {gql.name} without Authorization header",
                    f"Send {gql.name} as low-privilege user",
                    *([f"Try variable {v}=admin or {v}=1" for v in gql.variables if v.lower() in ("role", "userid", "accountid", "ownerid")]),
                ],
            })

    for smell in result.auth_smells:
        cases.append({
            "priority": "high", "title": f"Client-side auth: role={smell.role_value}",
            "steps": [
                f"Call the protected endpoint directly without role={smell.role_value} on frontend",
                f"Send role={smell.role_value} (or is_admin=true) in the API request body",
                f"Check if server re-validates or trusts frontend role state",
            ],
        })

    for dom in result.dom_xss:
        if dom.priority == "high":
            cases.append({
                "priority": "high", "title": f"DOM XSS: {dom.source} → {dom.sink}",
                "steps": [
                    f"Inject <img src=x onerror=alert(1)> via {dom.source}",
                    f"Test: ?param=<svg/onload=alert(1)> and check if {dom.sink} reflects it",
                    "Try hash-based injection if source is location.hash",
                ],
            })

    for secret in result.secrets:
        if not secret.public_by_design:
            cases.append({
                "priority": secret.severity, "title": f"Secret: {secret.kind} ({secret.value})",
                "steps": [
                    f"Verify this {secret.kind} is active",
                    "Rotate/revoke immediately if confirmed",
                    "Check git history for broader exposure",
                ],
            })

    for sm in result.source_maps:
        cases.append({
            "priority": "medium", "title": f"Source map exposed: {sm.map_url}",
            "steps": [
                f"Download {sm.map_url} — reconstruct full source",
                f"Grep sources for API routes, secrets, TODO/auth comments",
                *([f"Comment: {c[:80]}" for c in sm.suspicious_comments[:3]]),
            ],
        })

    for storage in result.storage_usage:
        if any(kw in storage.key.lower() for kw in ("token", "auth", "jwt", "session", "key")):
            cases.append({
                "priority": "medium", "title": f"Token in {storage.storage_type}: {storage.key}",
                "steps": [
                    f"Check {storage.storage_type}.getItem('{storage.key}') in DevTools console",
                    "Verify token is invalidated on logout",
                    "Check if token can be stolen via XSS (no HttpOnly protection)",
                ],
            })

    # Sort by priority
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cases.sort(key=lambda c: sev.get(c["priority"], 4))
    return cases


# ---------------------------------------------------------------------------
# Helper: build URL list from StackProfile interesting paths
# ---------------------------------------------------------------------------

def js_urls_from_profile(profile, base_url: str) -> list[str]:
    """Probe common JS bundle locations based on detected stack."""
    urls = []
    detected_keys = getattr(profile, "detected_keys", set())

    if "nextjs" in detected_keys:
        urls += [
            urljoin(base_url, "/_next/static/chunks/main.js"),
            urljoin(base_url, "/_next/static/chunks/pages/_app.js"),
            urljoin(base_url, "/_next/static/chunks/webpack.js"),
        ]
    if "nuxt" in detected_keys:
        urls += [urljoin(base_url, "/_nuxt/app.js")]
    if "sveltekit" in detected_keys:
        urls += [urljoin(base_url, "/_app/immutable/start.js")]

    # Always probe generic locations
    urls += [
        urljoin(base_url, "/static/js/main.chunk.js"),
        urljoin(base_url, "/assets/js/app.js"),
        urljoin(base_url, "/js/app.js"),
        urljoin(base_url, "/bundle.js"),
    ]
    return urls


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _main() -> None:
    import argparse, warnings
    warnings.filterwarnings("ignore")

    parser = argparse.ArgumentParser(description="hxxpsin js_deep_analyzer")
    parser.add_argument("urls", nargs="+", help="JS bundle URLs to analyze")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="-")
    args = parser.parse_args()

    analyzer = JSDeepAnalyzer(args.urls)
    result = await analyzer.run()

    output = json.dumps(result.to_dict(), indent=2) if args.json else result.summary()

    if args.out == "-":
        print(output)
    else:
        import pathlib
        pathlib.Path(args.out).write_text(output)
        print(f"[+] Wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(_main())
