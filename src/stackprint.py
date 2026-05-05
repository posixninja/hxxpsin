"""
stackprint — Stack fingerprinting module for hxxpsin.

Target URL → probe headers/cookies/HTML/JS → infer stack → emit StackProfile.

Runs in ~5-10 seconds using plain async HTTP (no browser).
Feed StackProfile.seed_paths into the Playwright crawler's BFS queue.
Feed StackProfile.recommended_tests into your Burp checklist.
"""

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import NamedTuple, Optional
from urllib.parse import urljoin, urlparse

import httpx

# ---------------------------------------------------------------------------
# Signal definition
# ---------------------------------------------------------------------------

class Signal(NamedTuple):
    kind: str           # header_exists | header_match | cookie_exists | html_match | js_match
    target: str         # header name, cookie substring, or unused placeholder for html/js
    pattern: Optional[str]  # regex; None means just check existence
    weight: int         # 1–3; tech detected when cumulative weight >= threshold


# ---------------------------------------------------------------------------
# Technology definitions
# ---------------------------------------------------------------------------

_TECHS: dict[str, dict] = {

    # CDN / Edge
    "cloudflare": {
        "category": "cdn", "display": "Cloudflare", "threshold": 2,
        "signals": [
            Signal("header_exists", "cf-ray",              None,            3),
            Signal("header_match",  "server",              r"cloudflare",   2),
            Signal("cookie_exists", "__cf",                None,            2),
        ],
    },
    "vercel": {
        "category": "cdn", "display": "Vercel", "threshold": 2,
        "signals": [
            Signal("header_exists", "x-vercel-id",         None,            3),
            Signal("header_exists", "x-vercel-cache",      None,            2),
            Signal("header_match",  "server",              r"vercel",       2),
        ],
    },
    "cloudfront": {
        "category": "cdn", "display": "AWS CloudFront", "threshold": 2,
        "signals": [
            Signal("header_exists", "x-amz-cf-id",         None,            3),
            Signal("header_match",  "via",                 r"CloudFront",   2),
        ],
    },
    "fastly": {
        "category": "cdn", "display": "Fastly", "threshold": 2,
        "signals": [
            Signal("header_exists", "fastly-restarts",     None,            3),
            Signal("header_match",  "via",                 r"varnish",      2),
            Signal("header_match",  "x-served-by",         r"cache-",       2),
        ],
    },
    "akamai": {
        "category": "cdn", "display": "Akamai", "threshold": 2,
        "signals": [
            Signal("header_exists", "x-check-cacheable",   None,            3),
            Signal("header_exists", "x-akamai-transformed",None,            3),
            Signal("header_match",  "server",              r"AkamaiGHost",  3),
        ],
    },
    "netlify": {
        "category": "cdn", "display": "Netlify", "threshold": 2,
        "signals": [
            Signal("header_exists", "x-nf-request-id",     None,            3),
            Signal("header_match",  "server",              r"Netlify",      2),
        ],
    },

    # Frontend
    "nextjs": {
        "category": "frontend", "display": "Next.js", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"__NEXT_DATA__",          3),
            Signal("html_match",    "",  r'/_next/static/',         3),
            Signal("html_match",    "",  r'/_next/image',           2),
            Signal("header_exists", "x-nextjs-cache",      None,    3),
            Signal("header_match",  "x-powered-by",        r"Next", 3),
        ],
    },
    "react": {
        "category": "frontend", "display": "React", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"__reactFiber|__reactProps|data-reactroot", 3),
            Signal("html_match",    "",  r"react\.production\.min\.js",               2),
            Signal("js_match",      "",  r"React\.createElement|__webpack_require__", 2),
        ],
    },
    "vue": {
        "category": "frontend", "display": "Vue.js", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"__vue_app__|v-app|data-v-",   3),
            Signal("html_match",    "",  r"vue\.esm|vue\.min\.js",       2),
            Signal("js_match",      "",  r"createApp|defineComponent",   2),
        ],
    },
    "nuxt": {
        "category": "frontend", "display": "Nuxt.js", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"window\.__NUXT__|__nuxt",  3),
            Signal("html_match",    "",  r'/_nuxt/',                  3),
        ],
    },
    "angular": {
        "category": "frontend", "display": "Angular", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"ng-version|ng-app|<app-root", 3),
            Signal("html_match",    "",  r"angular\.min\.js",            2),
        ],
    },
    "sveltekit": {
        "category": "frontend", "display": "SvelteKit", "threshold": 2,
        "signals": [
            Signal("html_match",    "",  r"__SVELTEKIT_APP_VERSION__", 3),
            Signal("html_match",    "",  r"/_app/immutable/",          3),
        ],
    },

    # Backend
    "express": {
        "category": "backend", "display": "Express/Node.js", "threshold": 2,
        "signals": [
            Signal("header_match",  "x-powered-by",   r"Express",   3),
            Signal("cookie_exists", "connect.sid",    None,         3),
        ],
    },
    "rails": {
        "category": "backend", "display": "Ruby on Rails", "threshold": 2,
        "signals": [
            Signal("header_match",  "x-runtime",      r"^\d+\.\d+", 2),
            Signal("cookie_exists", "_session_id",    None,         3),
            Signal("cookie_exists", "_rails",         None,         2),
        ],
    },
    "django": {
        "category": "backend", "display": "Django", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "csrftoken",          None,         3),
            Signal("html_match",    "",  r"csrfmiddlewaretoken",        2),
            Signal("header_match",  "x-frame-options",   r"SAMEORIGIN", 1),
        ],
    },
    "laravel": {
        "category": "backend", "display": "Laravel/PHP", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "laravel_session",    None,         3),
            Signal("cookie_exists", "XSRF-TOKEN",         None,         2),
        ],
    },
    "spring": {
        "category": "backend", "display": "Spring Boot", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "JSESSIONID",              None,    2),
            Signal("header_exists", "x-application-context",  None,    3),
        ],
    },
    "aspnet": {
        "category": "backend", "display": "ASP.NET", "threshold": 2,
        "signals": [
            Signal("header_exists", "x-aspnet-version",    None,        3),
            Signal("header_exists", "x-aspnetmvc-version", None,        3),
            Signal("cookie_exists", "ASP.NET_SessionId",   None,        3),
            Signal("cookie_exists", "ASPXAUTH",            None,        3),
        ],
    },
    "phoenix": {
        "category": "backend", "display": "Phoenix/Elixir", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "_phoenix_",      None,            3),
            Signal("header_match",  "server",         r"Cowboy|Plug",  3),
        ],
    },

    # Infra
    "nginx": {
        "category": "infra", "display": "nginx", "threshold": 2,
        "signals": [Signal("header_match", "server", r"nginx", 3)],
    },
    "apache": {
        "category": "infra", "display": "Apache", "threshold": 2,
        "signals": [Signal("header_match", "server", r"Apache", 3)],
    },
    "caddy": {
        "category": "infra", "display": "Caddy", "threshold": 2,
        "signals": [Signal("header_match", "server", r"Caddy", 3)],
    },
    "envoy": {
        "category": "infra", "display": "Envoy", "threshold": 2,
        "signals": [
            Signal("header_match",  "server", r"envoy",                           3),
            Signal("header_exists", "x-envoy-upstream-service-time", None,        3),
        ],
    },
    "traefik": {
        "category": "infra", "display": "Traefik", "threshold": 2,
        "signals": [Signal("header_match", "server", r"traefik", 3)],
    },

    # API (detected via JS/HTML analysis + path probing, not headers/cookies alone)
    "graphql": {
        "category": "api", "display": "GraphQL", "threshold": 2,
        "signals": [
            Signal("html_match", "", r'"/graphql"',               2),
            Signal("js_match",   "", r"ApolloClient|createHttpLink|gql`", 2),
            Signal("js_match",   "", r'"/graphql"',               1),
        ],
    },
    "trpc": {
        "category": "api", "display": "tRPC", "threshold": 2,
        "signals": [
            Signal("js_match",   "", r"createTRPCNext|@trpc/client|api/trpc", 3),
            Signal("html_match", "", r"api/trpc",                              2),
        ],
    },

    # Auth providers
    "jwt": {
        "category": "auth", "display": "JWT", "threshold": 2,
        "signals": [
            Signal("js_match",      "", r"jsonwebtoken|jwt\.sign|jwt\.verify", 2),
            Signal("cookie_exists", "access_token", None,                      1),
            Signal("cookie_exists", "id_token",     None,                      2),
        ],
    },
    "nextauth": {
        "category": "auth", "display": "NextAuth.js", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "next-auth.session-token", None,           3),
            Signal("cookie_exists", "__Secure-next-auth",      None,           3),
            Signal("cookie_exists", "__Host-next-auth",        None,           3),
            Signal("html_match",    "", r"/api/auth/session|next-auth",        2),
        ],
    },
    "auth0": {
        "category": "auth", "display": "Auth0", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "auth0",       None,                       3),
            Signal("html_match",    "", r"auth0\.com|@auth0/auth0",            3),
            Signal("js_match",      "", r"auth0\.com|@auth0/auth0-spa-js",     3),
        ],
    },
    "cognito": {
        "category": "auth", "display": "AWS Cognito", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "cognito",    None,                        2),
            Signal("js_match",      "", r"amazon-cognito|CognitoUserPool",     3),
        ],
    },
    "firebase": {
        "category": "auth", "display": "Firebase Auth", "threshold": 2,
        "signals": [
            Signal("html_match",    "", r"firebaseapp\.com|firebase/app",      3),
            Signal("js_match",      "", r"firebase/auth|initializeApp",        2),
        ],
    },
    "clerk": {
        "category": "auth", "display": "Clerk", "threshold": 2,
        "signals": [
            Signal("cookie_exists", "__clerk",    None,                        3),
            Signal("html_match",    "", r"@clerk/nextjs|@clerk/clerk-react",   3),
            Signal("js_match",      "", r"@clerk/|ClerkProvider",              3),
        ],
    },
}

# ---------------------------------------------------------------------------
# Paths to probe for existence
# ---------------------------------------------------------------------------

_PROBE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/trpc",
    "/admin",
    "/admin/login",
    "/debug",
    "/.env",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/metrics",
    "/health",
    "/_next/static/",
    "/__nuxt/",
    "/_app/immutable/",
]

# Minimal fallback brute list used when ffuf/gobuster are unavailable.
# Real path brute-forcing is delegated to external tools (see tool_gen.py).
_BRUTE_PATHS = [
    "/administrator", "/manage", "/management", "/panel", "/cp",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/api/v3", "/api/v4", "/api/internal", "/api/admin",
    "/rest", "/rest/v1", "/v1", "/v2", "/v3",
    "/trace", "/info", "/env", "/dump", "/heapdump",
    "/actuator/beans", "/actuator/loggers", "/actuator/threaddump",
    "/jolokia", "/h2-console", "/console",
    "/.env.local", "/.env.dev", "/.env.production", "/.env.backup",
    "/config.json", "/secrets.json", "/credentials.json",
    "/.git/HEAD", "/.git/config", "/.htaccess", "/.htpasswd",
    "/web.config", "/appsettings.json", "/application.properties",
    "/swagger-ui.html", "/redoc", "/openapi3",
    "/v2/api-docs", "/v3/api-docs",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/.DS_Store", "/package.json",
    "/healthz", "/readyz", "/livez", "/ping", "/version",
    "/login", "/signup", "/register", "/auth", "/oauth",
    "/users", "/user", "/profile", "/me", "/account",
]

# Signals that flag an interesting discovery regardless of framework
_RISK_FLAGS = {
    "source_map": re.compile(r"//[#@]\s*sourceMappingURL=\S+\.map", re.MULTILINE),
    "hardcoded_secret": re.compile(
        r"""(?:api[_-]?key|secret|password|token|AUTH)\s*[:=]\s*["'`][A-Za-z0-9+/=_\-]{12,}["'`]""",
        re.IGNORECASE,
    ),
    "graphql_schema": re.compile(r'"__schema"', re.IGNORECASE),
    "ws_url": re.compile(r"""["'](wss?://[^"']{4,200})["']"""),
    "sse_client": re.compile(r"new EventSource|text/event-stream"),
    "grpc_web": re.compile(r"application/grpc-web|grpc-web"),
    "internal_ip": re.compile(r"""["']((?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^"']{4,50})["']"""),
}

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# Passive-source parsers — robots.txt, sitemap.xml, OIDC discovery
# These extract paths from documents the server already volunteers, turning
# discarded probe responses into real coverage.
# ---------------------------------------------------------------------------

_ROBOTS_DIRECTIVE_RE = re.compile(
    r"^\s*(disallow|allow|sitemap)\s*:\s*(\S.*?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_robots(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Extract (paths, sitemap_urls) from a robots.txt body.
    Disallow/Allow values are returned as-is (paths, possibly with wildcards stripped)."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for m in _ROBOTS_DIRECTIVE_RE.finditer(text):
        directive = m.group(1).lower()
        value = m.group(2).strip()
        if not value or value == "/":
            continue
        if directive == "sitemap":
            sitemaps.append(urljoin(base_url, value))
        else:
            # Strip wildcards and trailing comments; keep leading slash
            value = value.split("#", 1)[0].strip()
            value = value.replace("*", "").rstrip("$")
            if value and value.startswith("/") and len(value) < 200:
                paths.append(value)
    return paths, sitemaps


def _parse_sitemap_xml(text: str) -> tuple[list[str], list[str]]:
    """Parse a sitemap.xml or sitemap_index.xml body.
    Returns (loc_urls, child_sitemap_urls). Caller decides how deep to recurse."""
    import xml.etree.ElementTree as ET
    locs: list[str] = []
    child_sitemaps: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return locs, child_sitemaps
    # Strip XML namespace from tag names for easy matching
    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1].lower()
        if tag == "loc" and elem.text:
            url = elem.text.strip()
            if url.startswith("http"):
                # Determine if this <loc> is inside a <sitemap> (index) or <url> (leaf)
                parent_tag = ""
                # ElementTree doesn't track parents; use a simple heuristic — the
                # url is a child sitemap if it ends in .xml or .xml.gz
                if url.lower().endswith((".xml", ".xml.gz")):
                    child_sitemaps.append(url)
                else:
                    locs.append(url)
    # Cap to avoid runaway sitemaps (some real-world sitemaps have 50k entries)
    return locs[:200], child_sitemaps[:20]


def _parse_openid_config(text: str) -> list[str]:
    """Extract endpoint URLs from a /.well-known/openid-configuration body."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    keys = (
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
        "jwks_uri", "registration_endpoint", "revocation_endpoint",
        "introspection_endpoint", "end_session_endpoint", "device_authorization_endpoint",
    )
    out: list[str] = []
    for k in keys:
        v = data.get(k)
        if isinstance(v, str) and v.startswith("http"):
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class GraphQLFindings:
    introspection_enabled: bool = False
    object_types_with_ids: list[str] = field(default_factory=list)  # type names
    batching_supported: bool = False
    field_suggestions_leak: bool = False
    max_depth_hit: int = 0
    mutations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "introspection_enabled": self.introspection_enabled,
            "object_types_with_ids": self.object_types_with_ids,
            "batching_supported": self.batching_supported,
            "field_suggestions_leak": self.field_suggestions_leak,
            "max_depth_hit": self.max_depth_hit,
            "mutations": self.mutations,
        }


@dataclass
class StackProfile:
    target: str
    protocols: list[str] = field(default_factory=list)
    detected: dict[str, list[str]] = field(default_factory=dict)  # category → [display names]
    detected_keys: set[str] = field(default_factory=set)
    interesting_paths: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    recommended_tests: list[str] = field(default_factory=list)
    graphql: Optional[GraphQLFindings] = None
    hash_routing: bool = False  # True if SPA uses fragment routing (e.g. /#/login)

    def to_dict(self) -> dict:
        category_order = ["cdn", "frontend", "backend", "api", "auth", "infra"]
        d = {
            "target": self.target,
            "protocols": self.protocols,
            "stack": {
                cat: self.detected.get(cat, [])
                for cat in category_order
                if self.detected.get(cat)
            },
            "interesting_paths": self.interesting_paths,
            "risk_flags": self.risk_flags,
            "websocket_urls": self.websocket_urls,
            "recommended_tests": self.recommended_tests,
            "hash_routing": self.hash_routing,
        }
        if self.graphql:
            d["graphql"] = self.graphql.to_dict()
        return d

    def summary(self) -> str:
        lines = [f"Target: {self.target}"]
        lines.append(f"Protocols: {', '.join(self.protocols) or 'unknown'}")
        lines.append("")
        lines.append("Detected stack:")
        for cat, techs in self.detected.items():
            lines.append(f"  {cat:<12} {', '.join(techs)}")
        if self.risk_flags:
            lines.append("")
            lines.append("Risk flags:")
            for f in self.risk_flags:
                lines.append(f"  ! {f}")
        if self.websocket_urls:
            lines.append("")
            lines.append("WebSocket URLs:")
            for u in self.websocket_urls:
                lines.append(f"  {u}")
        if self.interesting_paths:
            lines.append("")
            lines.append("Interesting paths (confirmed):")
            for p in self.interesting_paths:
                lines.append(f"  {p}")
        if self.graphql:
            gql = self.graphql
            lines.append("")
            lines.append("GraphQL active probe:")
            lines.append(f"  introspection : {'enabled' if gql.introspection_enabled else 'disabled'}")
            lines.append(f"  batching      : {'yes' if gql.batching_supported else 'no'}")
            lines.append(f"  field hints   : {'yes (schema leak)' if gql.field_suggestions_leak else 'no'}")
            lines.append(f"  max depth     : {gql.max_depth_hit}")
            if gql.object_types_with_ids:
                lines.append(f"  IDOR types    : {', '.join(gql.object_types_with_ids[:10])}")
            if gql.mutations:
                lines.append(f"  mutations     : {', '.join(gql.mutations[:8])}")
        lines.append("")
        lines.append("Recommended tests:")
        for i, t in enumerate(self.recommended_tests, 1):
            lines.append(f"  {i:>2}. {t}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main fingerprinting class
# ---------------------------------------------------------------------------

_GQL_INTROSPECTION = '{"query":"{ __schema { queryType { name } types { name kind fields { name type { name kind ofType { name kind } } } } mutationType { name } } }"}'
_GQL_BATCH_TEST    = '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
_GQL_DEEP_QUERY    = '{"query":"{ ' + "a { " * 12 + "__typename" + " }" * 12 + ' }"}'
_GQL_BOGUS_FIELD   = '{"query":"{ doesNotExistXyz }"}'
_GQL_HEADERS       = {"Content-Type": "application/json"}

_GQL_ID_FIELD_RE   = re.compile(r"\bid\b", re.IGNORECASE)
_GQL_SUGGEST_RE    = re.compile(r"Did you mean|suggestions?|similar field", re.IGNORECASE)


class GraphQLProber:
    """Active GraphQL endpoint analysis. Fires when stackprint confirms /graphql is live."""

    def __init__(self, endpoint_url: str, timeout: float = 6.0):
        self.url = endpoint_url
        self.timeout = timeout

    async def probe(self, client: httpx.AsyncClient) -> GraphQLFindings:
        findings = GraphQLFindings()

        schema_json = await self._post(client, _GQL_INTROSPECTION)
        if schema_json and "data" in schema_json and schema_json.get("data"):
            findings.introspection_enabled = True
            findings.object_types_with_ids = self._extract_object_types_with_ids(schema_json)
            findings.mutations = self._extract_mutations(schema_json)

        batch_resp = await self._post(client, _GQL_BATCH_TEST, is_list=True)
        if isinstance(batch_resp, list) and len(batch_resp) >= 2:
            findings.batching_supported = True

        # Field suggestion leak — send a bogus field name and look for "Did you mean"
        bogus_resp = await self._post(client, _GQL_BOGUS_FIELD)
        raw_bogus = json.dumps(bogus_resp) if bogus_resp else ""
        if _GQL_SUGGEST_RE.search(raw_bogus):
            findings.field_suggestions_leak = True

        # Measure how deep a query the server accepts before rejecting
        findings.max_depth_hit = await self._probe_depth(client)

        return findings

    async def _post(self, client: httpx.AsyncClient, body: str, is_list: bool = False):
        try:
            resp = await client.post(
                self.url, content=body, headers=_GQL_HEADERS, timeout=self.timeout
            )
            return resp.json()
        except Exception:
            return None

    async def _probe_depth(self, client: httpx.AsyncClient) -> int:
        """Binary-search the max accepted nesting depth (5–20 range)."""
        accepted = 0
        for depth in (5, 10, 15, 20):
            inner = "{ __typename" + " }" * depth
            query = json.dumps({"query": "{ " + " a {" * depth + inner + " }" * depth + " }"})
            try:
                resp = await client.post(
                    self.url, content=query, headers=_GQL_HEADERS, timeout=self.timeout
                )
                data = resp.json()
                if "errors" not in data or not any(
                    "depth" in str(e).lower() or "complex" in str(e).lower()
                    for e in data.get("errors", [])
                ):
                    accepted = depth
            except Exception:
                break
        return accepted

    @staticmethod
    def _extract_object_types_with_ids(schema_json: dict) -> list[str]:
        types = schema_json.get("data", {}).get("__schema", {}).get("types", [])
        result = []
        for t in types:
            if t.get("kind") != "OBJECT":
                continue
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            fields = t.get("fields") or []
            if any(_GQL_ID_FIELD_RE.fullmatch(f.get("name", "")) for f in fields):
                result.append(name)
        return result

    @staticmethod
    def _extract_mutations(schema_json: dict) -> list[str]:
        types = schema_json.get("data", {}).get("__schema", {}).get("types", [])
        mut_type = schema_json.get("data", {}).get("__schema", {}).get("mutationType")
        if not mut_type:
            return []
        mut_name = mut_type.get("name", "Mutation")
        for t in types:
            if t.get("name") == mut_name and t.get("kind") == "OBJECT":
                return [f.get("name", "") for f in (t.get("fields") or [])]
        return []


class Stackprint:
    def __init__(self, target: str, timeout: float = 8.0, max_js_bundles: int = 3):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_js_bundles = max_js_bundles
        self._origin = self._parse_origin(target)

        self._html: str = ""
        self._js_content: str = ""          # concatenated JS bundle content
        self._headers: dict[str, str] = {}  # lowercase header names
        self._cookies: dict[str, str] = {}
        self._probed_paths: list[str] = []  # paths that returned 200-399
        self._actuator_confirmed: bool = False  # set when PAT actuator probing hits
        self._http_version: str = "unknown"
        self._graphql_findings: Optional[GraphQLFindings] = None
        # Soft-404 baseline: (status_code, redirect_location, body_length)
        self._soft404_baseline: Optional[tuple[int, str, int]] = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> StackProfile:
        async with httpx.AsyncClient(
            headers=_BROWSER_HEADERS,
            follow_redirects=False,
            timeout=self.timeout,
            verify=False,
            http2=True,
        ) as client:
            await self._fetch_homepage(client)
            await self._probe_paths(client)
            await asyncio.gather(
                self._fetch_js_bundles(client),
                self._probe_graphql(client),
                self._brute_paths(client),
            )

        profile = self._build_profile()
        return profile

    async def _probe_graphql(self, client: httpx.AsyncClient) -> None:
        for gql_path in ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"):
            if gql_path in self._probed_paths:
                prober = GraphQLProber(self.target + gql_path, timeout=self.timeout)
                self._graphql_findings = await prober.probe(client)
                return

    async def _brute_paths(self, client: httpx.AsyncClient) -> None:
        """Brute-force a broader wordlist using the soft-404 baseline to filter non-existent paths."""
        already_known = set(self._probed_paths)

        async def probe(path: str) -> None:
            url = self.target + path
            try:
                resp = await client.get(url, timeout=3.0, follow_redirects=False)
                status = resp.status_code
                location = resp.headers.get("location", "")
                body_len = len(resp.content)

                if self._is_soft404(status, location, body_len):
                    return

                if 200 <= status < 400:
                    self._probed_paths.append(path)
            except Exception:
                pass

        # Batch in chunks of 30 to avoid overwhelming the server
        chunk_size = 30
        paths = [p for p in _BRUTE_PATHS if p not in already_known]
        for i in range(0, len(paths), chunk_size):
            await asyncio.gather(*[probe(p) for p in paths[i:i + chunk_size]])

    # ------------------------------------------------------------------
    # Probing
    # ------------------------------------------------------------------

    async def _fetch_homepage(self, client: httpx.AsyncClient) -> None:
        try:
            resp = await client.get(self.target, follow_redirects=True)
            self._http_version = f"HTTP/{resp.http_version}"
            self._headers = {k.lower(): v for k, v in resp.headers.items()}
            self._cookies = {k: v for k, v in resp.cookies.items()}
            self._html = resp.text
        except Exception as exc:
            print(f"[stackprint] homepage fetch failed: {exc}", file=sys.stderr)

    async def _calibrate_soft404(self, client: httpx.AsyncClient) -> None:
        """GET a random sentinel path to establish the server's 404 response fingerprint."""
        sentinel = self.target + "/hxxpsin-nonexistent-8a3f9c2b"
        try:
            # Don't follow redirects — we want the raw redirect location, not the destination
            resp = await client.get(sentinel, timeout=4.0, follow_redirects=False)
            location = resp.headers.get("location", "")
            self._soft404_baseline = (resp.status_code, location, len(resp.content))
        except Exception:
            self._soft404_baseline = None

    def _is_soft404(self, status: int, location: str, body_len: int) -> bool:
        if self._soft404_baseline is None:
            return False
        base_status, base_loc, base_len = self._soft404_baseline
        # Same status + same redirect target → this path is treated identically to 404
        if status == base_status and location == base_loc:
            return True
        # Same status + similar body length (within 5%) → likely same error page
        if status == base_status and base_len > 0 and abs(body_len - base_len) / base_len < 0.05:
            return True
        return False

    async def _probe_paths(self, client: httpx.AsyncClient) -> None:
        await self._calibrate_soft404(client)

        # Paths whose response body we want to *parse* — robots/sitemap/OIDC.
        # For these we follow redirects and extract structured content.
        body_extract = {
            "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        }

        async def probe(path: str) -> None:
            url = self.target + path
            follow = path in body_extract
            try:
                resp = await client.get(url, timeout=4.0, follow_redirects=follow)
                status = resp.status_code
                location = resp.headers.get("location", "")
                body_len = len(resp.content)

                # Skip soft-404 check for body_extract paths: SPA fallbacks
                # often return 200 with a similar empty Location header to the
                # 404 baseline, causing false matches. We want these bodies.
                if not follow and self._is_soft404(status, location, body_len):
                    return

                if 200 <= status < 400:
                    self._probed_paths.append(path)
                    if follow and 200 <= status < 300 and body_len > 0:
                        await self._extract_passive_paths(client, path, resp.text)
                    return

                # 405 = Method Not Allowed → path exists but GET isn't accepted.
                # Try a minimal POST for known POST-only paths (GraphQL, API endpoints).
                if status == 405 and any(kw in path for kw in ("/graphql", "/graphiql", "/api", "/query")):
                    post_resp = await client.post(url, content="{}", timeout=4.0,
                                                  follow_redirects=False,
                                                  headers={"Content-Type": "application/json"})
                    if 200 <= post_resp.status_code < 500:
                        self._probed_paths.append(path)
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in _PROBE_PATHS])

        # SpringBoot actuator probing — load paths from PAT at runtime
        try:
            import payloads as _payloads
            actuator_paths = _payloads.springboot_actuator()
            actuator_probes = [f"/{p}" for p in actuator_paths if not p.startswith("/")]
            actuator_hits: list[str] = []

            async def probe_actuator(path: str) -> None:
                url = self.target + path
                try:
                    resp = await client.get(url, timeout=3.0, follow_redirects=False)
                    if resp.status_code in (200, 204) and not self._is_soft404(resp.status_code, "", len(resp.content)):
                        actuator_hits.append(path)
                        self._probed_paths.append(path)
                except Exception:
                    pass

            await asyncio.gather(*[probe_actuator(p) for p in actuator_probes])
            if actuator_hits:
                self._actuator_confirmed = True
        except Exception:
            pass

    async def _extract_passive_paths(
        self, client: httpx.AsyncClient, source_path: str, body: str,
    ) -> None:
        """Promote paths discovered in robots.txt / sitemap.xml / OIDC bodies."""
        if source_path == "/robots.txt":
            paths, sitemap_urls = _parse_robots(body, self.target)
            for p in paths:
                if p not in self._probed_paths:
                    self._probed_paths.append(p)
            # Recurse into any Sitemap: URLs declared in robots.txt
            for sm_url in sitemap_urls[:5]:
                try:
                    r = await client.get(sm_url, timeout=4.0, follow_redirects=True)
                    if r.status_code == 200 and r.content:
                        await self._consume_sitemap(client, r.text, depth=0)
                except Exception:
                    pass
            return

        if source_path in ("/sitemap.xml", "/sitemap_index.xml"):
            await self._consume_sitemap(client, body, depth=0)
            return

        if source_path in ("/.well-known/openid-configuration",
                           "/.well-known/oauth-authorization-server"):
            for url in _parse_openid_config(body):
                # Only keep same-origin paths
                parsed = urlparse(url)
                target_host = urlparse(self.target).netloc
                if parsed.netloc == target_host and parsed.path:
                    if parsed.path not in self._probed_paths:
                        self._probed_paths.append(parsed.path)
            return

    async def _consume_sitemap(
        self, client: httpx.AsyncClient, body: str, depth: int,
    ) -> None:
        """Parse a sitemap body and add discovered paths. Recurses one level for indexes."""
        target_host = urlparse(self.target).netloc
        locs, child_sitemaps = _parse_sitemap_xml(body)
        for url in locs:
            parsed = urlparse(url)
            if parsed.netloc != target_host:
                continue
            path = parsed.path or "/"
            if path not in self._probed_paths and len(path) < 200:
                self._probed_paths.append(path)
        if depth < 1:  # one level of sitemap-index recursion
            for child_url in child_sitemaps[:10]:
                parsed = urlparse(child_url)
                if parsed.netloc != target_host:
                    continue
                try:
                    r = await client.get(child_url, timeout=4.0, follow_redirects=True)
                    if r.status_code == 200 and r.content:
                        await self._consume_sitemap(client, r.text, depth=depth + 1)
                except Exception:
                    pass

    async def _fetch_js_bundles(self, client: httpx.AsyncClient) -> None:
        srcs = _SCRIPT_SRC_RE.findall(self._html)

        # Prefer larger/chunk-named scripts (likely the app bundle)
        srcs = sorted(set(srcs), key=lambda s: (
            "chunk" in s or "main" in s or "app" in s or "bundle" in s
        ), reverse=True)[:self.max_js_bundles]

        parts = []
        # Chunks discovered from import statements in the entry bundles —
        # fetched in a second pass so SPAs that lazy-load (Angular, Webpack
        # code-splitting) are reachable without a browser.
        nested_chunks: set[str] = set()

        async def fetch_one(src: str) -> None:
            url = src if src.startswith("http") else urljoin(self.target, src)
            try:
                resp = await client.get(url, timeout=6.0, follow_redirects=True)
                if "javascript" in resp.headers.get("content-type", ""):
                    body = resp.text[:300_000]
                    parts.append(body)
                    # Discover lazy-loaded chunks: import {x} from "./chunk-ABC.js"
                    for m in re.finditer(
                        r"""(?:from\s*|import\s*\(?\s*)["']\.?/?(chunk-[A-Za-z0-9_\-]+\.js|[\w\-./]+/[\w\-]+\.js)["']""",
                        body,
                    ):
                        chunk_path = m.group(1)
                        if chunk_path not in srcs:
                            nested_chunks.add(urljoin(url, chunk_path))
            except Exception:
                pass

        await asyncio.gather(*[fetch_one(s) for s in srcs])

        # Second pass: fetch up to 6 more nested chunks
        if nested_chunks:
            extra = list(nested_chunks)[:6]
            await asyncio.gather(*[fetch_one(c) for c in extra])

        self._js_content = "\n".join(parts)

        # Extract SPA routes from the bundle text — works without a browser,
        # so quick mode also benefits.
        try:
            from spa_router import extract_routes_from_text
            for route in extract_routes_from_text(self._js_content):
                if route not in self._probed_paths:
                    self._probed_paths.append(route)
        except ImportError:
            pass

    # ------------------------------------------------------------------
    # Signal evaluation
    # ------------------------------------------------------------------

    def _eval_signal(self, sig: Signal) -> bool:
        if sig.kind == "header_exists":
            return sig.target.lower() in self._headers

        if sig.kind == "header_match":
            val = self._headers.get(sig.target.lower(), "")
            return bool(re.search(sig.pattern, val, re.IGNORECASE))

        if sig.kind == "cookie_exists":
            return any(sig.target.lower() in k.lower() for k in self._cookies)

        if sig.kind == "html_match":
            return bool(re.search(sig.pattern, self._html, re.IGNORECASE))

        if sig.kind == "js_match":
            return bool(re.search(sig.pattern, self._js_content, re.IGNORECASE))

        return False

    def _detect(self) -> set[str]:
        detected: set[str] = set()
        for key, tech in _TECHS.items():
            score = sum(
                sig.weight for sig in tech["signals"] if self._eval_signal(sig)
            )
            if score >= tech["threshold"]:
                detected.add(key)

        # Path-based detections (require confirmed probe hits)
        if "/graphql" in self._probed_paths or "/graphiql" in self._probed_paths:
            detected.add("graphql")
        if "/api/trpc" in self._probed_paths:
            detected.add("trpc")
        if self._actuator_confirmed:
            detected.add("spring")

        # WebSocket detection (JS source only — no browser context here)
        # Mark presence; actual URL list extracted separately
        if re.search(r"""["'](wss?://[^"']{4,200})["']""", self._js_content):
            detected.add("websocket")

        return detected

    # ------------------------------------------------------------------
    # Profile assembly
    # ------------------------------------------------------------------

    def _build_profile(self) -> StackProfile:
        detected_keys = self._detect()

        # Group by category
        detected_by_cat: dict[str, list[str]] = {}
        for key in detected_keys:
            tech = _TECHS.get(key, {})
            cat = tech.get("category", "api")
            display = tech.get("display", key)
            detected_by_cat.setdefault(cat, []).append(display)

        # Protocols
        protocols: list[str] = [self._http_version]
        alt_svc = self._headers.get("alt-svc", "")
        if re.search(r"\bh3\b", alt_svc):
            protocols.append("HTTP/3 (advertised via Alt-Svc)")
        upgrade = self._headers.get("upgrade", "")
        if "websocket" in upgrade.lower():
            protocols.append("WebSocket upgrade available")

        # Risk flags
        risk_flags: list[str] = []
        for flag_name, pattern in _RISK_FLAGS.items():
            haystack = self._html + "\n" + self._js_content
            if pattern.search(haystack):
                risk_flags.append(flag_name.replace("_", " "))

        # WebSocket URLs from JS
        ws_urls = list(dict.fromkeys(
            m.group(1)
            for m in re.finditer(
                r"""["'](wss?://[^"']{4,200})["']""", self._js_content
            )
        ))

        # Interesting paths: confirmed probes + framework-specific seeds
        interesting = list(self._probed_paths)
        if "nextjs" in detected_keys:
            interesting += ["/_next/static/chunks/", "/_next/data/"]
        if "graphql" in detected_keys:
            interesting += ["/graphql", "/graphiql"]
        if "spring" in detected_keys:
            interesting += ["/actuator/env", "/actuator/mappings", "/actuator/heapdump"]
        if "django" in detected_keys:
            interesting += ["/admin/"]
        if "laravel" in detected_keys:
            interesting += ["/.env", "/storage/logs/laravel.log"]
        # Deduplicate preserving order
        seen_paths: set[str] = set()
        unique_paths: list[str] = []
        for p in interesting:
            if p not in seen_paths:
                seen_paths.add(p)
                unique_paths.append(p)

        # Annotate risk flags with GraphQL active findings
        gql = self._graphql_findings
        if gql:
            if gql.introspection_enabled:
                risk_flags.append("graphql introspection enabled")
            if gql.batching_supported:
                risk_flags.append("graphql batching supported (DoS/rate-limit bypass)")
            if gql.field_suggestions_leak:
                risk_flags.append("graphql field suggestion leak (schema enumeration without introspection)")
            if gql.max_depth_hit >= 10:
                risk_flags.append(f"graphql deep query accepted (depth ≥{gql.max_depth_hit}) — DoS surface")

        # Recommendations
        from playbooks import build_recommendations
        recommended = build_recommendations(detected_keys)

        # Hash-routing detection — if the SPA uses /#/ routes, the crawler
        # needs to mirror discovered paths to their hash form.
        try:
            from spa_router import is_hash_routing
            hash_routing = is_hash_routing(self._html) or is_hash_routing(self._js_content)
        except ImportError:
            hash_routing = False

        return StackProfile(
            target=self.target,
            protocols=protocols,
            detected=detected_by_cat,
            detected_keys=detected_keys,
            interesting_paths=unique_paths,
            risk_flags=risk_flags,
            websocket_urls=ws_urls,
            recommended_tests=recommended,
            graphql=gql,
            hash_routing=hash_routing,
        )

    @staticmethod
    def _parse_origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"


# ---------------------------------------------------------------------------
# Crawler integration: seed paths into CrawlConfig
# ---------------------------------------------------------------------------

def apply_profile_to_crawler(profile: StackProfile, config) -> None:
    """
    Mutate a CrawlConfig to pre-seed interesting paths discovered by stackprint.
    Call before running the Crawler.
    """
    from urllib.parse import urljoin
    base = profile.target
    for path in profile.interesting_paths:
        full = urljoin(base, path)
        # CrawlConfig doesn't have a seed list field yet — caller manages queue
        # This is a convenience hook; the CLI wires it up.
        _ = full  # consumed by caller via profile.interesting_paths directly


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _main() -> None:
    import argparse
    import warnings

    warnings.filterwarnings("ignore")  # suppress SSL verify=False noise

    parser = argparse.ArgumentParser(description="hxxpsin stackprint")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--out", default="-")
    args = parser.parse_args()

    sp = Stackprint(args.url, timeout=args.timeout)
    profile = await sp.run()

    if args.json:
        output = json.dumps(profile.to_dict(), indent=2)
    else:
        output = profile.summary()

    if args.out == "-":
        print(output)
    else:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[+] Wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(_main())
