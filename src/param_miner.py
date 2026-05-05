"""
param_miner.py — Hidden parameter discovery (Burp Param Miner equivalent).

For each high-score endpoint, probes GET query params and JSON body keys
from a wordlist and flags any that produce a detectable response change.

Only runs on findings at or above min_score. Results feed into ActiveScanner
as additional injection targets and appear as a dedicated report section.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import httpx

# ---------------------------------------------------------------------------
# Wordlist (~200 high-value parameter names)
# ---------------------------------------------------------------------------

_PARAM_WORDLIST: list[str] = [
    # Admin / debug
    "debug", "test", "admin", "internal", "verbose", "trace", "dev",
    "development", "staging", "prod", "production", "preview", "beta",
    "mode", "env", "environment", "config", "settings", "setup",
    # Auth / token
    "token", "key", "secret", "api_key", "apikey", "access_token",
    "auth", "auth_token", "authorization", "jwt", "session", "sid",
    "csrf", "nonce", "otp", "code", "grant", "refresh_token",
    # Identity / access control
    "id", "user", "user_id", "uid", "account", "account_id",
    "role", "roles", "permission", "permissions", "scope", "scopes",
    "group", "groups", "plan", "tier", "subscription", "feature",
    "flag", "flags", "enabled", "disabled", "active", "admin_flag",
    # Redirect / URL injection
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "next", "continue", "callback", "success_url",
    "error_url", "target", "goto", "forward", "origin", "ref",
    "referrer", "source", "from", "to", "href", "link", "uri",
    # File / path
    "file", "path", "filename", "filepath", "dir", "directory",
    "folder", "include", "template", "view", "page", "layout",
    "theme", "skin", "module", "plugin", "component", "resource",
    # Injection surface
    "q", "query", "search", "filter", "sort", "order", "where",
    "field", "fields", "select", "column", "columns", "table",
    "limit", "offset", "page", "per_page", "size", "count",
    "start", "end", "from_date", "to_date", "range",
    "cmd", "command", "exec", "execute", "run", "shell",
    "lang", "language", "locale", "timezone", "currency",
    "format", "output", "type", "kind", "action", "method",
    "op", "operation", "request", "payload", "data", "body",
    # Misc
    "version", "v", "api_version", "expand", "embed", "include",
    "depth", "level", "recursive", "cascade", "force", "override",
    "bypass", "skip", "ignore", "strict", "validate", "dry_run",
    "preview_mode", "readonly", "write", "create", "update", "delete",
    "batch", "bulk", "async", "sync", "queue", "background",
    "webhook", "notify", "callback_url", "hook",
    "tag", "label", "category", "namespace", "context", "region",
    "bucket", "prefix", "suffix", "pattern", "regex",
    "download", "export", "import", "upload", "stream",
    "raw", "pretty", "indent", "encoding", "charset",
    "width", "height", "quality", "resize", "crop", "rotate",
    # SpringBoot actuator param names (from PAT Insecure Management Interface)
    "actuator", "health", "env", "heapdump", "shutdown", "mappings",
    "metrics", "prometheus", "loggers", "beans", "conditions", "info",
    # Prototype pollution (from PAT Prototype Pollution)
    "__proto__", "constructor", "prototype",
    # Common hidden params (from PAT Hidden Parameters)
    "_method", "method", "_source", "callback", "jsonp",
    # Override / bypass signals
    "override", "X-HTTP-Method-Override", "x-method-override",
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ParamFinding:
    endpoint: str
    method: str
    param_name: str
    baseline_status: int
    found_status: int
    baseline_len: int
    found_len: int
    evidence: str
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "param": self.param_name,
            "baseline_status": self.baseline_status,
            "found_status": self.found_status,
            "baseline_len": self.baseline_len,
            "found_len": self.found_len,
            "evidence": self.evidence,
            "response_snippet": self.response_snippet[:200],
        }


@dataclass
class ParamMineResult:
    endpoints_probed: int = 0
    findings: list[ParamFinding] = field(default_factory=list)

    @property
    def interesting(self) -> list[ParamFinding]:
        return [f for f in self.findings if f.baseline_status != f.found_status
                or abs(f.found_len - f.baseline_len) / max(f.baseline_len, 1) > 0.10]

    def to_dict(self) -> dict:
        return {
            "endpoints_probed": self.endpoints_probed,
            "interesting": len(self.interesting),
            "findings": [f.to_dict() for f in self.interesting],
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ParamMiner:
    """
    Discovers undocumented GET params and JSON body keys by comparing
    baseline responses to responses with wordlist params injected.
    """

    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 6.0,
        min_score: int = 6,
        top_n: int = 10,
        concurrency: int = 8,
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.min_score = min_score
        self.top_n = top_n
        self.concurrency = concurrency

    async def run(self, request_findings: list) -> ParamMineResult:
        result = ParamMineResult()

        candidates = [
            f for f in request_findings
            if f.score >= self.min_score
        ][:self.top_n]

        result.endpoints_probed = len(candidates)
        if not candidates:
            return result

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers=self.auth_headers,
        ) as client:
            tasks = [self._mine_endpoint(client, f) for f in candidates]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)

        return result

    async def _mine_endpoint(self, client: httpx.AsyncClient, finding) -> list[ParamFinding]:
        url = finding.url
        method = finding.method.upper()
        body = finding.body

        baseline_status, baseline_len = await self._baseline(client, url, method, body)
        if baseline_status == 0:
            return []

        findings: list[ParamFinding] = []
        sem = asyncio.Semaphore(self.concurrency)

        async def probe_one(param: str) -> Optional[ParamFinding]:
            async with sem:
                if method == "GET" or not body:
                    return await self._probe_get_param(
                        client, url, param, baseline_status, baseline_len
                    )
                else:
                    return await self._probe_json_key(
                        client, url, method, body, param, baseline_status, baseline_len
                    )

        results = await asyncio.gather(*[probe_one(p) for p in _PARAM_WORDLIST], return_exceptions=True)
        for r in results:
            if isinstance(r, ParamFinding):
                findings.append(r)

        return findings

    async def _baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: Optional[str],
    ) -> tuple[int, int]:
        try:
            if method in ("POST", "PUT", "PATCH") and body:
                resp = await client.request(
                    method, url, content=body,
                    headers={**self.auth_headers, "Content-Type": "application/json"},
                )
            else:
                resp = await client.get(url)
            return resp.status_code, len(resp.content)
        except Exception:
            return 0, 0

    async def _probe_get_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        baseline_status: int,
        baseline_len: int,
    ) -> Optional[ParamFinding]:
        probe_value = f"hxxpsin-probe-{param}"
        parsed = urlparse(url)
        existing = parse_qs(parsed.query)
        if param in existing:
            return None  # already observed in crawl
        new_params = {**{k: v[0] for k, v in existing.items()}, param: probe_value}
        probe_url = parsed._replace(query=urlencode(new_params)).geturl()
        try:
            resp = await client.get(probe_url)
            evidence = self._is_interesting(
                baseline_status, resp.status_code, baseline_len, len(resp.content), resp.text
            )
            if evidence:
                return ParamFinding(
                    endpoint=url, method="GET", param_name=param,
                    baseline_status=baseline_status, found_status=resp.status_code,
                    baseline_len=baseline_len, found_len=len(resp.content),
                    evidence=evidence, response_snippet=resp.text[:300],
                )
        except Exception:
            pass
        return None

    async def _probe_json_key(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        existing_body: Optional[str],
        key: str,
        baseline_status: int,
        baseline_len: int,
    ) -> Optional[ParamFinding]:
        try:
            bd = json.loads(existing_body) if existing_body else {}
        except Exception:
            bd = {}

        if key in bd:
            return None  # already in observed body

        probe_value = f"hxxpsin-probe-{key}"
        new_body = json.dumps({**bd, key: probe_value}, separators=(",", ":"))
        try:
            resp = await client.request(
                method, url, content=new_body,
                headers={**self.auth_headers, "Content-Type": "application/json"},
            )
            evidence = self._is_interesting(
                baseline_status, resp.status_code, baseline_len, len(resp.content), resp.text
            )
            if evidence:
                return ParamFinding(
                    endpoint=url, method=method, param_name=key,
                    baseline_status=baseline_status, found_status=resp.status_code,
                    baseline_len=baseline_len, found_len=len(resp.content),
                    evidence=evidence, response_snippet=resp.text[:300],
                )
        except Exception:
            pass
        return None

    @staticmethod
    def _is_interesting(
        baseline_status: int,
        found_status: int,
        baseline_len: int,
        found_len: int,
        body: str,
    ) -> Optional[str]:
        """Return an evidence string if the response changed significantly."""
        # Status class changed (e.g. 200→500, 200→403 — but not 4xx→4xx noise)
        baseline_class = baseline_status // 100
        found_class = found_status // 100
        if baseline_class != found_class and not (baseline_class == 4 and found_class == 4):
            return f"status changed {baseline_status}→{found_status}"

        # Body length delta > 10%
        delta = abs(found_len - baseline_len)
        if baseline_len > 0 and delta / baseline_len > 0.10 and delta > 50:
            direction = "grew" if found_len > baseline_len else "shrank"
            return f"body {direction} {delta}B ({round(100*delta/baseline_len)}%)"

        # Error string appeared in body
        if re.search(
            r"(error|exception|traceback|invalid|unexpected|unknown|forbidden|not allowed)",
            body[:500], re.IGNORECASE
        ):
            # Only interesting if baseline didn't have it
            return "error string appeared in response — parameter may be processed"

        return None
