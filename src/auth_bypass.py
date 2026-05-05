"""
auth_bypass.py — Automatic SQL injection auth bypass detection.

For every endpoint classified as Cat.AUTH (login surface), tries the PAT
sql_auth_bypass() wordlist (~195 payloads) substituted into common credential
field shapes, and flags any payload that returns an auth-token signal.

Detection (in order of confidence):
  1. Status flips from 4xx baseline to 2xx with token-shaped body → confirmed (0.95)
  2. Status flips from 4xx baseline to 2xx with auth-shaped Set-Cookie → confirmed (0.9)
  3. Status flips from 4xx baseline to 2xx without obvious token → likely (0.6)

Why this catches what the verifier misses: SQLi-bypass payloads on a login
endpoint don't trigger SQL error strings (the error is caught by the auth
layer), they trigger an unexpected 200. The verifier only looks for error
strings; this module looks for the unexpected success.

Pipeline position: after auto_auth, --active-scan gated (sends ~80
payloads per login endpoint).

Sources: PAT SQL Injection/Intruder/Auth_Bypass.txt + Auth_Bypass2.txt
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

import payloads as _payloads


# Login endpoint indicators (path-based, case-insensitive)
_LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign-in|sign_in|sessions?|auth/(login|signin|token)|"
    r"oauth/token|users/v\d+/login|api/auth)($|/|\?)",
    re.IGNORECASE,
)

# Token field names that indicate auth success in response body
_AUTH_SIGNAL_RE = re.compile(
    r'"(token|access_token|auth_token|jwt|id_token|bearerToken|'
    r'authentication|sessionToken|session_token)"\s*:',
    re.IGNORECASE,
)

# JWT shape detection (anywhere in response body)
_JWT_BODY_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

# Auth-shaped cookie names
_AUTH_COOKIE_RE = re.compile(r"(token|jwt|session|auth|sid|sso|jsessionid|connect\.sid)", re.I)


@dataclass
class AuthBypassFinding:
    endpoint: str
    method: str
    field: str               # which body field was attacked (email/username/login)
    payload: str
    verdict: str             # confirmed | likely
    confidence: float
    evidence: str
    response_status: int = 0
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "field": self.field,
            "payload": self.payload,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "response_status": self.response_status,
            "response_snippet": self.response_snippet[:300],
        }


@dataclass
class AuthBypassResult:
    endpoints_tested: int = 0
    payloads_sent: int = 0
    findings: list[AuthBypassFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[AuthBypassFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "payloads_sent": self.payloads_sent,
            "confirmed": len(self.confirmed),
            "findings": [f.to_dict() for f in self.findings],
        }


class AuthBypassProbe:
    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 10.0,
        max_payloads: int = 80,
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.max_payloads = max_payloads

    async def run(self, classifier_result, target: Optional[str] = None) -> AuthBypassResult:
        """Iterate Cat.AUTH endpoints + known login paths, fuzz with auth-bypass payloads."""
        from classifier import Cat
        from auto_auth import _LOGIN_PATHS
        result = AuthBypassResult()

        # Candidates: classified Cat.AUTH endpoints OR endpoints whose path matches login pattern
        seen: set[str] = set()
        candidates: list[tuple[str, str]] = []  # (url, method)

        # 1. From classifier
        for f in classifier_result.request_findings:
            key = f"{f.method} {f.url}"
            if key in seen:
                continue
            is_auth_cat = Cat.AUTH in f.categories
            path = urlparse(f.url).path
            is_login_path = _LOGIN_PATH_RE.search(path) is not None
            if (is_auth_cat or is_login_path) and f.method in ("POST", "PUT"):
                seen.add(key)
                candidates.append((f.url, f.method))

        # 2. Probe known login paths from auto_auth's wordlist (crawler often misses
        #    these because they're only hit via JS form submit, not links)
        if target:
            for path in _LOGIN_PATHS:
                url = target.rstrip("/") + path
                key = f"POST {url}"
                if key not in seen:
                    seen.add(key)
                    candidates.append((url, "POST"))

        result.endpoints_tested = len(candidates)
        if not candidates:
            return result

        bypass_payloads = _payloads.sql_auth_bypass()[:self.max_payloads]

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        ) as client:
            for url, method in candidates:
                findings = await self._probe_endpoint(client, url, method, bypass_payloads)
                result.findings.extend(findings)
                result.payloads_sent += len(bypass_payloads) * 3  # ~3 field-shape variants per payload
        return result

    async def _probe_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        payloads_list: list[str],
    ) -> list[AuthBypassFinding]:
        # Establish baseline with junk credentials
        baseline_status = await self._baseline(client, url, method)
        if baseline_status == 0:
            return []
        # 404 / 405 = endpoint doesn't exist or doesn't accept POST — skip
        if baseline_status in (404, 405):
            return []
        # 2xx with random creds = endpoint doesn't actually auth — skip
        if baseline_status < 300:
            return []

        findings: list[AuthBypassFinding] = []
        # Try each common credential-field shape
        for cred_field in ("email", "username", "login"):
            for payload in payloads_list:
                body = {cred_field: payload, "password": "x"}
                try:
                    r = await client.request(method, url, json=body, headers=self.auth_headers)
                except httpx.HTTPError:
                    continue

                finding = self._evaluate(url, method, cred_field, payload, r, baseline_status)
                if finding:
                    findings.append(finding)
                    # Found one that works — break inner payload loop, try other fields
                    break
            # If we got a confirmed bypass for this field, no need to try more fields
            if any(f.field == cred_field and f.verdict == "confirmed" for f in findings):
                break
        return findings

    async def _baseline(self, client: httpx.AsyncClient, url: str, method: str) -> int:
        """Send junk creds to learn the failure status code."""
        for shape in (
            {"email": "hxxpsin_baseline_xyz@nowhere.invalid", "password": "wrong_pw_baseline"},
            {"username": "hxxpsin_baseline_xyz", "password": "wrong_pw_baseline"},
            {"login": "hxxpsin_baseline_xyz", "password": "wrong_pw_baseline"},
        ):
            try:
                r = await client.request(method, url, json=shape, headers=self.auth_headers)
                return r.status_code
            except httpx.HTTPError:
                continue
        return 0

    @staticmethod
    def _evaluate(
        url: str, method: str, field: str, payload: str,
        r: httpx.Response, baseline_status: int,
    ) -> Optional[AuthBypassFinding]:
        # Only flip from 4xx baseline to 2xx is interesting
        if not (baseline_status >= 400 and 200 <= r.status_code < 300):
            return None

        text = r.text[:3000]
        # 1. JWT in body — strongest signal
        if _JWT_BODY_RE.search(text):
            return AuthBypassFinding(
                endpoint=url, method=method, field=field, payload=payload,
                verdict="confirmed", confidence=0.95,
                evidence=(f"AUTH BYPASS: payload {payload!r} in {field} field returned status "
                          f"{r.status_code} (baseline {baseline_status}) with JWT in response body"),
                response_status=r.status_code,
                response_snippet=text[:300],
            )
        # 2. Auth-token field name in body
        if _AUTH_SIGNAL_RE.search(text):
            return AuthBypassFinding(
                endpoint=url, method=method, field=field, payload=payload,
                verdict="confirmed", confidence=0.9,
                evidence=(f"AUTH BYPASS: payload {payload!r} in {field} field returned status "
                          f"{r.status_code} (baseline {baseline_status}) with auth-token field in body"),
                response_status=r.status_code,
                response_snippet=text[:300],
            )
        # 3. Auth-shaped Set-Cookie
        for cookie_name in r.cookies.keys():
            if _AUTH_COOKIE_RE.search(cookie_name):
                return AuthBypassFinding(
                    endpoint=url, method=method, field=field, payload=payload,
                    verdict="confirmed", confidence=0.88,
                    evidence=(f"AUTH BYPASS: payload {payload!r} in {field} field returned status "
                              f"{r.status_code} (baseline {baseline_status}) with auth cookie {cookie_name}"),
                    response_status=r.status_code,
                    response_snippet=text[:300],
                )
        # 4. Status flip without obvious token — still suspicious
        return AuthBypassFinding(
            endpoint=url, method=method, field=field, payload=payload,
            verdict="likely", confidence=0.6,
            evidence=(f"Suspicious status flip: payload {payload!r} in {field} field returned "
                      f"status {r.status_code} (baseline {baseline_status}) — manual validation required"),
            response_status=r.status_code,
            response_snippet=text[:300],
        )
