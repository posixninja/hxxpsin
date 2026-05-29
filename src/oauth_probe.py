"""
oauth_probe.py — OAuth/OIDC surface checks (redirect_uri, state, implicit flow leakage).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlencode

from probe_http import open_probe_client


@dataclass
class OAuthFinding:
    url: str
    test: str
    severity: str
    evidence: str

    def to_dict(self) -> dict:
        return {"url": self.url, "test": self.test, "severity": self.severity, "evidence": self.evidence}


@dataclass
class OAuthProbeResult:
    endpoints_tested: int = 0
    confirmed: list[OAuthFinding] = field(default_factory=list)
    likely: list[OAuthFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "confirmed": [f.to_dict() for f in self.confirmed],
            "likely": [f.to_dict() for f in self.likely],
        }


_OAUTH_PATH_RE = re.compile(
    r"(/oauth2?/|/authorize|/token|/\.well-known/openid-configuration|/login/oauth)",
    re.I,
)


class OAuthProbe:
    def __init__(self, auth_headers: Optional[dict] = None, timeout: float = 8.0):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout

    def _authorize_urls(self, target: str, finding_urls: list[str]) -> list[str]:
        urls = set()
        for u in finding_urls:
            if _OAUTH_PATH_RE.search(u):
                urls.add(u.split("?")[0] if "authorize" in u.lower() else u)
        for path in ("/oauth/authorize", "/oauth2/authorize", "/authorize", "/login/oauth/authorize"):
            urls.add(urljoin(target, path))
        return list(urls)[:10]

    async def run(
        self,
        target: str,
        finding_urls: list[str] | None = None,
        http_cache=None,
    ) -> OAuthProbeResult:
        result = OAuthProbeResult()
        urls = self._authorize_urls(target, finding_urls or [])
        evil_redirect = "https://evil.hxxpsin.oauth.test/callback"

        async with open_probe_client(
            http_cache,
            timeout=self.timeout,
            follow_redirects=False,
            headers=self.auth_headers,
        ) as client:
            for base in urls:
                result.endpoints_tested += 1
                params = {
                    "response_type": "code",
                    "client_id": "hxxpsin-probe",
                    "redirect_uri": evil_redirect,
                    "scope": "openid",
                    "state": "probe",
                }
                url = base + ("&" if "?" in base else "?") + urlencode(params)
                try:
                    r = await client.get(url, use_cache=False)
                    loc = r.headers.get("location", "")
                    if evil_redirect in loc or "evil.hxxpsin" in r.text:
                        result.confirmed.append(OAuthFinding(
                            url=base, test="redirect_uri_bypass",
                            severity="high",
                            evidence=f"External redirect accepted (status {r.status_code})",
                        ))
                    params2 = {**params, "response_type": "token"}
                    url2 = base + ("&" if "?" in base else "?") + urlencode(params2)
                    r2 = await client.get(url2, use_cache=False)
                    if "access_token=" in (r2.headers.get("location") or "") or "access_token" in r2.text[:500]:
                        result.likely.append(OAuthFinding(
                            url=base, test="implicit_flow",
                            severity="medium", evidence="Token may be returned in redirect fragment",
                        ))
                    if r.status_code in (200, 302) and "state" not in (r.text or "").lower() and r.status_code == 200:
                        result.likely.append(OAuthFinding(
                            url=base, test="missing_state_hint",
                            severity="low", evidence="Authorize endpoint reachable; verify PKCE/state manually",
                        ))
                except Exception as exc:
                    print(f"  oauth {base}: {exc}", file=sys.stderr)
        return result
