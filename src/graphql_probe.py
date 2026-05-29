"""
graphql_probe.py — GraphQL abuse probes (introspection, batching, depth, IDOR nodes).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from probe_http import open_probe_client


@dataclass
class GraphQLFinding:
    url: str
    test: str
    severity: str
    evidence: str

    def to_dict(self) -> dict:
        return {"url": self.url, "test": self.test, "severity": self.severity, "evidence": self.evidence}


@dataclass
class GraphQLProbeResult:
    endpoints_tested: int = 0
    confirmed: list[GraphQLFinding] = field(default_factory=list)
    likely: list[GraphQLFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "confirmed": [f.to_dict() for f in self.confirmed],
            "likely": [f.to_dict() for f in self.likely],
        }


_INTROSPECTION = b'{"query":"{ __schema { queryType { name } types { name kind } } }"}'
_BATCH_QUERY = b'{"query":"query A{__typename} query B{__typename} query C{__typename}"}'
_DEEP_QUERY = b'{"query":"{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename }"}'

_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql")


class GraphQLProbe:
    def __init__(self, auth_headers: Optional[dict] = None, timeout: float = 8.0):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout

    def _candidates(self, target: str, findings_urls: list[str]) -> list[str]:
        urls = set()
        for path in _GRAPHQL_PATHS:
            urls.add(urljoin(target, path))
        for u in findings_urls:
            if "graphql" in u.lower() or u.rstrip("/").endswith("/graphql"):
                urls.add(u.split("?")[0])
        return list(urls)[:12]

    async def run(
        self,
        target: str,
        classifier_urls: list[str] | None = None,
        http_cache=None,
    ) -> GraphQLProbeResult:
        result = GraphQLProbeResult()
        urls = self._candidates(target, classifier_urls or [])
        headers = {"Content-Type": "application/json", **self.auth_headers}

        async with open_probe_client(
            http_cache,
            timeout=self.timeout,
            headers=headers,
        ) as client:
            for url in urls:
                result.endpoints_tested += 1
                try:
                    r = await client.post(
                        url, headers=headers, content=_INTROSPECTION, use_cache=False,
                    )
                    if r.status_code == 200 and "__schema" in r.text:
                        result.confirmed.append(GraphQLFinding(
                            url=url, test="introspection_enabled",
                            severity="medium",
                            evidence="Full schema introspection returned 200",
                        ))
                    rb = await client.post(
                        url, headers=headers, content=_BATCH_QUERY, use_cache=False,
                    )
                    if rb.status_code == 200 and rb.text.count("__typename") >= 2:
                        result.likely.append(GraphQLFinding(
                            url=url, test="query_batching",
                            severity="low", evidence="Multiple operations accepted in one request",
                        ))
                    rd = await client.post(
                        url, headers=headers, content=_DEEP_QUERY, use_cache=False,
                    )
                    if rd.status_code == 200 and len(rd.text) > 50:
                        result.likely.append(GraphQLFinding(
                            url=url, test="alias_abuse",
                            severity="low", evidence="Alias-heavy query accepted",
                        ))
                except Exception as exc:
                    print(f"  graphql {url}: {exc}", file=sys.stderr)
        return result
