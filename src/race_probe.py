"""
race_probe.py — Concurrency / race-condition confirmation for classifier-flagged paths.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from typing import Optional

from classifier import Cat
from probe_http import open_probe_client


@dataclass
class RaceFinding:
    url: str
    method: str
    evidence: str
    responses_differ: bool

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "evidence": self.evidence, "responses_differ": self.responses_differ,
        }


@dataclass
class RaceProbeResult:
    endpoints_tested: int = 0
    confirmed: list[RaceFinding] = field(default_factory=list)
    likely: list[RaceFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "confirmed": [f.to_dict() for f in self.confirmed],
            "likely": [f.to_dict() for f in self.likely],
        }


_BURST = 8


class RaceProbe:
    def __init__(self, auth_headers: Optional[dict] = None, timeout: float = 8.0):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout

    def _targets(self, classifier_result) -> list[tuple[str, str, Optional[str]]]:
        out = []
        for f in classifier_result.request_findings:
            if Cat.RACE not in f.categories:
                continue
            out.append((f.method, f.url, f.body))
        return out[:15]

    async def run(self, classifier_result, http_cache=None) -> RaceProbeResult:
        result = RaceProbeResult()
        targets = self._targets(classifier_result)
        if not targets:
            return result

        async with open_probe_client(
            http_cache,
            timeout=self.timeout,
            headers=self.auth_headers,
        ) as client:
            for method, url, body in targets:
                result.endpoints_tested += 1
                headers = dict(self.auth_headers)
                if body:
                    headers.setdefault("Content-Type", "application/json")
                body_b = (body or "{}").encode() if isinstance(body, str) else (body or b"{}")

                async def _one() -> tuple[int, int]:
                    try:
                        if method.upper() == "POST":
                            r = await client.post(
                                url, headers=headers, content=body_b, use_cache=False,
                            )
                        else:
                            r = await client.request(
                                method, url, headers=headers, use_cache=False,
                            )
                        return r.status_code, len(r.content)
                    except Exception:
                        return 0, 0

                try:
                    pairs = await asyncio.gather(*[_one() for _ in range(_BURST)])
                    statuses = {p[0] for p in pairs}
                    lengths = {p[1] for p in pairs}
                    differ = len(statuses) > 1 or (max(lengths) - min(lengths) > 32 if lengths else False)
                    if differ:
                        result.confirmed.append(RaceFinding(
                            url=url, method=method,
                            evidence=f"Burst {_BURST}: status set {statuses}, length spread",
                            responses_differ=True,
                        ))
                    elif 200 in statuses and len(statuses) == 1:
                        result.likely.append(RaceFinding(
                            url=url, method=method,
                            evidence=f"Burst {_BURST}: uniform {statuses[0]} — manual race tooling advised",
                            responses_differ=False,
                        ))
                except Exception as exc:
                    print(f"  race {url}: {exc}", file=sys.stderr)
        return result
