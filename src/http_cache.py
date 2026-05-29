"""
http_cache.py — Shared HTTP response cache, in-flight dedup, rate limit, scope guard.

Wired through _ScanContext so all probes reuse one polite httpx layer.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


def _cache_key(method: str, url: str, headers: dict, body: bytes | None) -> str:
    h = hashlib.sha256()
    h.update(method.upper().encode())
    h.update(url.encode())
    for k in sorted(headers.keys()):
        h.update(k.lower().encode())
        h.update(str(headers[k]).encode())
    if body:
        h.update(body)
    return h.hexdigest()


@dataclass
class HttpGovernorConfig:
    max_concurrent: int = 12
    requests_per_second: float = 20.0
    allow_hosts: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=list)


class ScopeGuard:
    """Allow only in-scope hosts/paths."""

    def __init__(self, target_url: str, cfg: HttpGovernorConfig):
        parsed = urlparse(target_url)
        self._default_host = (parsed.hostname or "").lower()
        self._allow = {h.lower() for h in (cfg.allow_hosts or [])}
        if self._default_host:
            self._allow.add(self._default_host)
        self._deny_res = [re.compile(p) for p in (cfg.deny_paths or [])]

    def allowed(self, url: str) -> bool:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if self._allow and host not in self._allow:
            return False
        path = p.path or "/"
        for rx in self._deny_res:
            if rx.search(path):
                return False
        return True


class RateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / max(rps, 0.1)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


@dataclass
class CachedResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes
    elapsed_ms: float


class HttpCache:
    """In-memory cache + in-flight deduplication for httpx requests."""

    def __init__(
        self,
        target_url: str,
        cfg: Optional[HttpGovernorConfig] = None,
        timeout: float = 8.0,
        verify: bool = False,
    ):
        self.cfg = cfg or HttpGovernorConfig()
        self.scope = ScopeGuard(target_url, self.cfg)
        self.rate = RateLimiter(self.cfg.requests_per_second)
        self._cache: dict[str, CachedResponse] = {}
        self._inflight: dict[str, asyncio.Future] = {}
        self._sem = asyncio.Semaphore(self.cfg.max_concurrent)
        self._client: Optional[httpx.AsyncClient] = None
        self._timeout = timeout
        self._verify = verify

    async def __aenter__(self) -> "HttpCache":
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            verify=self._verify,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("HttpCache not entered — use async with")
        return self._client

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        content: bytes | None = None,
        use_cache: bool = True,
        follow_redirects: bool = True,
    ) -> CachedResponse:
        if not self.scope.allowed(url):
            raise PermissionError(f"out of scope: {url}")

        hdrs = dict(headers or {})
        key = _cache_key(method, url, hdrs, content)

        if use_cache and key in self._cache:
            return self._cache[key]

        if key in self._inflight:
            return await self._inflight[key]

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._inflight[key] = fut

        async def _do() -> CachedResponse:
            await self.rate.acquire()
            async with self._sem:
                t0 = time.monotonic()
                resp = await self.client.request(
                    method, url, headers=hdrs, content=content,
                    follow_redirects=follow_redirects,
                )
                elapsed = (time.monotonic() - t0) * 1000.0
                cached = CachedResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    content=resp.content,
                    elapsed_ms=elapsed,
                )
                if use_cache:
                    self._cache[key] = cached
                return cached

        try:
            result = await _do()
            fut.set_result(result)
            return result
        except Exception as exc:
            fut.set_exception(exc)
            raise
        finally:
            self._inflight.pop(key, None)

    def stats(self) -> dict:
        return {"cached_entries": len(self._cache), "inflight": len(self._inflight)}
