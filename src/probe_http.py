"""
probe_http.py — Shared HTTP access for probes via HttpCache or fallback httpx.

When PipelineState carries an HttpCache from _ScanContext, probes should use
CacheBackedClient so identical requests dedupe and scope/rate limits apply.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx

from http_cache import CachedResponse, HttpCache


def cached_to_httpx_response(cached: CachedResponse) -> httpx.Response:
    return httpx.Response(
        status_code=cached.status_code,
        headers=cached.headers,
        content=cached.content,
        request=httpx.Request("GET", "http://probe-http.local/"),
    )


class CacheBackedClient:
    """Minimal httpx.AsyncClient-compatible facade over HttpCache."""

    def __init__(self, cache: HttpCache, default_headers: Optional[dict] = None):
        self._cache = cache
        self._default_headers = dict(default_headers or {})

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = {**self._default_headers, **(kwargs.get("headers") or {})}
        content = kwargs.get("content")
        if content is None and kwargs.get("json") is not None:
            content = json.dumps(kwargs["json"]).encode()
            headers.setdefault("Content-Type", "application/json")
        if isinstance(content, str):
            content = content.encode()
        follow_redirects = kwargs.get("follow_redirects", True)
        # Mutations default to no cache reuse unless explicitly cached
        use_cache = kwargs.get("use_cache")
        if use_cache is None:
            use_cache = method.upper() in ("GET", "HEAD", "OPTIONS")
        cached = await self._cache.request(
            method,
            url,
            headers=headers,
            content=content,
            use_cache=use_cache,
            follow_redirects=follow_redirects,
        )
        return cached_to_httpx_response(cached)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        return None

    async def __aenter__(self) -> "CacheBackedClient":
        return self

    async def __aexit__(self, *args) -> None:
        return None


class _HttpxProbeWrapper:
    """Strip cache-only kwargs before delegating to httpx."""

    def __init__(self, client: httpx.AsyncClient):
        self._client = client

    def _strip(self, kwargs: dict) -> dict:
        return {k: v for k, v in kwargs.items() if k != "use_cache"}

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        return await self._client.request(method, url, **self._strip(kwargs))

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self._client.get(url, **self._strip(kwargs))

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self._client.post(url, **self._strip(kwargs))

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "_HttpxProbeWrapper":
        return self

    async def __aexit__(self, *args) -> None:
        await self._client.__aexit__(*args)


ProbeClient = CacheBackedClient | _HttpxProbeWrapper


@asynccontextmanager
async def open_probe_client(
    http_cache: Optional[HttpCache],
    *,
    timeout: float = 8.0,
    verify: bool = False,
    follow_redirects: bool = True,
    headers: Optional[dict] = None,
) -> AsyncIterator[ProbeClient]:
    """Yield a probe HTTP client — shared cache when available."""
    if http_cache is not None:
        yield CacheBackedClient(http_cache, default_headers=headers)
    else:
        async with httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers=headers,
        ) as client:
            yield _HttpxProbeWrapper(client)
