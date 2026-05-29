"""Tests for HttpCache scope and dedup."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from http_cache import HttpCache, HttpGovernorConfig, ScopeGuard


def test_scope_guard_allows_target_host():
    g = ScopeGuard("https://ctf.corp.local", HttpGovernorConfig())
    assert g.allowed("https://ctf.corp.local/api/users")
    assert not g.allowed("https://evil.com/")


@pytest.mark.asyncio
async def test_http_cache_dedup():
    calls = []

    class FakeResp:
        status_code = 200
        headers = {"content-type": "text/plain"}
        content = b"ok"

    class FakeClient:
        async def request(self, method, url, **kw):
            calls.append((method, url))
            return FakeResp()

        async def aclose(self):
            pass

    cache = HttpCache("https://t.local", HttpGovernorConfig(requests_per_second=100))
    cache._client = FakeClient()
    r1 = await cache.request("GET", "https://t.local/a")
    r2 = await cache.request("GET", "https://t.local/a")
    assert r1.content == r2.content
    assert len(calls) == 1
