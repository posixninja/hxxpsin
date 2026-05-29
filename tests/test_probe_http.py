"""probe_http shared client tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from http_cache import HttpCache, HttpGovernorConfig
from probe_http import CacheBackedClient, open_probe_client


@pytest.mark.asyncio
async def test_cache_backed_client_dedup():
    calls = []

    class FakeResp:
        status_code = 200
        headers = {}
        content = b"ok"

    class FakeInner:
        async def request(self, method, url, **kw):
            calls.append(url)
            return FakeResp()

        async def aclose(self):
            pass

    cache = HttpCache("https://t.local", HttpGovernorConfig(requests_per_second=100))
    cache._client = FakeInner()
    client = CacheBackedClient(cache)
    await client.get("https://t.local/x", use_cache=True)
    await client.get("https://t.local/x", use_cache=True)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_open_probe_client_fallback():
    async with open_probe_client(None, timeout=2.0) as client:
        assert hasattr(client, "get")
