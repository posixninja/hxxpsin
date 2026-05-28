"""Tests for the outbound LLM gateway.

Verifies that ServusLLMClient.generate hits the right URL with the
right headers and body, and that the response shape is correctly
parsed. Uses a fake aiohttp/httpx transport — does not touch the
network.

Run:  python -m pytest tests/test_servus_client.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from servus_client import ServusClientError, ServusLLMClient, ServusReply  # noqa: E402


def _make_transport(responder):
    """Return an httpx MockTransport that calls `responder(request) -> (status, json)`."""

    def handler(request: httpx.Request) -> httpx.Response:
        status, payload = responder(request)
        return httpx.Response(status, json=payload)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_generate_posts_to_chat_complete_with_bearer(monkeypatch):
    captured = {}

    def responder(req: httpx.Request):
        captured["url"] = str(req.url)
        captured["auth"] = req.headers.get("authorization")
        captured["body"] = json.loads(req.content.decode())
        return (
            200,
            {
                "reply": "hi",
                "tool_calls": [],
                "provider": "claude",
                "model": "claude-opus-4-7",
                "cognitive_session_id": "sess-1",
                "cognitive_decision": {"kind": "allow"},
                "crs": 0.9,
                "delegation_chain": ["alice", "hxxpsin"],
            },
        )

    # Monkeypatch httpx.AsyncClient with one using our mock transport.
    real_async_client = httpx.AsyncClient

    def patched(**kwargs):
        kwargs["transport"] = _make_transport(responder)
        return real_async_client(**kwargs)

    monkeypatch.setattr("servus_client.httpx.AsyncClient", patched)

    client = ServusLLMClient(
        base_url="http://servus.local:9999",
        token="tok123",
        initiator_subject="alice",
        default_provider="claude",
    )
    reply = await client.generate(
        messages=[{"role": "user", "content": "ping"}], system="be brief"
    )

    assert isinstance(reply, ServusReply)
    assert reply.reply == "hi"
    assert reply.allowed is True
    assert reply.cognitive_session_id == "sess-1"
    assert captured["url"] == "http://servus.local:9999/v1/chat/complete"
    assert captured["auth"] == "Bearer tok123"
    assert captured["body"]["initiator_subject"] == "alice"
    assert captured["body"]["provider"] == "claude"
    assert captured["body"]["system_prompt"] == "be brief"
    assert captured["body"]["messages"] == [{"role": "user", "content": "ping"}]


@pytest.mark.asyncio
async def test_generate_propagates_http_4xx_as_client_error(monkeypatch):
    def responder(req: httpx.Request):
        return (401, {"error": "unauthorized"})

    real_async_client = httpx.AsyncClient

    def patched(**kwargs):
        kwargs["transport"] = _make_transport(responder)
        return real_async_client(**kwargs)

    monkeypatch.setattr("servus_client.httpx.AsyncClient", patched)
    client = ServusLLMClient(base_url="http://x", token="", initiator_subject="alice")
    with pytest.raises(ServusClientError) as exc:
        await client.generate(messages=[{"role": "user", "content": "hi"}])
    assert "unauthorized" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_session_id_is_remembered_across_calls(monkeypatch):
    state = {"call": 0}

    def responder(req: httpx.Request):
        state["call"] += 1
        state["last_session"] = json.loads(req.content.decode()).get("session_id")
        return (
            200,
            {
                "reply": "ok",
                "tool_calls": [],
                "provider": "claude",
                "model": "claude-opus-4-7",
                "cognitive_session_id": "stable-sid",
                "cognitive_decision": {"kind": "allow"},
                "delegation_chain": [],
            },
        )

    real_async_client = httpx.AsyncClient

    def patched(**kwargs):
        kwargs["transport"] = _make_transport(responder)
        return real_async_client(**kwargs)

    monkeypatch.setattr("servus_client.httpx.AsyncClient", patched)
    client = ServusLLMClient(base_url="http://x", token="t", initiator_subject="a")
    await client.generate(messages=[{"role": "user", "content": "1"}])
    await client.generate(messages=[{"role": "user", "content": "2"}])
    assert state["call"] == 2
    # Second call should re-send the session_id we picked up from call 1
    assert state["last_session"] == "stable-sid"
