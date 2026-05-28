"""Tests for the A2A HTTP server.

Boots the aiohttp app via ``aiohttp.test_utils`` so the wire shape
matches what servus's A2AClient actually consumes. Uses
HXXPSIN_COGNITION_INSECURE=1 to bypass cognitiond.

Run:  python -m pytest tests/test_a2a_server.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# Skip cognitiond — these tests run without any SN infrastructure.
os.environ["HXXPSIN_COGNITION_INSECURE"] = "1"

from a2a_server.app import build_app  # noqa: E402


@pytest.fixture
async def client():
    app = build_app(public_url="http://test.local:9851")
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert body["service"] == "hxxpsin-a2a"


@pytest.mark.asyncio
async def test_agent_card_has_seven_agents(client):
    resp = await client.get("/.well-known/agent.json")
    assert resp.status == 200
    card = await resp.json()
    assert card["name"] == "hxxpsin"
    agent_ids = {a["id"] for a in card["agents"]}
    assert agent_ids == {"scan", "probe", "burp", "recon", "payload", "verify", "intel"}
    # Per-agent floor — catches accidental skill removal.
    by_id = {a["id"]: a for a in card["agents"]}
    assert len(by_id["scan"]["skills"]) >= 4
    assert len(by_id["probe"]["skills"]) >= 20
    assert len(by_id["burp"]["skills"]) >= 5
    assert len(by_id["recon"]["skills"]) >= 3
    assert len(by_id["payload"]["skills"]) >= 3
    assert len(by_id["verify"]["skills"]) >= 2
    assert len(by_id["intel"]["skills"]) >= 1
    total_skills = sum(len(a["skills"]) for a in card["agents"])
    assert total_skills >= 38  # 4 + 20 + 5 + 3 + 3 + 2 + 1 = 38


@pytest.mark.asyncio
async def test_agent_card_skill_shape(client):
    resp = await client.get("/.well-known/agent.json")
    card = await resp.json()
    repeater = next(
        s for a in card["agents"] if a["id"] == "burp" for s in a["skills"] if s["id"] == "repeater"
    )
    assert "description" in repeater
    assert repeater["inputSchema"]["type"] == "object"
    assert "url" in repeater["inputSchema"]["properties"]


@pytest.mark.asyncio
async def test_unknown_skill_returns_jsonrpc_error(client):
    payload = {
        "jsonrpc": "2.0",
        "id": "t1",
        "method": "tasks/send",
        "params": {"agentId": "scan", "skillId": "no_such_skill", "params": {}},
    }
    resp = await client.post("/", json=payload)
    assert resp.status == 200
    body = await resp.json()
    assert body["id"] == "t1"
    assert "error" in body
    assert body["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_repeater_task_lifecycle_submit_poll(client):
    payload = {
        "jsonrpc": "2.0",
        "id": "rep1",
        "method": "tasks/send",
        "params": {
            "agentId": "burp",
            "skillId": "repeater",
            "params": {"url": "http://127.0.0.1:1/", "times": 1},
            "metadata": {"initiatorSubject": "alice"},
        },
    }
    resp = await client.post("/", json=payload)
    body = await resp.json()
    assert "result" in body, body
    task_id = body["result"]["id"]
    assert body["result"]["state"] == "submitted"

    # Wait briefly for the task to settle (connection-refused happens fast)
    for _ in range(20):
        await asyncio.sleep(0.05)
        poll = await client.get(f"/tasks/{task_id}")
        rec = await poll.json()
        if rec["state"] in ("completed", "failed", "canceled"):
            break
    assert rec["state"] == "completed"
    assert rec["output"]["request"]["url"] == "http://127.0.0.1:1/"
    assert len(rec["output"]["responses"]) == 1


@pytest.mark.asyncio
async def test_poll_unknown_task_returns_404(client):
    resp = await client.get("/tasks/no-such-task")
    assert resp.status == 404


@pytest.mark.asyncio
async def test_cancel_completed_task_is_idempotent(client):
    # Submit and let complete
    payload = {
        "jsonrpc": "2.0",
        "id": "c1",
        "method": "tasks/send",
        "params": {
            "agentId": "burp",
            "skillId": "repeater",
            "params": {"url": "http://127.0.0.1:1/", "times": 1},
        },
    }
    body = await (await client.post("/", json=payload)).json()
    task_id = body["result"]["id"]
    for _ in range(20):
        await asyncio.sleep(0.05)
        rec = await (await client.get(f"/tasks/{task_id}")).json()
        if rec["state"] in ("completed", "failed", "canceled"):
            break
    assert rec["state"] in ("completed", "failed")

    cancel = await client.delete(f"/tasks/{task_id}")
    assert cancel.status == 200
    # Should report the terminal state, NOT flip it to canceled
    assert (await cancel.json())["state"] == rec["state"]


@pytest.mark.asyncio
async def test_jsonrpc_non_send_method_returns_method_not_found(client):
    resp = await client.post(
        "/", json={"jsonrpc": "2.0", "id": "x", "method": "tasks/list", "params": {}}
    )
    body = await resp.json()
    assert body["error"]["code"] == -32601
