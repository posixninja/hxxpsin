"""Tests for the A2A payload agent skills.

Exercises the stateless ``payload_encode_variants`` end-to-end via
JSON-RPC, plus the start/status/stop lifecycle of
``payload_callback_server``. ``payload_tunnel`` is registration-only —
spinning up a real cloudflared/ngrok process is out of scope for a unit
test.

Run:  python -m pytest tests/test_a2a_payload_skills.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

os.environ["HXXPSIN_COGNITION_INSECURE"] = "1"

from a2a_server.app import build_app  # noqa: E402
from a2a_server.skills import REGISTRY  # noqa: E402


@pytest.fixture
async def client():
    app = build_app(public_url="http://test.local:9851")
    async with TestClient(TestServer(app)) as c:
        yield c


def _submit(skill_id: str, params: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": skill_id,
        "method": "tasks/send",
        "params": {
            "agentId": "payload",
            "skillId": skill_id,
            "params": params,
            "metadata": {"initiatorSubject": "alice"},
        },
    }


async def _wait_terminal(client, task_id: str, deadline_s: float = 10.0) -> dict:
    end = asyncio.get_event_loop().time() + deadline_s
    while asyncio.get_event_loop().time() < end:
        await asyncio.sleep(0.05)
        rec = await (await client.get(f"/tasks/{task_id}")).json()
        if rec["state"] in ("completed", "failed", "canceled"):
            return rec
    raise TimeoutError(f"task {task_id} didn't settle in {deadline_s}s")


def test_payload_skills_registered():
    ids = {s.skill_id for s in REGISTRY.skills_for("payload")}
    assert ids == {"payload_encode_variants", "payload_callback_server", "payload_tunnel"}


@pytest.mark.asyncio
async def test_encode_variants_returns_variants(client):
    resp = await client.post(
        "/",
        json=_submit("payload_encode_variants", {"value": "abc"}),
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id)
    assert rec["state"] == "completed"
    out = rec["output"]
    assert "variants" in out
    assert isinstance(out["variants"], list)
    assert len(out["variants"]) > 0
    assert "schemes_applied" in out


@pytest.mark.asyncio
async def test_encode_variants_respects_scheme_subset(client):
    resp = await client.post(
        "/",
        json=_submit("payload_encode_variants", {"value": "abc", "schemes": ["url"]}),
    )
    task_id = (await resp.json())["result"]["id"]
    rec = await _wait_terminal(client, task_id)
    assert rec["state"] == "completed"
    assert rec["output"]["schemes_applied"] == ["url"]


@pytest.mark.asyncio
async def test_callback_server_lifecycle(client):
    # 1. start
    start = await client.post("/", json=_submit("payload_callback_server", {"action": "start"}))
    start_body = await start.json()
    rec = await _wait_terminal(client, start_body["result"]["id"])
    assert rec["state"] == "completed"
    server_id = rec["output"]["server_id"]
    local_url = rec["output"]["local_url"]
    assert local_url.startswith("http://127.0.0.1:")

    # 2. mint a correlation token
    mint = await client.post(
        "/",
        json=_submit("payload_callback_server", {"action": "mint_token", "server_id": server_id}),
    )
    mrec = await _wait_terminal(client, (await mint.json())["result"]["id"])
    assert mrec["state"] == "completed"
    assert mrec["output"]["token"].startswith("probe-")

    # 3. status
    stat = await client.post(
        "/",
        json=_submit("payload_callback_server", {"action": "status", "server_id": server_id}),
    )
    srec = await _wait_terminal(client, (await stat.json())["result"]["id"])
    assert srec["state"] == "completed"
    assert srec["output"]["server_id"] == server_id
    assert srec["output"]["hits_total"] == 0

    # 4. stop
    stop = await client.post(
        "/",
        json=_submit("payload_callback_server", {"action": "stop", "server_id": server_id}),
    )
    drec = await _wait_terminal(client, (await stop.json())["result"]["id"])
    assert drec["state"] == "completed"
    assert drec["output"]["stopped"] is True


@pytest.mark.asyncio
async def test_callback_server_status_rejects_unknown_id(client):
    resp = await client.post(
        "/",
        json=_submit("payload_callback_server", {"action": "status", "server_id": "deadbeef"}),
    )
    rec = await _wait_terminal(client, (await resp.json())["result"]["id"])
    assert rec["state"] == "completed"
    assert "error" in rec["output"]


@pytest.mark.asyncio
async def test_tunnel_advertised(client):
    """Registration check only — actually starting a cloudflared tunnel
    requires the binary and external network."""
    card = await (await client.get("/.well-known/agent.json")).json()
    payload = next(a for a in card["agents"] if a["id"] == "payload")
    tunnel = next(s for s in payload["skills"] if s["id"] == "payload_tunnel")
    assert tunnel["inputSchema"]["properties"]["backend"]["enum"] == [
        "cloudflared", "ngrok", "static",
    ]
