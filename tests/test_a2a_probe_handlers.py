"""Tests for the directly-wired A2A probe skill handlers.

Verifies that submitting a probe_* task via the JSON-RPC entry routes
through the matching direct handler (not the scan-delegated stub).
Each test uses an unreachable URL so the probe completes quickly with
connection errors — we only assert that the right code path ran and
the response shape is probe-specific, not scan-delegation pointer.

Run:  python -m pytest tests/test_a2a_probe_handlers.py -v
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


def _submit(skill_id: str, params: dict, agent_id: str = "probe") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": skill_id,
        "method": "tasks/send",
        "params": {
            "agentId": agent_id,
            "skillId": skill_id,
            "params": params,
            "metadata": {"initiatorSubject": "alice"},
        },
    }


async def _wait_terminal(client, task_id: str, deadline_s: float = 10.0) -> dict:
    """Poll a task until terminal or deadline."""
    end = asyncio.get_event_loop().time() + deadline_s
    while asyncio.get_event_loop().time() < end:
        await asyncio.sleep(0.1)
        rec = await (await client.get(f"/tasks/{task_id}")).json()
        if rec["state"] in ("completed", "failed", "canceled"):
            return rec
    raise TimeoutError(f"task {task_id} didn't settle in {deadline_s}s")


@pytest.mark.asyncio
async def test_direct_handlers_registered():
    """Confirm the new direct probes are in the registry under agent=probe."""
    skills = {s.skill_id for s in REGISTRY.skills_for("probe")}
    for sid in (
        "probe_open_redirect",
        "probe_jwt",
        "probe_crlf",
        "probe_desync",
        "probe_nosql",
        # pre-existing direct handlers
        "probe_cloud_metadata",
        "probe_scm_exposure",
        "probe_ct_confusion",
    ):
        assert sid in skills, f"missing direct skill {sid}"


@pytest.mark.asyncio
async def test_probe_jwt_schema_has_token_param(client):
    """The agent card should advertise `token` for probe_jwt, not generic url-only."""
    resp = await client.get("/.well-known/agent.json")
    card = await resp.json()
    probe_skills = {s["id"]: s for a in card["agents"] if a["id"] == "probe" for s in a["skills"]}
    jwt = probe_skills["probe_jwt"]
    assert "token" in jwt["inputSchema"]["properties"]


@pytest.mark.asyncio
async def test_probe_desync_schema_has_urls(client):
    resp = await client.get("/.well-known/agent.json")
    card = await resp.json()
    probe_skills = {s["id"]: s for a in card["agents"] if a["id"] == "probe" for s in a["skills"]}
    assert "urls" in probe_skills["probe_desync"]["inputSchema"]["properties"]


@pytest.mark.asyncio
async def test_probe_open_redirect_returns_probe_shape_not_scan_pointer(client):
    """When the direct handler runs, the output should look like an
    OpenRedirectResult, NOT a {scan_id, family, next_steps} pointer."""
    resp = await client.post(
        "/", json=_submit("probe_open_redirect", {"url": "http://127.0.0.1:1/r"})
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id, deadline_s=15.0)
    assert rec["state"] == "completed", rec
    # The scan-delegated stub returns these specific keys; if any are
    # present, the direct handler wasn't invoked.
    out = rec["output"]
    assert "scan_id" not in out
    assert "next_steps" not in out
    # An OpenRedirectResult.to_dict carries a "findings" key.
    assert "findings" in out


@pytest.mark.asyncio
async def test_probe_jwt_requires_token_when_no_auth(client):
    """Without a token AND without an auth_file, probe_jwt returns a clean error."""
    resp = await client.post(
        "/", json=_submit("probe_jwt", {"url": "http://127.0.0.1:1/api"})
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id)
    assert rec["state"] == "completed"
    assert "error" in rec["output"]
    assert "JWT" in rec["output"]["error"] or "token" in rec["output"]["error"].lower()


@pytest.mark.asyncio
async def test_probe_jwt_with_token_runs_probe(client):
    """Supplying a token should make the probe attempt attacks (won't reach
    the unreachable host but will produce a JWTAttackResult dict)."""
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"
    resp = await client.post(
        "/", json=_submit("probe_jwt", {"url": "http://127.0.0.1:1/api", "token": token})
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id, deadline_s=15.0)
    # The probe may complete or fail depending on network; we just need to
    # see it actually ran (output has probe-specific keys, not scan-delegate).
    out = rec.get("output") or {}
    assert "scan_id" not in out
    # JWTAttackResult.to_dict carries "findings" key.
    if rec["state"] == "completed":
        assert "findings" in out or "error" in out


@pytest.mark.asyncio
async def test_probe_crlf_returns_probe_shape(client):
    resp = await client.post(
        "/", json=_submit("probe_crlf", {"url": "http://127.0.0.1:1/page"})
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id, deadline_s=15.0)
    assert rec["state"] == "completed"
    out = rec["output"]
    assert "scan_id" not in out
    # CRLFResult.to_dict carries "urls_tested" key.
    assert "urls_tested" in out or "findings" in out


@pytest.mark.asyncio
async def test_probe_desync_passes_extra_urls(client):
    """probe_desync should accept the optional `urls` list without errors."""
    resp = await client.post(
        "/",
        json=_submit(
            "probe_desync",
            {"url": "http://127.0.0.1:1/a", "urls": ["http://127.0.0.1:1/b"]},
        ),
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id, deadline_s=15.0)
    assert rec["state"] == "completed"
    out = rec["output"]
    assert "scan_id" not in out


@pytest.mark.asyncio
async def test_idor_remains_scan_delegated(client):
    """probe_idor is NOT in _DIRECT_HANDLERS — it should still return a
    scan-delegation pointer, not a probe result."""
    resp = await client.post(
        "/", json=_submit("probe_idor", {"url": "http://127.0.0.1:1/users/1"})
    )
    body = await resp.json()
    task_id = body["result"]["id"]
    rec = await _wait_terminal(client, task_id, deadline_s=10.0)
    assert rec["state"] == "completed"
    out = rec["output"]
    assert "scan_id" in out  # marks scan-delegated stub
    assert "next_steps" in out
