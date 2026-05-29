"""Tests for the A2A intel agent skills.

intel_msf needs an actual MSF backend (msfrpcd or postgres). We don't
spin one up here — instead we assert registration shape and that the
skill returns a clean error when MSF is disabled in config (the default).

Run:  python -m pytest tests/test_a2a_intel_skills.py -v
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
            "agentId": "intel",
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


def test_intel_skills_registered():
    ids = {s.skill_id for s in REGISTRY.skills_for("intel")}
    assert ids == {"intel_msf"}


@pytest.mark.asyncio
async def test_intel_msf_advertised(client):
    card = await (await client.get("/.well-known/agent.json")).json()
    intel = next(a for a in card["agents"] if a["id"] == "intel")
    msf = next(s for s in intel["skills"] if s["id"] == "intel_msf")
    assert msf["inputSchema"]["required"] == ["target"]
    assert msf["inputSchema"]["properties"]["action"]["enum"] == ["augment", "sessions", "ping"]


@pytest.mark.asyncio
async def test_intel_msf_returns_disabled_error_when_unconfigured(client, tmp_path, monkeypatch):
    """The default MSFProfile has enabled=False, so the skill should
    return a clean error rather than trying to connect."""
    # Neutralize the ambient config search chain (~/.config + cwd/hxxpsin.toml)
    # so a dev machine's real [msf] block can't leak in and flip enabled=True.
    monkeypatch.setattr("auth_config.default_paths", lambda cwd=None: [])
    # Empty config — uses default MSFProfile (enabled=False)
    cfg_path = tmp_path / "hxxpsin.toml"
    cfg_path.write_text("")
    resp = await client.post(
        "/",
        json=_submit(
            "intel_msf",
            {"target": "http://ctf.corp.local", "action": "ping", "config_path": str(cfg_path)},
        ),
    )
    rec = await _wait_terminal(client, (await resp.json())["result"]["id"])
    assert rec["state"] == "completed"
    out = rec["output"]
    assert "error" in out
    assert "disabled" in out["error"].lower()
