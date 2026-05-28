"""Tests for the A2A verify agent skills.

``verify_browser`` is registration-only — Playwright + Chromium aren't
guaranteed in CI. ``verify_challenge_tracker`` snapshot/diff is
exercised against the in-process snapshot registry without hitting an
external scoreboard.

Run:  python -m pytest tests/test_a2a_verify_skills.py -v
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
from a2a_server.skills import verify_challenge_tracker as ct  # noqa: E402


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
            "agentId": "verify",
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


def test_verify_skills_registered():
    ids = {s.skill_id for s in REGISTRY.skills_for("verify")}
    assert ids == {"verify_browser", "verify_challenge_tracker"}


@pytest.mark.asyncio
async def test_verify_browser_advertised(client):
    card = await (await client.get("/.well-known/agent.json")).json()
    verify = next(a for a in card["agents"] if a["id"] == "verify")
    browser = next(s for s in verify["skills"] if s["id"] == "verify_browser")
    assert browser["inputSchema"]["properties"]["verification_type"]["enum"] == ["xss", "redirect"]


@pytest.mark.asyncio
async def test_challenge_tracker_diff_with_in_memory_snapshots(client):
    """Seed the snapshot registry directly so the diff path runs without
    needing a live Juice Shop instance."""
    from challenge_tracker import ChallengeSnapshot  # type: ignore[import-not-found]

    pre = ChallengeSnapshot(target_app="juice-shop")
    pre.solved_ids = {"1", "2"}
    pre.all_challenges = {
        "1": {"name": "C1", "category": "auth", "difficulty": 1},
        "2": {"name": "C2", "category": "xss", "difficulty": 2},
        "3": {"name": "C3", "category": "ssrf", "difficulty": 4},
    }
    post = ChallengeSnapshot(target_app="juice-shop")
    post.solved_ids = {"1", "2", "3"}
    post.all_challenges = pre.all_challenges
    ct._SNAPSHOTS["pre_test"] = pre
    ct._SNAPSHOTS["post_test"] = post

    resp = await client.post(
        "/",
        json=_submit(
            "verify_challenge_tracker",
            {"action": "diff", "pre_snapshot_id": "pre_test", "post_snapshot_id": "post_test"},
        ),
    )
    rec = await _wait_terminal(client, (await resp.json())["result"]["id"])
    assert rec["state"] == "completed", rec
    out = rec["output"]
    assert out["newly_triggered"] == 1
    assert out["triggered"][0]["name"] == "C3"
    assert out["pre_solved"] == 2
    assert out["post_solved"] == 3


@pytest.mark.asyncio
async def test_challenge_tracker_diff_rejects_unknown_snapshot(client):
    resp = await client.post(
        "/",
        json=_submit(
            "verify_challenge_tracker",
            {"action": "diff", "pre_snapshot_id": "nope1", "post_snapshot_id": "nope2"},
        ),
    )
    rec = await _wait_terminal(client, (await resp.json())["result"]["id"])
    assert rec["state"] == "completed"
    assert "error" in rec["output"]
