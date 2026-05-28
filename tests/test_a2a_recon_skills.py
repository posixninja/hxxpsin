"""Tests for the A2A recon agent skills.

Exercises only the parts of recon that don't require live DNS or HTTP
against a real target:
  - registry shape + agent-card advertisement
  - schema-shape sanity for the three skills
  - encode_variants-like determinism (none here — recon is network-bound)

Live-network checks belong in an integration suite.

Run:  python -m pytest tests/test_a2a_recon_skills.py -v
"""

from __future__ import annotations

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


def test_recon_skills_registered():
    ids = {s.skill_id for s in REGISTRY.skills_for("recon")}
    assert ids == {"recon_stackprint", "recon_dns", "recon_surface_map"}


@pytest.mark.asyncio
async def test_recon_agent_advertised(client):
    card = await (await client.get("/.well-known/agent.json")).json()
    recon = next(a for a in card["agents"] if a["id"] == "recon")
    skills_by_id = {s["id"]: s for s in recon["skills"]}
    assert "recon_stackprint" in skills_by_id
    assert skills_by_id["recon_stackprint"]["inputSchema"]["required"] == ["url"]
    assert skills_by_id["recon_dns"]["inputSchema"]["required"] == ["domain"]
    assert skills_by_id["recon_surface_map"]["inputSchema"]["required"] == ["seed"]
    # dkim_selectors is array-typed
    dns_props = skills_by_id["recon_dns"]["inputSchema"]["properties"]
    assert dns_props["dkim_selectors"]["type"] == "array"
    # port_scan is enum
    sm_props = skills_by_id["recon_surface_map"]["inputSchema"]["properties"]
    assert sm_props["port_scan"]["enum"] == ["none", "web", "full"]
