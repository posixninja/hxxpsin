"""OAuth probe unit tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oauth_probe import OAuthProbe


@pytest.mark.asyncio
async def test_oauth_probe_runs_candidates():
    r = await OAuthProbe(timeout=2.0).run("https://invalid-oauth-target.test", [])
    assert r.endpoints_tested >= 1
