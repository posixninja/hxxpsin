"""GraphQL probe smoke tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from graphql_probe import GraphQLProbe


@pytest.mark.asyncio
async def test_graphql_no_endpoints():
    r = await GraphQLProbe().run("https://nonexistent-invalid.test", [])
    assert r.endpoints_tested >= 1
