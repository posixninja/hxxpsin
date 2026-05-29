"""Race probe unit tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from classifier import Cat, ClassifierResult, Finding
from race_probe import RaceProbe


def _race_finding(url: str = "https://t.local/api/checkout") -> Finding:
    return Finding(
        method="POST",
        url=url,
        score=40,
        categories=[Cat.RACE],
        evidence=["race-condition-prone path"],
    )


def _empty_classifier(**kw) -> ClassifierResult:
    return ClassifierResult(
        request_findings=kw.get("request_findings", []),
        websocket_findings=[],
        js_route_findings=[],
        js_constants=[],
        by_category=kw.get("by_category", {}),
    )


@pytest.mark.asyncio
async def test_race_no_targets():
    cr = _empty_classifier()
    r = await RaceProbe().run(cr)
    assert r.endpoints_tested == 0


@pytest.mark.asyncio
async def test_race_finds_targets_without_network():
    f = _race_finding()
    cr = _empty_classifier(request_findings=[f], by_category={Cat.RACE: [f]})
    # Will attempt network; may return likely/confirmed or empty on unreachable host
    r = await RaceProbe(timeout=2.0).run(cr)
    assert r.endpoints_tested == 1
