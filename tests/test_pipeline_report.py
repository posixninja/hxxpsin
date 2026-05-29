"""Pipeline always-run report tests."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from classifier import ClassifierResult, Finding
from collector import Collector
from pipeline_state import PipelineState
from stackprint import StackProfile
from verifier import VerifyReport, VerifyResult


@pytest.mark.asyncio
async def test_write_pipeline_report_minimal(tmp_path):
    import main as m

    class Args:
        target = "https://example.com"
        timeout = 5.0

    finding = Finding("GET", "https://example.com/", 50, ["Injection"], [])
    result = ClassifierResult(
        request_findings=[finding],
        websocket_findings=[],
        js_route_findings=[],
        js_constants=[],
        by_category={},
    )
    col = Collector(origin="https://example.com")
    profile = StackProfile(target="https://example.com", detected={})

    ps = PipelineState(
        args=Args(),
        profile=profile,
        col=col,
        out=tmp_path,
        start=0.0,
        total_steps=10,
        step_offset=1,
        result=result,
        verify_report=VerifyReport(results=[
            VerifyResult(
                url=finding.url,
                method=finding.method,
                categories=finding.categories,
                verdict="likely",
                confidence=0.6,
                evidence="test",
            ),
        ]),
    )

    md_path, json_path = await m._write_pipeline_report(
        Args(), ps, profile, col, tmp_path, 0.0, 1, 10,
    )
    assert Path(md_path).exists()
    assert Path(json_path).exists()
    data = __import__("json").loads(Path(json_path).read_text())
    assert "deduped_evidence" in data
