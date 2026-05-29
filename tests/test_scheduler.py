"""Tests for concurrent stage scheduler."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scheduler import Stage, run_stages, load_completed_stages, persist_stage_record, StageRecord


@pytest.mark.asyncio
async def test_scheduler_runs_in_dependency_order(tmp_path):
    order = []

    async def a(ctx):
        order.append("a")

    async def b(ctx):
        order.append("b")

    stages = [
        Stage("a", a),
        Stage("b", b, depends_on=("a",)),
    ]
    await run_stages(stages, object(), out_dir=tmp_path, max_concurrent=4)
    assert order == ["a", "b"]


@pytest.mark.asyncio
async def test_scheduler_isolates_failures(tmp_path):
    ran = []

    async def ok(ctx):
        ran.append("ok")

    async def bad(ctx):
        raise RuntimeError("boom")

    stages = [
        Stage("bad", bad),
        Stage("ok", ok, depends_on=()),
    ]
    result = await run_stages(stages, object(), out_dir=tmp_path, max_concurrent=4)
    assert "ok" in ran
    assert result.records["bad"].status == "error"
    assert result.records["ok"].status == "done"


@pytest.mark.asyncio
async def test_resume_skips_completed(tmp_path):
    done = []

    async def once(ctx):
        done.append(1)

    rec = StageRecord(name="once", status="done", elapsed_ms=1.0)
    persist_stage_record(tmp_path, rec)
    assert "once" in load_completed_stages(tmp_path)

    await run_stages(
        [Stage("once", once)],
        object(),
        out_dir=tmp_path,
        resume=True,
    )
    assert done == []
