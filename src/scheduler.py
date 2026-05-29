"""
scheduler.py — Concurrent, crash-isolated stage runner for the hxxpsin pipeline.

Each stage declares dependencies; ready stages run in parallel under a
Semaphore. Exceptions are captured as StageError without aborting siblings.
Completed stages can be persisted to out/stages/<name>.json for --resume.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional


@dataclass
class StageError:
    stage: str
    exc_type: str
    message: str
    traceback: str = ""

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "exc_type": self.exc_type,
            "message": self.message,
            "traceback": self.traceback,
        }


@dataclass
class StageRecord:
    name: str
    status: str  # pending | running | done | error | skipped
    started_at: float = 0.0
    finished_at: float = 0.0
    elapsed_ms: float = 0.0
    error: Optional[StageError] = None
    skipped_reason: str = ""

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "skipped_reason": self.skipped_reason,
        }
        if self.error:
            d["error"] = self.error.to_dict()
        return d


@dataclass
class Stage:
    """One pipeline unit."""

    name: str
    run: Callable[[Any], Awaitable[None]]
    depends_on: tuple[str, ...] = ()
    enabled: Callable[[Any], bool] = lambda _ctx: True
    skip_if_done: bool = True


@dataclass
class SchedulerResult:
    records: dict[str, StageRecord] = field(default_factory=dict)
    stage_timings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "records": {k: v.to_dict() for k, v in self.records.items()},
            "stage_timings": self.stage_timings,
        }


def stages_dir(out: Path) -> Path:
    d = out / "stages"
    d.mkdir(parents=True, exist_ok=True)
    return d


def stage_artifact_path(out: Path, name: str) -> Path:
    return stages_dir(out) / f"{name}.json"


def load_completed_stages(out: Path) -> set[str]:
    """Return stage names that completed successfully on a prior run."""
    done: set[str] = set()
    sd = out / "stages"
    if not sd.is_dir():
        return done
    for p in sd.glob("*.json"):
        try:
            data = json.loads(p.read_text())
            if data.get("status") == "done":
                done.add(p.stem)
        except Exception:
            pass
    return done


def persist_stage_record(out: Path, record: StageRecord) -> None:
    path = stage_artifact_path(out, record.name)
    path.write_text(json.dumps(record.to_dict(), indent=2))


def persist_stage_result(out: Path, name: str, data: dict) -> None:
    """Persist probe result payload for resume/report (separate from status record)."""
    path = stages_dir(out) / f"{name}.result.json"
    path.write_text(json.dumps(data, indent=2))


def _default_emit(event: str, payload: dict) -> None:
    pass


async def run_stages(
    stages: list[Stage],
    ctx: Any,
    *,
    out_dir: Optional[Path] = None,
    max_concurrent: int = 6,
    resume: bool = False,
    on_event: Optional[Callable[[str, dict], None]] = None,
) -> SchedulerResult:
    """
    Run stages in dependency order with parallel waves.

    ctx: pipeline context object (PipelineState or similar).
    on_event: callback(event_name, payload) for TUI hooks.
    """
    emit = on_event or _default_emit
    completed_resume = load_completed_stages(out_dir) if (resume and out_dir) else set()

    by_name = {s.name: s for s in stages}
    records: dict[str, StageRecord] = {s.name: StageRecord(name=s.name, status="pending") for s in stages}
    sem = asyncio.Semaphore(max(1, max_concurrent))
    result = SchedulerResult(records=records)

    async def _run_one(stage: Stage) -> None:
        rec = records[stage.name]
        if not stage.enabled(ctx):
            rec.status = "skipped"
            rec.skipped_reason = "disabled"
            emit("stage_done", {"name": stage.name, "status": "skipped"})
            if out_dir:
                persist_stage_record(out_dir, rec)
            return

        if resume and stage.skip_if_done and stage.name in completed_resume:
            rec.status = "skipped"
            rec.skipped_reason = "resume: already completed"
            emit("stage_done", {"name": stage.name, "status": "skipped", "resume": True})
            return

        rec.status = "running"
        rec.started_at = time.monotonic()
        emit("stage_start", {"name": stage.name, "depends_on": list(stage.depends_on)})

        async with sem:
            t0 = time.monotonic()
            try:
                await stage.run(ctx)
                rec.status = "done"
                rec.error = None
            except Exception as exc:
                rec.status = "error"
                rec.error = StageError(
                    stage=stage.name,
                    exc_type=type(exc).__name__,
                    message=str(exc),
                    traceback=traceback.format_exc(),
                )
            finally:
                rec.finished_at = time.monotonic()
                rec.elapsed_ms = (rec.finished_at - rec.started_at) * 1000.0
                result.stage_timings.append({
                    "name": stage.name,
                    "status": rec.status,
                    "elapsed_ms": round(rec.elapsed_ms, 1),
                })
                emit("stage_done", {
                    "name": stage.name,
                    "status": rec.status,
                    "elapsed_ms": rec.elapsed_ms,
                    "error": rec.error.to_dict() if rec.error else None,
                })
                if out_dir:
                    persist_stage_record(out_dir, rec)

    remaining = set(by_name.keys())
    while remaining:
        ready = [
            n for n in remaining
            if all(
                dep not in remaining or records[dep].status in ("done", "skipped", "error")
                for dep in by_name[n].depends_on
            )
        ]
        if not ready:
            # Circular or missing dependency — run whatever is left sequentially
            ready = [next(iter(remaining))]

        await asyncio.gather(*[_run_one(by_name[n]) for n in ready])
        remaining -= set(ready)

    if out_dir:
        summary_path = stages_dir(out_dir) / "_scheduler.json"
        summary_path.write_text(json.dumps(result.to_dict(), indent=2))

    return result
