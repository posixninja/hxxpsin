"""Skills under the ``scan`` agent — pipeline orchestrators.

These either fork a full hxxpsin subprocess (``scan_full`` / ``scan_quick``)
or invoke specific pipeline slices in-process (``scan_triage``,
``confirm_finding``).

Subprocess scans reuse [mcp_agent/scan_runner.py](../../mcp_agent/scan_runner.py)
so MCP lookups (``scan_status``, ``scan_report``, …) and A2A
submissions share the same task ledger.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from . import REGISTRY


def _solve_one_script() -> Path:
    """Locate ``scripts/solve_one.py`` so ``confirm_finding`` can shell out."""
    here = Path(__file__).resolve()
    # src/a2a_server/skills/scan.py → project_root
    project_root = here.parents[3]
    return project_root / "scripts" / "solve_one.py"

REGISTRY.declare_agent(
    "scan",
    name="hxxpsin scan orchestrators",
    description="Full pipeline, quick fingerprint, triage, and per-finding solver.",
)


def _runner():
    """Lazy import to avoid pulling subprocess machinery at agent-card load."""
    from mcp_agent.scan_runner import ScanRunner

    return ScanRunner()


def _store():
    from mcp_agent.task_store import TaskStore

    return TaskStore()


async def _scan_full(
    *,
    url: str,
    auth_file: str | None = None,
    active_scan: bool = False,
    solve: bool = True,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    rec = _runner().start(
        target=url,
        mode="scan",
        auth=auth_file,
        active_scan=active_scan,
        solve=solve,
        extra_args=extra_args,
    )
    return rec.to_dict()


async def _scan_quick(
    *, url: str, extra_args: list[str] | None = None
) -> dict[str, Any]:
    rec = _runner().start(target=url, mode="quick", extra_args=extra_args)
    return rec.to_dict()


async def _scan_triage(
    *, url: str, auth_file: str | None = None, extra_args: list[str] | None = None
) -> dict[str, Any]:
    """Crawl + classify only — no active probes, no solver.

    Implemented by forking ``scan`` with ``active_scan=False`` and
    ``solve=False`` (which is the default; both are opt-in flags on
    ``main.py``). The classifier still runs and produces the prioritized
    findings list; active injection probes and the agentic solver are
    skipped. Keeps the logic in one place (main.py) rather than forking
    the pipeline."""
    rec = _runner().start(
        target=url,
        mode="scan",
        auth=auth_file,
        active_scan=False,
        solve=False,
        extra_args=extra_args,
    )
    return rec.to_dict()


async def _confirm_finding(
    *,
    scan_id: str,
    finding_index: int = 0,
    provider: str = "claude",
) -> dict[str, Any]:
    """Run the 3-stage solver against a single finding from a completed scan.

    Reconstructs the finding from ``classify.json`` (persisted by
    ``reporter.py``) and shells out to ``scripts/solve_one.py`` so the
    long LLM-driven pipeline runs out-of-process from the A2A event
    loop. The subprocess writes ``solver-<index>.json`` next to the
    scan's other artifacts. Falls back to a stale-read of ``solver.json``
    when ``classify.json`` is missing (older scans).
    """
    rec = _store().get(scan_id)
    classify_path = Path(rec.out_dir) / "classify.json"

    # Fallback path: scan ran before classify.json existed → return what
    # solver.json has (the old behavior). New scans always write classify.json
    # so this branch only fires on legacy output dirs.
    if not classify_path.exists():
        solver_path = Path(rec.out_dir) / "solver.json"
        if not solver_path.exists():
            return {
                "scan_id": scan_id,
                "finding_index": finding_index,
                "error": (
                    "scan has no classify.json (legacy output) and no solver.json. "
                    "Re-run scan_full to enable on-demand confirm_finding."
                ),
            }
        data = json.loads(solver_path.read_text())
        findings = data.get("findings") or []
        if not findings:
            return {"scan_id": scan_id, "finding_index": finding_index, "verdict": "no_findings"}
        idx = max(0, min(finding_index, len(findings) - 1))
        return {
            "scan_id": scan_id,
            "finding_index": idx,
            "provider": provider,
            "verdict": findings[idx],
            "source": "stale_solver_json",
        }

    # Happy path: classify.json exists → run scripts/solve_one.py as a subprocess.
    script_path = _solve_one_script()
    argv = [
        sys.executable,
        str(script_path),
        "--scan-dir",
        rec.out_dir,
        "--finding-index",
        str(finding_index),
        "--provider",
        provider,
    ]
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out_bytes, err_bytes = await proc.communicate()
    out_text = (out_bytes or b"").decode(errors="replace")
    err_text = (err_bytes or b"").decode(errors="replace")
    if proc.returncode != 0:
        return {
            "scan_id": scan_id,
            "finding_index": finding_index,
            "provider": provider,
            "error": f"solve_one exit={proc.returncode}",
            "stderr": err_text[:2000],
        }
    try:
        result = json.loads(out_text)
    except json.JSONDecodeError:
        result = {"raw_stdout": out_text[:2000]}
    result.update({"scan_id": scan_id, "finding_index": finding_index, "provider": provider})
    return result


REGISTRY.add(
    agent_id="scan",
    skill_id="scan_full",
    description=(
        "Long-running full pipeline: recon → crawl → classify → probes → "
        "enrich → report. Returns a scan_id immediately. Pair with MCP "
        "scan_status / scan_report."
    ),
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "auth_file": {"type": "string"},
            "active_scan": {"type": "boolean", "default": False},
            "solve": {"type": "boolean", "default": True},
            "extra_args": {"type": "array", "items": {"type": "string"}},
        },
    },
    handler=_scan_full,
)

REGISTRY.add(
    agent_id="scan",
    skill_id="scan_quick",
    description="60-second fingerprint + interesting paths. No browser, no probes.",
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "extra_args": {"type": "array", "items": {"type": "string"}},
        },
    },
    handler=_scan_quick,
)

REGISTRY.add(
    agent_id="scan",
    skill_id="scan_triage",
    description="Crawl + classify only — no active probes. For prioritization without exploitation.",
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "auth_file": {"type": "string"},
            "extra_args": {"type": "array", "items": {"type": "string"}},
        },
    },
    handler=_scan_triage,
)

REGISTRY.add(
    agent_id="scan",
    skill_id="confirm_finding",
    description=(
        "Run the three-stage agentic solver (recon → briefing → verdict) "
        "against a single finding from a completed scan. Requires the "
        "scan to have been launched with solve=true."
    ),
    input_schema={
        "type": "object",
        "required": ["scan_id"],
        "properties": {
            "scan_id": {"type": "string"},
            "finding_index": {"type": "integer", "default": 0},
            "provider": {"type": "string", "enum": ["claude", "openai", "ollama"], "default": "claude"},
        },
    },
    handler=_confirm_finding,
)
