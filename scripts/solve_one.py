#!/usr/bin/env python3
"""Run the 3-stage agentic solver against ONE classifier finding.

Used by the A2A ``confirm_finding`` skill — A2A spawns this as a
subprocess (same isolation model ``scan_full`` uses) so the long
LLM-driven pipeline runs out-of-process from the A2A event loop.

Inputs:
  --scan-dir PATH         Directory containing classify.json (required)
  --finding-index N       Which finding to run (default: 0)
  --provider PROVIDER     claude|openai|ollama (default: claude)
  --max-turns N           Max turns per finding (default: 10)
  --out PATH              Where to write solver-N.json (default: scan-dir)

Reads classify.json, reconstructs a ``Finding``, wires up a
``ServusLLMClient`` (with the configured provider), and calls
``solve_findings`` with ``top_n=1``. Writes ``solver-<index>.json``.

Exit codes:
  0  success — verdict written
  1  classify.json missing or no findings
  2  servus token not configured (SERVUS_AGENT_TOKEN)
  3  solver itself raised
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


# Ensure src/ is on sys.path so the imports below work whether this script is
# invoked via ``python3 scripts/solve_one.py`` or ``python3 -m scripts.solve_one``.
sys.path.insert(0, str(_project_root() / "src"))

from classifier import ClassifierResult, Finding  # noqa: E402
import servus_client  # noqa: E402


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


async def _amain(args: argparse.Namespace) -> int:
    scan_dir = Path(args.scan_dir).expanduser().resolve()
    classify_path = scan_dir / "classify.json"
    if not classify_path.exists():
        _err(f"[solve_one] {classify_path} not found")
        return 1
    data = json.loads(classify_path.read_text())
    findings_raw = data.get("findings") or []
    if not findings_raw:
        _err(f"[solve_one] {classify_path} has no findings")
        return 1
    if args.finding_index < 0 or args.finding_index >= len(findings_raw):
        _err(
            f"[solve_one] finding_index {args.finding_index} out of range "
            f"(0..{len(findings_raw) - 1})"
        )
        return 1
    finding = Finding.from_full_dict(findings_raw[args.finding_index])

    if not os.environ.get("SERVUS_AGENT_TOKEN"):
        _err("[solve_one] SERVUS_AGENT_TOKEN not set — cannot reach servus")
        return 2

    # Build a minimal ClassifierResult that carries exactly the one finding;
    # solve_findings takes the first top_n and writes per-finding verdicts.
    one_result = ClassifierResult(
        request_findings=[finding],
        websocket_findings=[],
        js_route_findings=[],
        js_constants=[],
        by_category={},
    )

    client = servus_client.ServusLLMClient(default_provider=args.provider)

    from challenge_solver import solve_findings

    try:
        result = await solve_findings(
            llm_generate=client.generate,
            model_name=f"servus/{args.provider}",
            classifier_result=one_result,
            target=str(data.get("target") or finding.url),
            out_dir=scan_dir,
            auth_headers=None,
            storage_state_path=None,
            top_n=1,
            verbose=False,
        )
    except Exception as e:
        _err(f"[solve_one] solver raised: {type(e).__name__}: {e}")
        return 3

    out_path = Path(args.out or scan_dir) / f"solver-{args.finding_index}.json"
    out_path.write_text(json.dumps(result.to_dict(), indent=2))
    print(json.dumps({"out": str(out_path), "verdicts": result.to_dict()}, indent=2))
    return 0


# Provide the same llm_generate signature challenge_solver expects without
# requiring an explicit async-context manager: ServusLLMClient.generate is
# already a coroutine, no context manager needed.


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the 3-stage solver on one finding")
    p.add_argument("--scan-dir", required=True)
    p.add_argument("--finding-index", type=int, default=0)
    p.add_argument("--provider", default="claude", choices=["claude", "openai", "ollama"])
    p.add_argument("--max-turns", type=int, default=10)
    p.add_argument("--out", default=None)
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    sys.exit(main())
