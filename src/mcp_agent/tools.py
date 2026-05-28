"""Architect-style tool surface for hxxpsin's MCP gateway.

MCP exposes ONLY atomic ops + read-only lookups. Anything that does
work (scans, probes, intruder runs, repeater replays) lives on the
A2A surface in [a2a_server](../a2a_server/) because A2A's submit /
poll / cancel lifecycle fits long-running work better than MCP's
single-round-trip ``tools/call``.

Two groups on MCP:

1. **Stateless atomic ops** — finish in <30s, no task state:
   ``stackprint``, ``decode``, ``encode_variants``, ``jwt_inspect``.

2. **Scan lookups** — read-only queries against scans/tasks that the
   A2A side created: ``scan_status``, ``scan_list``, ``scan_report``,
   ``scan_findings``, ``scan_solver_results``, ``scan_cancel``.

Every tool dispatch passes through ``InboundGate`` for cognitiond
authorization (see [inbound_gate.py](inbound_gate.py)).

Per the upstream feedback memory, the tool surface is capability-centric
(``fingerprint a stack``, ``decode this opaque blob``) rather than
challenge-tracker-shaped.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .scan_runner import ScanRunner
from .task_store import TaskStore

if TYPE_CHECKING:
    from .server import HxxpsinMCPServer

log = logging.getLogger(__name__)


def register_all(server: "HxxpsinMCPServer") -> None:
    """Wire every tool into the server. Called once at construction."""
    ctx = _Context()

    # --- Group 1: synchronous probes --------------------------------------

    server.register_tool(
        name="stackprint",
        description=(
            "Fingerprint a target URL's web stack (CDN, framework, backend, "
            "auth) and surface interesting paths / recommended tests. "
            "Synchronous; ~5–15s. Returns a StackProfile JSON."
        ),
        input_schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target https://… URL"},
                "timeout": {"type": "number", "default": 8.0},
                "max_js_bundles": {"type": "integer", "default": 3},
            },
        },
        handler=ctx.stackprint,
    )

    server.register_tool(
        name="decode",
        description=(
            "Recursively decode an opaque token / parameter / cookie value. "
            "Returns a tree of (scheme, decoded_value) pairs. Useful when a "
            "request body contains base64-of-json-of-jwt-of-… nested layers."
        ),
        input_schema={
            "type": "object",
            "required": ["value"],
            "properties": {
                "value": {"type": "string"},
                "max_depth": {"type": "integer", "default": 2},
            },
        },
        handler=ctx.decode,
    )

    server.register_tool(
        name="encode_variants",
        description=(
            "Produce labeled re-encodings of a payload for sink-decoder "
            "matching (url, url-double, unicode-escape, base64, html-entity, "
            "etc.). Use when a raw payload is filtered and you need the "
            "encoding the parser will re-decode on the far side."
        ),
        input_schema={
            "type": "object",
            "required": ["value"],
            "properties": {
                "value": {"type": "string"},
                "schemes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional whitelist of schemes; default = all",
                },
                "chain": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, apply schemes in sequence rather than independently",
                },
            },
        },
        handler=ctx.encode_variants,
    )

    server.register_tool(
        name="jwt_inspect",
        description=(
            "Split and decode a JWT; report alg, header, claims, and which "
            "automated attacks (alg=none, weak HS256, kid traversal, alg "
            "confusion) hxxpsin would attempt against it. Does NOT send any "
            "network traffic — purely structural analysis."
        ),
        input_schema={
            "type": "object",
            "required": ["token"],
            "properties": {"token": {"type": "string"}},
        },
        handler=ctx.jwt_inspect,
    )

    # --- Group 2: long-running scan LOOKUPS only ---------------------------
    # Scan start / repeater / probe ops live on the A2A surface
    # (see src/a2a_server/); MCP keeps only stateless atomic ops + lookups.

    server.register_tool(
        name="scan_status",
        description="Fetch the current status of a scan (queued/running/completed/failed/cancelled) plus elapsed time.",
        input_schema={
            "type": "object",
            "required": ["scan_id"],
            "properties": {"scan_id": {"type": "string"}},
        },
        handler=ctx.scan_status,
    )

    server.register_tool(
        name="scan_list",
        description="List recent scans (most recent first) with status, target, and finished_at.",
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 25, "maximum": 200}},
        },
        handler=ctx.scan_list,
    )

    server.register_tool(
        name="scan_report",
        description=(
            "Return the report.md (and optionally report.json) for a "
            "completed scan. Fails if the scan is not yet finished."
        ),
        input_schema={
            "type": "object",
            "required": ["scan_id"],
            "properties": {
                "scan_id": {"type": "string"},
                "include_json": {"type": "boolean", "default": False},
            },
        },
        handler=ctx.scan_report,
    )

    server.register_tool(
        name="scan_findings",
        description=(
            "Return the structured top findings for a completed scan "
            "(category, url, evidence, classifier score). Cheaper to "
            "consume than the full report.md when you only need the list."
        ),
        input_schema={
            "type": "object",
            "required": ["scan_id"],
            "properties": {
                "scan_id": {"type": "string"},
                "top": {"type": "integer", "default": 10, "maximum": 200},
            },
        },
        handler=ctx.scan_findings,
    )

    server.register_tool(
        name="scan_cancel",
        description="Terminate a running scan (SIGTERM the process group).",
        input_schema={
            "type": "object",
            "required": ["scan_id"],
            "properties": {"scan_id": {"type": "string"}},
        },
        handler=ctx.scan_cancel,
    )

    # --- Group 3: solver results ------------------------------------------

    server.register_tool(
        name="scan_solver_results",
        description=(
            "Return the verdicts produced by hxxpsin's three-stage agentic "
            "solver for a completed scan. Requires the scan to have been "
            "started with solve=true (otherwise solver.json will be absent). "
            "Each verdict is one of confirmed/refuted/inconclusive plus a "
            "reason and an evidence excerpt."
        ),
        input_schema={
            "type": "object",
            "required": ["scan_id"],
            "properties": {"scan_id": {"type": "string"}},
        },
        handler=ctx.scan_solver_results,
    )

    # --- Meta -------------------------------------------------------------

    server.register_tool(
        name="list_capabilities",
        description="Self-describe: tool groups, version, output directory root.",
        input_schema={"type": "object", "properties": {}},
        handler=ctx.list_capabilities,
    )


class _Context:
    """Lazy holders for shared state (task store, scan runner) and lazy
    imports of hxxpsin's own modules so a missing optional dep (e.g.
    playwright) doesn't prevent the MCP server from booting."""

    def __init__(self) -> None:
        self.store = TaskStore()
        self.runner = ScanRunner(store=self.store)

    # -- group 1 ----------------------------------------------------------

    async def stackprint(
        self,
        *,
        url: str,
        timeout: float = 8.0,
        max_js_bundles: int = 3,
    ) -> dict[str, Any]:
        from stackprint import StackProfiler  # type: ignore[import-not-found]
        profiler = StackProfiler(url, timeout=timeout, max_js_bundles=max_js_bundles)
        profile = await profiler.run()
        return profile.to_dict()

    def decode(self, *, value: str, max_depth: int = 2) -> dict[str, Any]:
        from codec import decode_tree, detect, try_decode_all  # type: ignore[import-not-found]
        return {
            "guesses": detect(value),
            "flat": try_decode_all(value, max_depth=max_depth),
            "tree": decode_tree(value, max_depth=max_depth),
        }

    def encode_variants(
        self,
        *,
        value: str,
        schemes: list[str] | None = None,
        chain: bool = False,
    ) -> dict[str, Any]:
        from codec import list_schemes, variants  # type: ignore[import-not-found]
        chosen = schemes or list_schemes()
        return {
            "schemes_applied": chosen,
            "chained": chain,
            "variants": variants(value, chosen, chain=chain),
        }

    def jwt_inspect(self, *, token: str) -> dict[str, Any]:
        from jwt_attack import _decode_part, _split_token  # type: ignore[import-not-found]
        split = _split_token(token)
        if split is None:
            return {"valid": False, "reason": "not a parseable JWT (need 3 dot-separated b64url parts)"}
        header, payload, sig_b64 = split
        attacks: list[str] = []
        alg = (header.get("alg") or "").lower()
        if alg in ("hs256", "hs384", "hs512"):
            attacks.append("weak HS256 wordlist crack")
        if alg.startswith("rs") or alg.startswith("es"):
            attacks.append("alg confusion (RS→HS) using grabbed PEMs")
        attacks.append("alg=none forgery")
        if header.get("kid"):
            attacks.append("kid path traversal / SQLi")
        return {
            "valid": True,
            "header": header,
            "payload": payload,
            "signature_present": bool(sig_b64),
            "applicable_attacks": attacks,
        }

    # -- group 2: scan lookups (scan_start lives on A2A) ------------------

    def scan_status(self, *, scan_id: str) -> dict[str, Any]:
        rec = self.store.get(scan_id)
        d = rec.to_dict()
        if rec.finished_at:
            d["elapsed_s"] = round(rec.finished_at - rec.started_at, 2)
        else:
            from time import time
            d["elapsed_s"] = round(time() - rec.started_at, 2)
        return d

    def scan_list(self, *, limit: int = 25) -> dict[str, Any]:
        return {"scans": [r.to_dict() for r in self.store.list(limit=limit)]}

    def scan_report(self, *, scan_id: str, include_json: bool = False) -> dict[str, Any]:
        rec = self.store.get(scan_id)
        if rec.status not in ("completed", "failed"):
            raise RuntimeError(f"scan {scan_id} is {rec.status}; no report yet")
        out_dir = Path(rec.out_dir)
        md = (out_dir / "report.md").read_text() if (out_dir / "report.md").exists() else None
        payload: dict[str, Any] = {"scan_id": scan_id, "status": rec.status, "report_md": md}
        if include_json:
            jp = out_dir / "report.json"
            if jp.exists():
                payload["report_json"] = json.loads(jp.read_text())
        return payload

    def scan_findings(self, *, scan_id: str, top: int = 10) -> dict[str, Any]:
        rec = self.store.get(scan_id)
        report_path = Path(rec.out_dir) / "report.json"
        if not report_path.exists():
            raise RuntimeError(f"scan {scan_id}: report.json not present (status={rec.status})")
        data = json.loads(report_path.read_text())
        # reporter.py serializes top scored findings under `top_findings`.
        findings = (data.get("top_findings") or [])[:top]
        return {"scan_id": scan_id, "top": top, "findings": findings}

    def scan_cancel(self, *, scan_id: str) -> dict[str, Any]:
        return self.runner.cancel(scan_id).to_dict()

    # -- group 3 ----------------------------------------------------------

    def scan_solver_results(self, *, scan_id: str) -> dict[str, Any]:
        rec = self.store.get(scan_id)
        path = Path(rec.out_dir) / "solver.json"
        if not path.exists():
            raise RuntimeError(
                f"scan {scan_id}: no solver.json. Re-run scan_start with solve=true to enable "
                "the three-stage agentic solver."
            )
        return {"scan_id": scan_id, "solver": json.loads(path.read_text())}

    # -- meta -------------------------------------------------------------

    def list_capabilities(self) -> dict[str, Any]:
        return {
            "server": "hxxpsin",
            "version": "0.1.0",
            "output_root": str(self.store.root),
            "tool_groups": {
                "sync_probes": ["stackprint", "decode", "encode_variants", "jwt_inspect"],
                "scan_lookups": [
                    "scan_status",
                    "scan_list",
                    "scan_report",
                    "scan_findings",
                    "scan_cancel",
                    "scan_solver_results",
                ],
            },
            "a2a_url": "http://127.0.0.1:9851",
        }
