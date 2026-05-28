"""aiohttp app for the hxxpsin A2A server.

Routes:

- ``GET  /health``                  — liveness
- ``GET  /.well-known/agent.json``  — agent card
- ``POST /``                        — JSON-RPC ``tasks/send``
- ``GET  /tasks/{task_id}``         — poll task state
- ``DELETE /tasks/{task_id}``       — cancel task

Tasks run as ``asyncio.Task`` instances within the server's event loop;
short-lived skills (probes, repeater, intruder) settle in seconds to
minutes. Long-running scans (``scan_full``) are special: the handler
returns immediately with a ``scan_id`` and the underlying subprocess
keeps running outside the asyncio task, so the A2A task is marked
completed as soon as the submit goes through. Callers poll via the MCP
``scan_status`` tool for the subprocess-backed lifecycle.

Every ``tasks/send`` runs through ``InboundGate`` for cognitiond
authorization before the skill handler executes — see
[../mcp_agent/inbound_gate.py](../mcp_agent/inbound_gate.py).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web

from .agent_card import build_agent_card
from .skills import REGISTRY

log = logging.getLogger(__name__)


_TERMINAL = {"completed", "failed", "canceled", "cancelled"}


# Typed app-state keys — aiohttp 3.13+ deprecates string-keyed app[...] access.
TASKS_KEY: web.AppKey = web.AppKey("tasks", dict)
PUBLIC_URL_KEY: web.AppKey = web.AppKey("public_url", str)
GATE_KEY: web.AppKey = web.AppKey("gate", object)


@dataclass
class _TaskRecord:
    task_id: str
    agent_id: str
    skill_id: str
    params: dict[str, Any]
    state: str  # submitted | working | completed | failed | canceled
    submitted_at: float
    finished_at: float | None = None
    output: Any | None = None
    error: str | None = None
    task: asyncio.Task[Any] | None = field(default=None, repr=False)

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.task_id,
            "state": self.state,
            "agentId": self.agent_id,
            "skillId": self.skill_id,
            "submittedAt": self.submitted_at,
        }
        if self.finished_at is not None:
            out["finishedAt"] = self.finished_at
        if self.output is not None:
            out["output"] = self.output
        if self.error:
            out["error"] = self.error
        return out


def build_app(*, public_url: str | None = None) -> web.Application:
    app = web.Application()
    app[TASKS_KEY] = {}  # task_id -> _TaskRecord
    app[PUBLIC_URL_KEY] = public_url or f"http://127.0.0.1:{os.environ.get('HXXPSIN_A2A_PORT', '9851')}"
    app[GATE_KEY] = _build_gate()

    app.router.add_get("/health", _health)
    app.router.add_get("/.well-known/agent.json", _agent_card)
    app.router.add_post("/", _jsonrpc)
    app.router.add_get("/tasks/{task_id}", _poll_task)
    app.router.add_delete("/tasks/{task_id}", _cancel_task)

    return app


def _build_gate() -> Any | None:
    try:
        from cognition_client import CognitionClient  # type: ignore[import-not-found]
        from identity import load as load_identity  # type: ignore[import-not-found]
        from mcp_agent.inbound_gate import InboundGate
    except Exception as e:
        log.warning("a2a inbound gate disabled (import failure): %s", e)
        return None
    return InboundGate(client=CognitionClient(), agent_actor_id=load_identity().actor_id)


async def _health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "service": "hxxpsin-a2a"})


async def _agent_card(request: web.Request) -> web.Response:
    card = build_agent_card(public_url=request.app[PUBLIC_URL_KEY])
    return web.json_response(card)


async def _poll_task(request: web.Request) -> web.Response:
    task_id = request.match_info["task_id"]
    rec = request.app[TASKS_KEY].get(task_id)
    if rec is None:
        return web.json_response({"error": "unknown_task"}, status=404)
    return web.json_response(rec.to_wire())


async def _cancel_task(request: web.Request) -> web.Response:
    task_id = request.match_info["task_id"]
    rec: _TaskRecord | None = request.app[TASKS_KEY].get(task_id)
    if rec is None:
        return web.json_response({"error": "unknown_task"}, status=404)
    if rec.state in _TERMINAL:
        return web.json_response(rec.to_wire())
    if rec.task is not None and not rec.task.done():
        rec.task.cancel()
    rec.state = "canceled"
    rec.finished_at = time.time()
    return web.json_response(rec.to_wire())


# ---------------------------------------------------------------------------
# JSON-RPC entry — only ``tasks/send`` is supported.
# ---------------------------------------------------------------------------


async def _jsonrpc(request: web.Request) -> web.Response:
    try:
        envelope = await request.json()
    except Exception:
        return _rpc_err(None, -32700, "parse error")
    if not isinstance(envelope, dict):
        return _rpc_err(None, -32600, "envelope must be object")
    rid = envelope.get("id")
    method = envelope.get("method")
    params = envelope.get("params") or {}
    if not isinstance(params, dict):
        return _rpc_err(rid, -32602, "params must be object")
    if method != "tasks/send":
        return _rpc_err(rid, -32601, f"method not found: {method!r}")

    agent_id = params.get("agentId") or params.get("agent_id")
    skill_id = params.get("skillId") or params.get("skill_id")
    if not (isinstance(agent_id, str) and isinstance(skill_id, str)):
        return _rpc_err(rid, -32602, "agentId and skillId required")
    skill_params = params.get("params") or {}
    if not isinstance(skill_params, dict):
        return _rpc_err(rid, -32602, "params.params must be object")
    metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}

    try:
        skill = REGISTRY.resolve(agent_id, skill_id)
    except KeyError as e:
        return _rpc_err(rid, -32601, str(e))

    # Inbound gate (cognitiond)
    gate = request.app[GATE_KEY]
    token = None
    if gate is not None:
        try:
            token = await gate.authorize(
                tool_name=f"{agent_id}.{skill_id}",
                arguments=skill_params,
                metadata=metadata,
                transport="a2a",
            )
        except Exception as e:
            return _rpc_err(rid, -32000, f"cognitiond deny: {e}")

    # Spawn the skill task
    task_id = uuid.uuid4().hex
    rec = _TaskRecord(
        task_id=task_id,
        agent_id=agent_id,
        skill_id=skill_id,
        params=skill_params,
        state="submitted",
        submitted_at=time.time(),
    )
    request.app[TASKS_KEY][task_id] = rec
    rec.task = asyncio.create_task(_run_skill(rec, skill, skill_params, gate, token))
    return web.json_response({"jsonrpc": "2.0", "id": rid, "result": rec.to_wire()})


async def _run_skill(
    rec: _TaskRecord,
    skill: Any,
    params: dict[str, Any],
    gate: Any | None,
    token: Any | None,
) -> None:
    rec.state = "working"
    try:
        output = await skill.handler(**params)
        rec.output = output if isinstance(output, (dict, list, str, int, float, bool, type(None))) else str(output)
        rec.state = "completed"
    except asyncio.CancelledError:
        rec.state = "canceled"
        raise
    except Exception as e:
        log.error("a2a skill %s/%s failed: %s\n%s", rec.agent_id, rec.skill_id, e, traceback.format_exc())
        rec.error = f"{type(e).__name__}: {e}"
        rec.state = "failed"
    finally:
        rec.finished_at = time.time()
        if gate is not None and token is not None:
            try:
                await gate.commit(token, result_payload={"state": rec.state})
            except Exception as e:  # noqa: BLE001
                log.warning("a2a gate commit failed: %s", e)


def _rpc_err(rid: Any, code: int, message: str, status: int = 200) -> web.Response:
    return web.json_response(
        {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}},
        status=status,
    )
