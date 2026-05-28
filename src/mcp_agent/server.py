"""HxxpsinMCPServer — stdio JSON-RPC 2.0 host speaking MCP 2024-11-05.

The wire shape this server implements is the same one
``servus/secretarius/mcp_client.py`` consumes:

    request : {"jsonrpc":"2.0", "id":<int>, "method":"tools/list", "params":{}}
    response: {"jsonrpc":"2.0", "id":<int>, "result":{...} | "error":{...}}
    one JSON object per line on stdin/stdout.

Methods handled:

- ``initialize`` → returns server info + protocolVersion
- ``notifications/initialized`` → no-op (no reply expected)
- ``tools/list`` → enumerate registered tools
- ``tools/call`` → dispatch by name; result is wrapped in MCP's
  ``content: [{type: "text", text: <json>}]`` shape so the client sees
  a uniform string regardless of the underlying handler's return type.

Tool registrations live in [tools.py](tools.py). Long-running scans are
delegated to [scan_runner.py](scan_runner.py), which is backed by
[task_store.py](task_store.py).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import sys
import threading
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)

_PROTOCOL_VERSION = "2024-11-05"
_SERVER_NAME = "hxxpsin"
_SERVER_VERSION = "0.1.0"


# JSON-RPC error codes (subset of the spec we actually emit)
_ERR_METHOD_NOT_FOUND = -32601
_ERR_INVALID_PARAMS = -32602
_ERR_INTERNAL = -32603


ToolHandler = Callable[..., Any]


@dataclass
class _Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


class HxxpsinMCPServer:
    """Single-process stdio JSON-RPC server. Tools are registered up-front.

    Every ``tools/call`` is wrapped in an ``InboundGate`` check against
    cognitiond so a compromised MCP host can't make hxxpsin probe
    arbitrary targets. The gate degrades to allow-all in dev when
    ``HXXPSIN_COGNITION_INSECURE=1`` is set.
    """

    def __init__(self, *, gate: "Any | None" = None) -> None:
        self._tools: dict[str, _Tool] = {}
        self._stdout_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._gate = gate or _default_gate()
        from . import tools as _tools_mod  # lazy: avoid heavy imports at module-load
        _tools_mod.register_all(self)

    # -- registration -----------------------------------------------------

    def register_tool(
        self,
        *,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: ToolHandler,
    ) -> None:
        if name in self._tools:
            raise ValueError(f"duplicate tool name: {name!r}")
        self._tools[name] = _Tool(
            name=name,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("event loop not yet available; call inside serve_forever")
        return self._loop

    # -- main loop --------------------------------------------------------

    def serve_forever(self) -> None:
        """Read JSON-RPC envelopes from stdin until EOF. Blocking."""
        self._loop = asyncio.new_event_loop()
        try:
            for raw in sys.stdin:
                line = raw.strip()
                if not line:
                    continue
                self._handle_line(line)
        finally:
            try:
                self._loop.close()
            finally:
                self._loop = None

    # -- dispatch ---------------------------------------------------------

    def _handle_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning("mcp_agent: non-JSON line discarded: %s", e)
            return

        method = msg.get("method")
        rid = msg.get("id")
        params = msg.get("params") or {}

        # Notifications have no `id` and never get a reply.
        if rid is None:
            log.debug("mcp_agent: notification %s ignored", method)
            return

        try:
            result = self._dispatch(method, params)
            self._write({"jsonrpc": "2.0", "id": rid, "result": result})
        except _RPCError as e:
            self._write({"jsonrpc": "2.0", "id": rid, "error": {"code": e.code, "message": str(e)}})
        except Exception as e:
            log.error("mcp_agent: dispatch failure for %s: %s\n%s", method, e, traceback.format_exc())
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": _ERR_INTERNAL, "message": f"{type(e).__name__}: {e}"},
                }
            )

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": _PROTOCOL_VERSION,
                "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
                "capabilities": {"tools": {}},
            }
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    }
                    for t in self._tools.values()
                ]
            }
        if method == "tools/call":
            return self._call_tool(params)
        raise _RPCError(_ERR_METHOD_NOT_FOUND, f"unknown method: {method!r}")

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise _RPCError(_ERR_INVALID_PARAMS, "tools/call requires string 'name'")
        tool = self._tools.get(name)
        if tool is None:
            raise _RPCError(_ERR_METHOD_NOT_FOUND, f"unknown tool: {name!r}")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise _RPCError(_ERR_INVALID_PARAMS, "tools/call 'arguments' must be an object")

        # MCP 2024-11-05 carries optional caller metadata under "_meta"
        metadata = params.get("_meta") if isinstance(params.get("_meta"), dict) else None

        token = None
        if self._gate is not None:
            try:
                token = self._loop.run_until_complete(  # type: ignore[union-attr]
                    _await(
                        self._gate.authorize(
                            tool_name=name, arguments=args, metadata=metadata, transport="mcp"
                        )
                    )
                )
            except Exception as e:
                # GateDenied or transport-failure → return MCP "isError" result so
                # the LLM host sees a clean tool error rather than a JSON-RPC error.
                msg = f"inbound gate denied {name!r}: {type(e).__name__}: {e}"
                log.warning(msg)
                return {"content": [{"type": "text", "text": msg}], "isError": True}

        try:
            value = tool.handler(**args)
            if inspect.isawaitable(value):
                value = self._loop.run_until_complete(_await(value))  # type: ignore[union-attr]
        except TypeError as e:
            raise _RPCError(_ERR_INVALID_PARAMS, f"argument error: {e}") from e

        text = value if isinstance(value, str) else json.dumps(value, default=_json_default)

        if self._gate is not None and token is not None:
            try:
                self._loop.run_until_complete(  # type: ignore[union-attr]
                    _await(
                        self._gate.commit(
                            token,
                            result_payload=value if isinstance(value, dict) else {"text": text[:2048]},
                        )
                    )
                )
            except Exception as e:
                log.warning("inbound gate commit failed for %s: %s", name, e)

        return {"content": [{"type": "text", "text": text}], "isError": False}

    # -- stdio ------------------------------------------------------------

    def _write(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, default=_json_default) + "\n"
        with self._stdout_lock:
            sys.stdout.write(line)
            sys.stdout.flush()


class _RPCError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


async def _await(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _json_default(o: Any) -> Any:
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if hasattr(o, "__dict__"):
        return o.__dict__
    return str(o)


def _default_gate() -> "Any | None":
    """Build a default InboundGate. Returns None if cognitiond cannot be
    reached AND we're not in insecure-dev mode — in that case, the
    server boots without a gate and every tool call will be denied
    until the operator either sets ``HXXPSIN_COGNITION_INSECURE=1`` or
    provides SVIDs and starts cognitiond."""
    try:
        from cognition_client import CognitionClient  # type: ignore[import-not-found]
        from identity import load as load_identity  # type: ignore[import-not-found]
        from .inbound_gate import InboundGate
    except Exception as e:
        log.warning("inbound gate disabled (import failure): %s", e)
        return None

    identity = load_identity()
    client = CognitionClient()
    return InboundGate(client=client, agent_actor_id=identity.actor_id)
