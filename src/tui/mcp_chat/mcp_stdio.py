"""Thin stdio JSON-RPC client for the hxxpsin MCP server.

Spawns ``python3 -m mcp_agent`` as a subprocess, performs the MCP
2024-11-05 handshake (``initialize`` + ``notifications/initialized``),
and exposes ``list_tools`` / ``call_tool`` over the same line protocol
the server speaks. One request at a time — sufficient for a single
chat loop and avoids inventing a multiplexer over a stdio pipe.

The TUI runs this from a background thread; methods block until the
server replies. The subprocess inherits ``HXXPSIN_COGNITION_INSECURE``
from the operator's environment, which is the same knob the rest of
the codebase uses to allow tool calls in dev.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_PROTOCOL_VERSION = "2024-11-05"


class MCPClientError(RuntimeError):
    """Wraps both JSON-RPC errors and transport-level failures."""


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict[str, Any]


class MCPStdioClient:
    """Subprocess-backed MCP client. Not thread-safe; serialize calls."""

    def __init__(
        self,
        *,
        python: str | None = None,
        src_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self._python = python or sys.executable
        # mcp_agent lives in src/; we need PYTHONPATH=src/ for `python -m mcp_agent`
        # to resolve its sibling-module imports (`identity`, `cognition_client`).
        self._src_dir = src_dir or Path(__file__).resolve().parents[2]
        self._env = env
        self._proc: subprocess.Popen | None = None
        self._next_id = 1
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        env = dict(os.environ)
        if self._env:
            env.update(self._env)
        existing_pp = env.get("PYTHONPATH", "")
        src = str(self._src_dir)
        env["PYTHONPATH"] = f"{src}:{existing_pp}" if existing_pp else src

        self._proc = subprocess.Popen(
            [self._python, "-m", "mcp_agent"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self._src_dir),
            env=env,
            bufsize=1,
            text=True,
        )
        # Handshake: initialize + notifications/initialized
        try:
            self._rpc(
                "initialize",
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "hxxpsin-tui-chat", "version": "0.1.0"},
                },
            )
            self._notify("notifications/initialized", {})
        except Exception as e:
            self.stop()
            raise MCPClientError(f"handshake failed: {e}") from e

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
        finally:
            self._proc = None

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # -- public API -------------------------------------------------------

    def list_tools(self) -> list[MCPTool]:
        result = self._rpc("tools/list", {})
        out: list[MCPTool] = []
        for entry in result.get("tools", []):
            out.append(
                MCPTool(
                    name=entry["name"],
                    description=entry.get("description", ""),
                    input_schema=entry.get("inputSchema", {}),
                )
            )
        return out

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Returns the raw MCP `{content:[...], isError:bool}` envelope."""
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    # -- low level --------------------------------------------------------

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._ensure_running()
            rid = self._next_id
            self._next_id += 1
            envelope = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
            self._write(envelope)
            line = self._read_line()
            if not line:
                raise MCPClientError(f"mcp_agent closed stdout while waiting for {method}")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError as e:
                raise MCPClientError(f"non-JSON reply from mcp_agent: {line!r}") from e
            if "error" in reply:
                err = reply["error"]
                raise MCPClientError(
                    f"{method} → {err.get('code')}: {err.get('message')}"
                )
            return reply.get("result") or {}

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        with self._lock:
            self._ensure_running()
            self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _ensure_running(self) -> None:
        if self._proc is None or self._proc.poll() is not None:
            raise MCPClientError("mcp_agent subprocess is not running")

    def _write(self, payload: dict[str, Any]) -> None:
        assert self._proc and self._proc.stdin
        line = json.dumps(payload) + "\n"
        try:
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
        except BrokenPipeError as e:
            raise MCPClientError("mcp_agent stdin closed") from e

    def _read_line(self) -> str:
        assert self._proc and self._proc.stdout
        return self._proc.stdout.readline()

    def drain_stderr(self, max_chars: int = 4096) -> str:
        """Best-effort scrape of buffered stderr — useful for the chat panel
        to surface why a subprocess died. Non-blocking via select()."""
        if self._proc is None or self._proc.stderr is None:
            return ""
        try:
            import select
            chunks: list[str] = []
            while True:
                r, _, _ = select.select([self._proc.stderr], [], [], 0)
                if not r:
                    break
                buf = os.read(self._proc.stderr.fileno(), 1024).decode(errors="replace")
                if not buf:
                    break
                chunks.append(buf)
                if sum(len(c) for c in chunks) >= max_chars:
                    break
            return "".join(chunks)[-max_chars:]
        except Exception:
            return ""
