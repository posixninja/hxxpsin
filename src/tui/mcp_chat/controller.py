"""ChatController — owns the MCP subprocess, the LLM client, and chat state.

The Dashboard panel hands operator messages here; the controller runs
the ReAct loop in a worker thread and posts results back through a
callback the panel registers. State (history, last error, MCP liveness)
lives on this object so the panel can be torn down + rebuilt without
losing context.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .mcp_stdio import MCPClientError, MCPStdioClient, MCPTool
from .react_loop import (
    ChatTurn,
    ToolCall,
    build_system_prompt,
    run_react_turn,
)
from .servus_supervisor import ServusStatus, ServusSupervisor


log = logging.getLogger(__name__)


@dataclass
class ChatSnapshot:
    """Immutable-ish view of chat state for the panel to render."""

    history: list[ChatTurn] = field(default_factory=list)
    mcp_alive: bool = False
    tools: list[MCPTool] = field(default_factory=list)
    last_error: str = ""
    provider: str = ""
    model: str = ""


class ChatController:
    """One per HxxpsinApp. Lazy-starts MCP; lazy-builds the LLM client."""

    def __init__(self, *, state: Any | None = None) -> None:
        self._state = state
        self._mcp = MCPStdioClient()
        self._servus = ServusSupervisor()
        self._tools: list[MCPTool] = []
        self._history: list[ChatTurn] = []
        self._last_error: str = ""
        self._provider: str = ""
        self._model: str = ""

    # -- lifecycle --------------------------------------------------------

    def ensure_mcp(self) -> tuple[bool, str]:
        """Boot the MCP server and cache the tool list. Returns
        (ok, message). Safe to call repeatedly."""
        if self._mcp.is_alive() and self._tools:
            return True, f"MCP up ({len(self._tools)} tools)"
        try:
            self._mcp.start()
            self._tools = self._mcp.list_tools()
            return True, f"MCP up ({len(self._tools)} tools)"
        except MCPClientError as e:
            stderr = self._mcp.drain_stderr()
            msg = f"{e}\n{stderr}" if stderr else str(e)
            self._last_error = msg
            return False, msg
        except Exception as e:  # subprocess/IO error
            self._last_error = f"{type(e).__name__}: {e}"
            return False, self._last_error

    def stop(self) -> None:
        self._mcp.stop()
        self._servus.stop()

    def ensure_servus(self) -> ServusStatus:
        """Boot servus if it isn't already listening. Returns the status
        so the panel can surface what happened (already up / spawned /
        failed)."""
        return self._servus.ensure_running()

    # -- snapshot ---------------------------------------------------------

    def snapshot(self) -> ChatSnapshot:
        return ChatSnapshot(
            history=list(self._history),
            mcp_alive=self._mcp.is_alive(),
            tools=list(self._tools),
            last_error=self._last_error,
            provider=self._provider,
            model=self._model,
        )

    # -- chat loop --------------------------------------------------------

    def send(
        self,
        user_msg: str,
        *,
        on_step: Callable[[str, dict], None] | None = None,
    ) -> ChatTurn:
        """Blocking: drives the ReAct loop to completion and returns the
        final ChatTurn. Designed to be called from a Textual worker
        thread."""
        if not user_msg.strip():
            return ChatTurn(user=user_msg, assistant="", error="empty message")

        ok, msg = self.ensure_mcp()
        if not ok:
            turn = ChatTurn(user=user_msg, assistant=f"MCP unavailable: {msg}", error=msg)
            self._history.append(turn)
            return turn

        # Make sure servus is reachable before we even try to build a
        # client — auto-spawn the daemon if it's down.
        if on_step:
            on_step("status", {"text": "checking servus…"})
        sstatus = self.ensure_servus()
        if not sstatus.running:
            turn = ChatTurn(
                user=user_msg,
                assistant=f"servus unavailable at {sstatus.url}: {sstatus.message}",
                error=sstatus.message,
            )
            self._history.append(turn)
            return turn
        if sstatus.owned and on_step:
            on_step("status", {"text": f"spawned servus (pid={sstatus.pid})"})

        try:
            client, generate, provider, model = _build_llm_client()
        except Exception as e:
            self._last_error = str(e)
            turn = ChatTurn(user=user_msg, assistant=f"LLM unavailable: {e}", error=str(e))
            self._history.append(turn)
            return turn

        self._provider, self._model = provider, model

        context = _scan_context(self._state)
        system_prompt = build_system_prompt(self._tools, context=context)
        prior = [(t.user, t.assistant, t.tool_calls) for t in self._history if not t.error]

        loop = asyncio.new_event_loop()
        try:
            async def _go() -> ChatTurn:
                async with client:
                    return await run_react_turn(
                        user_msg=user_msg,
                        history=prior,
                        system_prompt=system_prompt,
                        llm_generate=generate,
                        mcp=self._mcp,
                        on_step=on_step,
                    )

            turn = loop.run_until_complete(_go())
        finally:
            loop.close()

        self._history.append(turn)
        return turn

    def clear(self) -> None:
        self._history.clear()


# ---------------------------------------------------------------------------
# LLM client wiring — mirrors the pattern used by HxxpsinApp._run_quick_brief.
# ---------------------------------------------------------------------------


def _build_llm_client() -> tuple[Any, Any, str, str]:
    """Returns (client, async generate callable, provider, model).

    Routes through servus by way of the existing ClaudeClient /
    OpenAIClient shims so cognitiond stays in the loop."""
    src_path = str(Path(__file__).resolve().parents[2])
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    cfg_provider = "claude"
    servus_token = os.environ.get("SERVUS_AGENT_TOKEN")
    try:
        import auth_config  # type: ignore[import-not-found]

        cfg = auth_config.load()
        cfg_provider = (cfg.servus.default_provider or "claude").lower()
        if cfg.servus.agent_token:
            servus_token = cfg.servus.agent_token
    except Exception:
        pass

    if not servus_token:
        raise RuntimeError(
            "no SERVUS_AGENT_TOKEN — start servus and set the bearer "
            "(or configure [servus] in hxxpsin.toml)"
        )

    if cfg_provider == "openai":
        from openai_client import OpenAIClient  # type: ignore[import-not-found]

        model = "gpt-5"
        client = OpenAIClient(
            model=model, cache_dir=None, budget=20,
            timeout=120.0, max_tokens=2048, verbose=False,
        )
    else:
        from claude_client import ClaudeClient  # type: ignore[import-not-found]

        model = "claude-opus-4-7"
        client = ClaudeClient(
            model=model, cache_dir=None, budget=20,
            timeout=120.0, max_tokens=2048, verbose=False,
        )
    return client, client.generate, cfg_provider, model


def _scan_context(state: Any | None) -> str:
    """Render a tiny chunk of current AppState so the model can reference
    the active target / scan without having to call a tool for it."""
    if state is None:
        return ""
    bits: list[str] = []
    target = getattr(state, "target", None)
    if target:
        bits.append(f"- target: {target}")
    out_dir = getattr(state, "out_dir", None)
    if out_dir:
        bits.append(f"- out_dir: {out_dir}")
    reqs = getattr(state, "requests", None) or []
    if reqs:
        bits.append(f"- captured requests: {len(reqs)}")
    findings = getattr(state, "findings", None) or []
    if findings:
        bits.append(f"- findings so far: {len(findings)}")
    return "\n".join(bits)


__all__ = [
    "ChatController",
    "ChatSnapshot",
    "ChatTurn",
    "ToolCall",
]
