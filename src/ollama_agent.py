"""Stub — the Ollama ReAct loop is retired.

This module historically drove a tool-use agent against a local Ollama
model using a hand-rolled ReAct prompt. After the servus + cognitiond
migration, all LLM traffic goes through ``ServusLLMClient`` and the
3-stage solver pipeline in [challenge_solver.py](challenge_solver.py)
replaces the multi-turn agent. ``run_ollama_agent`` is kept only so the
existing import in ``main.py`` doesn't break.

If you need a tool-use loop again, drive it from ``main.py`` against
``servus_client.ServusLLMClient.generate`` directly — servus already
returns ``tool_calls`` on a single round-trip.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Optional

from claude_client import AgentTrace, AgentTurn  # stubs preserved for import compat

log = logging.getLogger(__name__)


ToolExecutor = Callable[[str, dict], Awaitable[dict]]


async def run_ollama_agent(
    *,
    llm_client: Any,
    system: str,
    user_prompt: str,
    tools: list[dict],
    tool_executor: ToolExecutor,
    max_turns: int = 10,
    temperature: float = 0.0,
    thinking_budget: Optional[int] = None,
    on_turn: Optional[Callable[[AgentTurn], None]] = None,
    on_prompt: Optional[Callable[[str, str], None]] = None,
) -> AgentTrace:
    del (
        llm_client,
        system,
        user_prompt,
        tools,
        tool_executor,
        max_turns,
        temperature,
        thinking_budget,
        on_turn,
        on_prompt,
    )
    log.warning(
        "run_ollama_agent: retired — solver path now uses ServusLLMClient + the "
        "3-stage pipeline in challenge_solver.py. Returning empty AgentTrace."
    )
    trace = AgentTrace()
    trace.error = "ollama ReAct agent retired; use challenge_solver three-stage path"
    return trace
