"""ReAct-style tool-use loop on top of the single-shot servus generate().

The shape we ask the LLM to produce:

    THOUGHT: <free-form reasoning>
    TOOL: <tool_name>
    ARGS: {"json": "..."}

…or, when finished:

    THOUGHT: <reasoning>
    ANSWER: <final reply for the user>

We loop: render the running transcript → call ``llm_generate(prompt,
system, expect_json=False)`` → parse → if it's a TOOL line, dispatch
through the MCP client and append the observation; if it's an ANSWER,
stop. Hard cap on iterations so a confused model can't burn budget.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .mcp_stdio import MCPClientError, MCPStdioClient, MCPTool


# Type of the LLM's generate function — we accept anything that takes
# (prompt, system, expect_json) kwargs and returns an awaitable with
# `.raw_text` / `.error`. Both ClaudeClient and OpenAIClient match.
LLMGenerate = Callable[..., Awaitable[Any]]


# Hard upper bound. With 5–7 tools the model rarely chains more than 3.
_DEFAULT_MAX_TURNS = 6


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result_text: str = ""
    is_error: bool = False
    elapsed_ms: int = 0


@dataclass
class ChatTurn:
    user: str
    assistant: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    error: str = ""


def build_system_prompt(tools: list[MCPTool], context: str = "") -> str:
    """Render the tool catalog into a single system prompt."""
    lines = [
        "You are an offensive web-recon assistant embedded in the hxxpsin TUI.",
        "You have access to the following MCP tools exposed by hxxpsin itself.",
        "Use them whenever they help answer the operator's question — do NOT make up findings.",
        "",
        "When you want to call a tool, reply with EXACTLY this format and nothing else:",
        "",
        "  THOUGHT: <one or two sentences of reasoning>",
        "  TOOL: <tool_name>",
        "  ARGS: <single-line JSON object of arguments>",
        "",
        "When you are done and ready to reply to the operator, use this format:",
        "",
        "  THOUGHT: <reasoning>",
        "  ANSWER: <markdown reply for the operator>",
        "",
        "Rules:",
        "- Emit exactly ONE THOUGHT and exactly ONE of (TOOL+ARGS) or ANSWER per turn.",
        "- ARGS must be valid JSON on a single line.",
        "- Prefer terse ANSWERs — the operator is reading a TUI panel.",
        "- If a tool errors, try a different approach or ANSWER explaining the failure.",
        "",
        "Available tools:",
    ]
    for t in tools:
        schema_props = (t.input_schema or {}).get("properties", {}) or {}
        required = (t.input_schema or {}).get("required", []) or []
        args_blurb = ", ".join(
            f"{name}{'*' if name in required else ''}: {(spec or {}).get('type', '?')}"
            for name, spec in schema_props.items()
        ) or "(no arguments)"
        desc = (t.description or "").replace("\n", " ").strip()
        lines.append(f"- {t.name}({args_blurb}) — {desc}")

    if context:
        lines += ["", "Current scan context:", context]
    return "\n".join(lines)


_TOOL_RE = re.compile(r"^\s*TOOL:\s*([A-Za-z0-9_\-]+)\s*$", re.MULTILINE)
_ARGS_RE = re.compile(r"^\s*ARGS:\s*(.+?)\s*$", re.MULTILINE)
_ANSWER_RE = re.compile(r"^\s*ANSWER:\s*(.+)$", re.MULTILINE | re.DOTALL)


def parse_llm_reply(text: str) -> tuple[str | None, str | None, dict | None]:
    """Return (answer, tool_name, args) — exactly one of (answer) or
    (tool_name+args) should be non-None for a well-formed reply.

    Returns (None, None, None) when the reply is unparseable; the loop
    treats that as an implicit ANSWER (raw text)."""
    ans = _ANSWER_RE.search(text)
    if ans:
        return ans.group(1).strip(), None, None

    tm = _TOOL_RE.search(text)
    if not tm:
        return None, None, None
    am = _ARGS_RE.search(text)
    if not am:
        # TOOL without ARGS — assume empty
        return None, tm.group(1).strip(), {}
    raw_args = am.group(1).strip()
    try:
        parsed = json.loads(raw_args)
        if not isinstance(parsed, dict):
            parsed = {}
    except json.JSONDecodeError:
        parsed = {}
    return None, tm.group(1).strip(), parsed


def render_transcript(
    user_msg: str,
    history: list[tuple[str, str, list[ToolCall]]],
    current_calls: list[ToolCall],
) -> str:
    """Build the prompt body sent to ``generate()`` each iteration.

    ``history`` is prior (user, assistant, tool_calls) tuples from this
    session; ``current_calls`` are tool calls already executed for the
    in-flight turn (we re-feed them so the LLM sees its own
    observations)."""
    parts: list[str] = []
    for u, a, calls in history:
        parts.append(f"OPERATOR: {u}")
        for c in calls:
            parts.append(
                f"OBSERVATION ({c.name}): "
                f"{'[error] ' if c.is_error else ''}{_clip(c.result_text, 1200)}"
            )
        if a:
            parts.append(f"ASSISTANT: {a}")
    parts.append(f"OPERATOR: {user_msg}")
    for c in current_calls:
        parts.append(
            f"OBSERVATION ({c.name}): "
            f"{'[error] ' if c.is_error else ''}{_clip(c.result_text, 1200)}"
        )
    parts.append("ASSISTANT:")
    return "\n\n".join(parts)


def _clip(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


async def run_react_turn(
    *,
    user_msg: str,
    history: list[tuple[str, str, list[ToolCall]]],
    system_prompt: str,
    llm_generate: LLMGenerate,
    mcp: MCPStdioClient,
    max_turns: int = _DEFAULT_MAX_TURNS,
    on_step: Callable[[str, dict], None] | None = None,
) -> ChatTurn:
    """Run one operator → assistant exchange, possibly with intermediate
    tool calls. Returns a ChatTurn carrying the final assistant text plus
    every tool call made along the way.

    ``on_step`` (if provided) is called with ('thought'|'tool_call'|
    'tool_result'|'answer', payload) so the UI can stream progress."""
    import time

    turn = ChatTurn(user=user_msg)
    calls: list[ToolCall] = []

    for iteration in range(max_turns):
        prompt = render_transcript(user_msg, history, calls)
        try:
            reply = await llm_generate(
                prompt=prompt, system=system_prompt, expect_json=False,
            )
        except Exception as exc:
            turn.error = f"LLM error: {exc}"
            turn.assistant = turn.error
            return turn

        text = (getattr(reply, "raw_text", "") or "").strip()
        err = getattr(reply, "error", "") or ""
        if err and not text:
            turn.error = f"LLM error: {err}"
            turn.assistant = turn.error
            return turn

        answer, tool_name, tool_args = parse_llm_reply(text)

        if answer is not None:
            if on_step:
                on_step("answer", {"text": answer})
            turn.assistant = answer
            turn.tool_calls = calls
            return turn

        if tool_name is None:
            # Unparseable — treat the whole reply as the answer to avoid wedging.
            if on_step:
                on_step("answer", {"text": text})
            turn.assistant = text or "(empty LLM reply)"
            turn.tool_calls = calls
            return turn

        if on_step:
            on_step("tool_call", {"name": tool_name, "arguments": tool_args or {}})

        t0 = time.monotonic()
        try:
            envelope = mcp.call_tool(tool_name, tool_args or {})
        except MCPClientError as exc:
            call = ToolCall(
                name=tool_name, arguments=tool_args or {},
                result_text=str(exc), is_error=True,
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )
            calls.append(call)
            if on_step:
                on_step("tool_result", {"name": tool_name, "ok": False, "text": str(exc)})
            continue

        result_text = _extract_text(envelope)
        call = ToolCall(
            name=tool_name, arguments=tool_args or {},
            result_text=result_text,
            is_error=bool(envelope.get("isError")),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
        calls.append(call)
        if on_step:
            on_step(
                "tool_result",
                {"name": tool_name, "ok": not call.is_error, "text": result_text},
            )

    turn.error = f"hit max_turns={max_turns} without an ANSWER"
    turn.assistant = turn.error
    turn.tool_calls = calls
    return turn


def _extract_text(envelope: dict[str, Any]) -> str:
    """MCP wraps results in ``content: [{type: 'text', text: ...}, ...]``."""
    parts = envelope.get("content") or []
    out: list[str] = []
    for p in parts:
        if isinstance(p, dict) and p.get("type") == "text":
            t = p.get("text") or ""
            if t:
                out.append(t)
    return "\n".join(out) if out else json.dumps(envelope)
