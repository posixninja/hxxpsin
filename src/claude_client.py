"""Anthropic-shaped LLM client — now a thin shim over servus.

Historically this module spoke the Anthropic Messages API directly.
Since hxxpsin became a SecurisNexus-registered workload, ALL outbound
LLM traffic routes through servus's cognition-gated chat-complete
endpoint instead. ``ClaudeClient`` is preserved as a public class only
so existing callers (``main.py``, ``challenge_solver.py``,
``llm_verifier.py``) keep working — internally it just delegates to
[ServusLLMClient](servus_client.py) with ``provider="claude"``.

What's preserved: class name, ``generate(prompt, system, expect_json,
temperature, max_tokens)`` returning an ``LLMResponse`` (which is what
the rest of the code actually uses — `.raw_text`, `.parsed`, etc.), the
disk cache, the budget counter, and ``ClaudeStats``.

What did NOT survive the rewrite:

- ``ANTHROPIC_API_KEY`` is no longer read here — servus holds the key.
- The multi-turn ``run_agent`` tool-use loop is gone. The 3-stage
  pipeline in ``challenge_solver.py`` only needs single-shot
  ``generate``. ``AgentTrace`` / ``AgentTurn`` are kept as no-op stubs
  because ``openai_client.py`` still imports them.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from llm_client import LLMResponse
from servus_client import ServusClientError, ServusLLMClient
from servus_response_cache import (
    cache_key,
    maybe_parse_json,
    read_cache,
    write_cache,
)


_DEFAULT_MODEL = "claude-opus-4-7"


@dataclass
class ClaudeStats:
    calls_made: int = 0
    cache_hits: int = 0
    errors: int = 0
    total_elapsed_ms: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    budget_exhausted: bool = False


@dataclass
class AgentTurn:
    """Stub kept for ``openai_client``'s historic import; tool-use loops
    are not driven from this file anymore."""

    role: str = "assistant"
    text: str = ""
    thinking: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    elapsed_ms: int = 0
    stop_reason: str = ""


@dataclass
class AgentTrace:
    """Stub — see [AgentTurn]."""

    turns: list[AgentTurn] = field(default_factory=list)
    final_text: str = ""
    final_parsed: Optional[dict] = None
    stop_reason: str = ""
    error: str = ""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    tool_calls_made: int = 0

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict:
        return {"stop_reason": self.stop_reason, "error": self.error, "turns": []}


class ClaudeClient:
    """Anthropic-shaped facade over [ServusLLMClient](servus_client.py).

    Sets ``provider="claude"`` on every call so servus routes to Anthropic.
    """

    PROVIDER = "claude"

    def __init__(
        self,
        api_key: Optional[str] = None,  # accepted for signature compat; unused
        model: str = _DEFAULT_MODEL,
        base_url: Optional[str] = None,  # ignored — servus has the upstream URL
        cache_dir: Optional[str] = None,
        budget: int = 20,
        timeout: float = 90.0,
        max_tokens: int = 2048,
        verbose: bool = False,
        servus: Optional[ServusLLMClient] = None,
    ):
        del api_key, base_url
        self.model = model
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.verbose = verbose
        self.stats = ClaudeStats()
        self._servus = servus or ServusLLMClient(timeout_s=timeout)

    async def __aenter__(self) -> "ClaudeClient":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    @property
    def host(self) -> str:
        return self._servus.base_url

    async def is_alive(self) -> bool:
        """Probe servus /health. Upstream API key validity is servus's concern."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self._servus.base_url}/health")
                return r.status_code == 200
        except Exception:
            return False

    async def generate(
        self,
        prompt: str,
        system: str = "",
        expect_json: bool = True,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        del temperature, max_tokens

        key = cache_key(self.PROVIDER, self.model, system, prompt)
        cached = read_cache(self.cache_dir, key)
        if cached is not None:
            self.stats.cache_hits += 1
            return LLMResponse(
                raw_text=cached, parsed=maybe_parse_json(cached), cached=True
            )
        if self.stats.calls_made >= self.budget:
            self.stats.budget_exhausted = True
            return LLMResponse(raw_text="", error=f"budget exhausted ({self.budget} calls)")

        t0 = time.monotonic()
        try:
            reply = await self._servus.generate(
                messages=[{"role": "user", "content": prompt}],
                system=system or None,
                provider=self.PROVIDER,
                expect_json=expect_json,
            )
        except ServusClientError as e:
            self.stats.errors += 1
            return LLMResponse(raw_text="", error=str(e))
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        self.stats.calls_made += 1
        self.stats.total_elapsed_ms += elapsed_ms

        if not reply.allowed and reply.cognitive_decision:
            reason = (reply.cognitive_decision or {}).get("reason") or "denied"
            self.stats.errors += 1
            return LLMResponse(raw_text="", elapsed_ms=elapsed_ms, error=f"cognitiond deny: {reason}")

        text = reply.reply or ""
        if self.verbose:
            print(
                f"  [claude→servus] {self.model} {elapsed_ms}ms → {text[:80]}",
                file=sys.stderr,
            )
        write_cache(self.cache_dir, key, text)
        return LLMResponse(
            raw_text=text,
            parsed=maybe_parse_json(text) if expect_json else None,
            elapsed_ms=elapsed_ms,
        )
