"""Ollama-shaped LLM client — now a thin shim over servus.

Historically this module talked directly to a local Ollama process via
``POST /api/generate``. Now all LLM traffic routes through servus's
cognition-gated chat-complete endpoint instead. ``LLMClient`` is
preserved as a public class only so existing callers (``main.py``,
``challenge_solver.py``, ``llm_verifier.py``) keep working — internally
it just delegates to [ServusLLMClient](servus_client.py) with
``provider="ollama"`` (servus is responsible for talking to the local
Ollama daemon if configured that way).

What's preserved: ``LLMResponse`` dataclass, ``LLMStats``,
``LLMClient.generate(prompt, system, expect_json, temperature,
max_tokens)``, the disk cache, the budget counter, and
``LLMClient.is_alive()``.

What changed: ``host`` / model selection are advisory — servus picks
the actual model based on its own config.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from servus_client import ServusClientError, ServusLLMClient
from servus_response_cache import (
    cache_key,
    maybe_parse_json,
    read_cache,
    write_cache,
)


_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "qwen2.5:7b"


@dataclass
class LLMResponse:
    raw_text: str
    parsed: Optional[dict] = None
    cached: bool = False
    elapsed_ms: int = 0
    error: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.raw_text)


@dataclass
class LLMStats:
    calls_made: int = 0
    cache_hits: int = 0
    errors: int = 0
    total_elapsed_ms: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    budget_exhausted: bool = False


class LLMClient:
    """Ollama-flavored facade over servus. Sets ``provider="ollama"``."""

    PROVIDER = "ollama"

    def __init__(
        self,
        host: str = _DEFAULT_OLLAMA_HOST,
        model: str = _DEFAULT_MODEL,
        cache_dir: Optional[str] = None,
        budget: int = 50,
        timeout: float = 60.0,
        verbose: bool = False,
        servus: Optional[ServusLLMClient] = None,
    ):
        self.host = host.rstrip("/")  # advisory; servus picks actual upstream
        self.model = model
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.timeout = timeout
        self.verbose = verbose
        self.stats = LLMStats()
        self._servus = servus or ServusLLMClient(timeout_s=timeout)

    async def __aenter__(self) -> "LLMClient":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def is_alive(self) -> bool:
        """Probe servus /health. We don't ping Ollama directly anymore."""
        try:
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
        max_tokens: int = 512,
    ) -> LLMResponse:
        del temperature, max_tokens

        key = cache_key(self.PROVIDER, self.model, system, prompt)
        cached = read_cache(self.cache_dir, key)
        if cached is not None:
            self.stats.cache_hits += 1
            return LLMResponse(raw_text=cached, parsed=maybe_parse_json(cached), cached=True)
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
                f"  [llm→servus] {reply.model or self.model} {elapsed_ms}ms → {text[:80]}",
                file=sys.stderr,
            )
        write_cache(self.cache_dir, key, text)
        return LLMResponse(
            raw_text=text,
            parsed=maybe_parse_json(text) if expect_json else None,
            elapsed_ms=elapsed_ms,
        )
