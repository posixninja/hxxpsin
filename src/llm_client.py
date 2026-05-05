"""
llm_client.py — Local LLM client (Ollama default; provider-pluggable later).

Ollama is the only provider for v1. Local-only by design — no data leaves the
operator's machine, which matters when the LLM is being fed real response
bodies that may contain customer PII.

API used: POST http://<host>/api/generate
  - body: {"model": "qwen2.5:7b", "prompt": "...", "stream": false,
           "format": "json", "options": {"temperature": 0.0, ...}}
  - response: {"response": "...", "done": true, ...}

Caching: every (model, prompt) pair is sha256-hashed and cached on disk so
re-running a scan doesn't re-spend tokens. Cache lives under <out>/llm_cache/.

Budget: caller supplies a max-call budget; client refuses further requests
once exhausted (returns LLMResponse with verdict="budget_exhausted").
"""

import asyncio
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx


_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "qwen2.5:7b"


@dataclass
class LLMResponse:
    raw_text: str
    parsed: Optional[dict] = None      # if response was valid JSON
    cached: bool = False
    elapsed_ms: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.raw_text)


@dataclass
class LLMStats:
    calls_made: int = 0
    cache_hits: int = 0
    errors: int = 0
    total_elapsed_ms: int = 0
    budget_exhausted: bool = False


class LLMClient:
    def __init__(self, host: str = _DEFAULT_OLLAMA_HOST,
                 model: str = _DEFAULT_MODEL,
                 cache_dir: Optional[str] = None,
                 budget: int = 50,
                 timeout: float = 60.0,
                 verbose: bool = False):
        self.host = host.rstrip("/")
        self.model = model
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.timeout = timeout
        self.verbose = verbose
        self.stats = LLMStats()
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout, verify=False,
            headers={"Content-Type": "application/json"},
        )
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    async def is_alive(self) -> bool:
        """Probe Ollama's /api/tags. Returns False if Ollama is not running
        or doesn't respond — callers should warn the user and skip LLM steps."""
        if self._client is None:
            return False
        try:
            r = await self._client.get(f"{self.host}/api/tags", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False

    async def generate(self, prompt: str, system: str = "",
                       expect_json: bool = True,
                       temperature: float = 0.0,
                       max_tokens: int = 512) -> LLMResponse:
        """Send a single prompt to the model. Returns LLMResponse with the
        raw text and (if expect_json) parsed dict if it was valid JSON."""
        cache_key = self._cache_key(self.model, system, prompt, temperature)
        cached = self._read_cache(cache_key)
        if cached is not None:
            self.stats.cache_hits += 1
            return LLMResponse(
                raw_text=cached, parsed=self._maybe_parse_json(cached),
                cached=True,
            )
        if self.stats.calls_made >= self.budget:
            self.stats.budget_exhausted = True
            return LLMResponse(
                raw_text="", error=f"budget exhausted ({self.budget} calls)",
            )
        if self._client is None:
            return LLMResponse(raw_text="", error="client not initialized")

        body: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            body["system"] = system
        if expect_json:
            body["format"] = "json"

        t0 = time.monotonic()
        try:
            r = await self._client.post(f"{self.host}/api/generate", json=body)
        except Exception as exc:
            self.stats.errors += 1
            return LLMResponse(raw_text="", error=f"{type(exc).__name__}: {exc}")
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        self.stats.calls_made += 1
        self.stats.total_elapsed_ms += elapsed_ms

        if r.status_code != 200:
            self.stats.errors += 1
            return LLMResponse(
                raw_text="", elapsed_ms=elapsed_ms,
                error=f"http {r.status_code}: {r.text[:200]}",
            )
        try:
            data = r.json()
            text = data.get("response", "")
        except Exception as exc:
            self.stats.errors += 1
            return LLMResponse(
                raw_text="", elapsed_ms=elapsed_ms,
                error=f"non-json response: {exc}",
            )
        if self.verbose:
            print(f"  [llm] {self.model} {elapsed_ms}ms → {text[:80]}",
                  file=sys.stderr)
        self._write_cache(cache_key, text)
        return LLMResponse(
            raw_text=text, parsed=self._maybe_parse_json(text),
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(model: str, system: str, prompt: str,
                   temperature: float) -> str:
        h = hashlib.sha256()
        h.update(model.encode())
        h.update(b"\x00")
        h.update(system.encode())
        h.update(b"\x00")
        h.update(prompt.encode())
        h.update(b"\x00")
        h.update(str(temperature).encode())
        return h.hexdigest()[:24]

    def _read_cache(self, key: str) -> Optional[str]:
        if not self.cache_dir:
            return None
        path = self.cache_dir / f"{key}.txt"
        if not path.exists():
            return None
        try:
            return path.read_text()
        except Exception:
            return None

    def _write_cache(self, key: str, text: str) -> None:
        if not self.cache_dir:
            return
        try:
            (self.cache_dir / f"{key}.txt").write_text(text)
        except Exception:
            pass

    @staticmethod
    def _maybe_parse_json(text: str) -> Optional[dict]:
        text = text.strip()
        if not text:
            return None
        # Ollama in format=json mode returns valid JSON, but defend against
        # the model wrapping it in ```json ... ``` fences anyway.
        if text.startswith("```"):
            text = text.strip("`").lstrip("json").strip()
        try:
            return json.loads(text)
        except Exception:
            return None
