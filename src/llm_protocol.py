"""
llm_protocol.py — Unified LLM client protocol for hxxpsin providers.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional, Protocol, runtime_checkable


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Common surface for Claude, OpenAI, Ollama, and Servus-backed clients."""

    model: str

    async def is_alive(self) -> bool: ...

    async def generate(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        tools: Optional[list] = None,
        **kwargs: Any,
    ) -> Any: ...

    async def __aenter__(self) -> "LLMClientProtocol": ...

    async def __aexit__(self, *args: Any) -> None: ...


GenerateFn = Callable[..., Awaitable[Any]]


def adapt_servus_client(client: Any) -> LLMClientProtocol:
    """Wrap ServusLLMClient to the protocol (duck-typed adapter)."""
    return client  # ServusLLMClient already exposes generate + is_alive


def adapt_ollama(llm: Any) -> LLMClientProtocol:
    return llm


def adapt_claude(claude: Any) -> LLMClientProtocol:
    return claude


def adapt_openai(oa: Any) -> LLMClientProtocol:
    return oa


class ServusGenerateAdapter:
    """Wrap ServusLLMClient.generate(messages=...) as prompt-based LLMClientProtocol."""

    def __init__(self, client: Any, *, model: str = ""):
        self._client = client
        self.model = model or getattr(client, "default_provider", "servus")

    async def is_alive(self) -> bool:
        return bool(self._client.token or True)

    async def generate(self, prompt: str, *, system: Optional[str] = None, **kwargs: Any) -> Any:
        reply = await self._client.generate(
            messages=[{"role": "user", "content": prompt}],
            system=system,
            provider=kwargs.get("provider"),
            expect_json=kwargs.get("expect_json", False),
        )
        return reply.reply

    async def __aenter__(self) -> "ServusGenerateAdapter":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None


def adapt_servus_generate(client: Any) -> ServusGenerateAdapter:
    return ServusGenerateAdapter(client)
