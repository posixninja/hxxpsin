"""Outbound LLM client — every LLM call hxxpsin makes goes through here.

hxxpsin used to talk to Anthropic / OpenAI / Ollama directly via
[claude_client.py](claude_client.py), [openai_client.py](openai_client.py),
[ollama_agent.py](ollama_agent.py), [llm_client.py](llm_client.py).
That bypassed SecurisNexus cognitive policy. This module is now the
single egress: every provider client is a thin shim over
``ServusLLMClient.generate``.

Wire shape matches servus's chat-complete endpoint
(``servus/secretarius/server/assistant_http_app.py:146-227``):

    POST {base_url}/v1/chat/complete
    Authorization: Bearer {token}
    {
      "messages":           [...],          # required
      "initiator_subject":  "user@host",   # required — audit & cognitiond
      "delegation_chain":   ["..."],        # optional; defaults to [initiator, agent]
      "delegation_ticket":  "...",          # optional, when policy requires it
      "session_id":         "...",          # optional, reuse a cognitive session
      "provider":           "openai",       # claude | openai | ollama
      "tools":              [...],          # optional OpenAI tool schemas
      "tool_choice":        "auto",         # only when tools supplied
      "system_prompt":      "...",          # optional override
      "correlation_id":     "..."           # optional
    }

Response is single-shot (servus doesn't stream today)::

    {
      "reply":                "...",
      "tool_calls":           [...],
      "provider":             "openai",
      "model":                "gpt-...",
      "cognitive_session_id": "...",
      "cognitive_decision":   {"kind": "allow", ...},
      "crs":                  0.95,
      "delegation_chain":     [...]
    }
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

import httpx

log = logging.getLogger(__name__)


@dataclass
class ServusReply:
    """Single-shot reply from servus's chat-complete."""

    reply: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    provider: Optional[str] = None
    model: Optional[str] = None
    cognitive_session_id: Optional[str] = None
    cognitive_decision: Mapping[str, Any] = field(default_factory=dict)
    crs: float = 0.0
    delegation_chain: list[str] = field(default_factory=list)
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return (self.cognitive_decision or {}).get("kind") == "allow"

    def as_text(self) -> str:
        """Convenience for callers that just want the reply text (e.g. JSON-mode probes)."""
        return self.reply or ""


class ServusClientError(RuntimeError):
    """HTTP-level or policy-level failure from the chat-complete call."""


class ServusLLMClient:
    """Stateful holder of base URL + bearer token + caller identity.

    Construct once per process. All callsites (challenge_solver, llm_verifier,
    briefing_generator, ...) share the same instance so cognitiond sees a
    coherent delegation chain.
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        initiator_subject: Optional[str] = None,
        delegation_chain: Optional[Sequence[str]] = None,
        session_id: Optional[str] = None,
        default_provider: Optional[str] = None,
        timeout_s: float = 180.0,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("SERVUS_ASSISTANT_URL")
            or "http://127.0.0.1:9847"
        ).rstrip("/")
        self.token = token or os.environ.get("SERVUS_AGENT_TOKEN") or ""
        self.initiator_subject = (
            initiator_subject
            or os.environ.get("HXXPSIN_INITIATOR_SUBJECT")
            or os.environ.get("USER")
            or "operator@hxxpsin"
        )
        self.delegation_chain = list(delegation_chain) if delegation_chain else None
        self.session_id = session_id
        self.default_provider = (
            default_provider
            or os.environ.get("HXXPSIN_DEFAULT_LLM_PROVIDER")
            or os.environ.get("SECRETARIUS_LLM_PROVIDER")
            or "openai"
        )
        self.timeout_s = timeout_s

    async def generate(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        system: Optional[str] = None,
        tools: Optional[Sequence[Mapping[str, Any]]] = None,
        tool_choice: Optional[str] = None,
        provider: Optional[str] = None,
        expect_json: bool = False,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        correlation_id: Optional[str] = None,
        delegation_ticket: Optional[str] = None,
    ) -> ServusReply:
        del temperature, max_tokens  # servus picks model params; pass via env if needed

        payload: dict[str, Any] = {
            "messages": list(messages),
            "initiator_subject": self.initiator_subject,
            "provider": (provider or self.default_provider),
            "correlation_id": correlation_id or uuid.uuid4().hex,
        }
        if self.delegation_chain:
            payload["delegation_chain"] = list(self.delegation_chain)
        if delegation_ticket:
            payload["delegation_ticket"] = delegation_ticket
        if self.session_id:
            payload["session_id"] = self.session_id
        if system:
            payload["system_prompt"] = system
        if tools:
            payload["tools"] = list(tools)
            if tool_choice:
                payload["tool_choice"] = tool_choice

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.base_url}/v1/chat/complete"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
        except httpx.HTTPError as e:
            raise ServusClientError(f"servus unreachable at {url}: {e}") from e

        if resp.status_code == 401:
            raise ServusClientError(
                "servus chat-complete unauthorized — set SERVUS_AGENT_TOKEN"
            )
        if resp.status_code >= 400:
            raise ServusClientError(
                f"servus chat-complete HTTP {resp.status_code}: {resp.text[:2000]}"
            )

        data = resp.json()
        reply = ServusReply(
            reply=str(data.get("reply") or ""),
            tool_calls=list(data.get("tool_calls") or []),
            provider=data.get("provider"),
            model=data.get("model"),
            cognitive_session_id=data.get("cognitive_session_id"),
            cognitive_decision=data.get("cognitive_decision") or {},
            crs=float(data.get("crs") or 0.0),
            delegation_chain=list(data.get("delegation_chain") or []),
            raw=data,
        )
        # If servus tells us the session_id, use it on subsequent turns so
        # the cognitive trajectory stays linked.
        if reply.cognitive_session_id and not self.session_id:
            self.session_id = reply.cognitive_session_id

        if expect_json and reply.reply:
            # Validate parseability up-front so callers don't have to.
            try:
                json.loads(reply.reply)
            except json.JSONDecodeError as e:
                log.warning("servus reply expected JSON but failed to parse: %s", e)

        if not reply.allowed and reply.cognitive_decision:
            log.warning(
                "servus reply not allowed: %s",
                (reply.cognitive_decision or {}).get("reason"),
            )

        return reply


# Module-level singleton — most callers just want one shared client.
_default: Optional[ServusLLMClient] = None


def default_client() -> ServusLLMClient:
    global _default
    if _default is None:
        _default = ServusLLMClient()
    return _default


def reset_default_client(client: ServusLLMClient | None = None) -> None:
    """For tests, or when explicit identity needs to be wired in at boot."""
    global _default
    _default = client


def configure_from_profile(profile: Any) -> ServusLLMClient:
    """Wire a ``ServusProfile`` (from ``auth_config.Config.servus``) into the
    module-level default client. Call once at boot from ``main.py`` so the
    [servus] TOML section actually takes effect across challenge_solver /
    llm_verifier / briefing_generator."""
    client = ServusLLMClient(
        base_url=profile.url,
        token=profile.agent_token,
        initiator_subject=profile.initiator_subject,
        default_provider=profile.default_provider,
    )
    reset_default_client(client)
    return client
