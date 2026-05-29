"""Cognitiond-backed authorization gate for MCP / A2A inbound calls.

Per the integration plan, hxxpsin gates INBOUND tool invocations against
SecurisNexus policy so a compromised MCP host can't make it probe
arbitrary targets. Outbound probe traffic itself is NOT gated — that's
a deliberate scope choice.

Wire shape (per ``cognition_client.evaluate``):

    scope:  assistant:tool:hxxpsin:<tool_name>
    body:   {"arguments": <tool args>,
             "initiator": <caller subject>,
             "delegation_chain": [<caller>, ..., hxxpsin actor>]}

Servus's ``A2AClient.send_task`` populates ``params.metadata`` with the
initiator + delegation chain (camelCase ``initiatorSubject`` /
``delegationChain``), and its MCP client carries them under an ``_meta``
extension on ``tools/call``. We accept both shapes so the same gate
works for both transports.

When cognitiond is unreachable or no SVID is configured, the gate
defers to ``HXXPSIN_COGNITION_INSECURE``:

- ``=1``  → allow everything (DEV ONLY, logs a WARNING)
- unset   → deny by default so we fail closed in production

Caller pattern::

    gate = InboundGate(client, agent_actor_id, identity)
    token = await gate.authorize(tool_name="scan_full",
                                  arguments={...},
                                  metadata={"initiatorSubject": "alice"})
    try:
        result = await dispatch(...)
    finally:
        await gate.commit(token, result_payload=result)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

log = logging.getLogger(__name__)


_DEFAULT_SCOPE_PREFIX = "assistant:tool:hxxpsin"


@dataclass(frozen=True)
class CommitToken:
    """Returned by ``authorize``; pass to ``commit`` after the tool runs.

    ``commit_id`` is None when running in insecure-dev mode — ``commit``
    becomes a no-op in that case.
    """

    commit_id: Optional[str]
    session_id: Optional[str] = None


class GateDenied(PermissionError):
    """Cognitiond returned a deny verdict (or we failed closed)."""


class InboundGate:
    """One per process. Wraps an async cognitiond client."""

    def __init__(
        self,
        client: Any,  # cognition_client.CognitionClient
        agent_actor_id: str,
        *,
        scope_prefix: str = _DEFAULT_SCOPE_PREFIX,
        insecure: Optional[bool] = None,
    ) -> None:
        self._client = client
        self._agent_actor_id = agent_actor_id
        self._scope_prefix = scope_prefix
        if insecure is None:
            insecure = os.environ.get("HXXPSIN_COGNITION_INSECURE", "").lower() in (
                "1",
                "true",
                "yes",
            )
        self._insecure = bool(insecure)
        if self._insecure:
            log.warning(
                "InboundGate: HXXPSIN_COGNITION_INSECURE=1 — all tool calls allowed (DEV ONLY)"
            )

    async def authorize(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
        transport: str = "mcp",
    ) -> CommitToken:
        if self._insecure:
            return CommitToken(commit_id=None)

        initiator, chain, ticket, session_id = _extract_caller(metadata, self._agent_actor_id)
        scope = f"{self._scope_prefix}:{tool_name}"
        body = {
            "arguments": dict(arguments) if arguments else {},
            "initiator": initiator,
            "delegation_chain": list(chain),
            "transport": transport,
            "tool": tool_name,
        }
        try:
            result = await self._client.evaluate(
                actor_id=self._agent_actor_id,
                scope=scope,
                body=body,
                session_id=session_id,
                delegation_ticket=ticket,
                delegation_chain=chain,
            )
        except Exception as e:
            log.warning("InboundGate: cognitiond evaluate failed for %s: %s — failing closed", scope, e)
            raise GateDenied(f"cognitiond unreachable for {scope}: {e}") from e

        decision = result.decision or {}
        kind = (decision.get("kind") or "").lower()
        if kind != "allow":
            reason = decision.get("reason") or f"cognitiond denied {scope}"
            raise GateDenied(reason)

        return CommitToken(commit_id=result.commit_id, session_id=result.session_id)

    async def commit(
        self, token: CommitToken, *, result_payload: Optional[Mapping[str, Any]] = None
    ) -> None:
        if self._insecure or not token.commit_id:
            return
        try:
            await self._client.commit(
                commit_id=token.commit_id,
                response_body=dict(result_payload) if result_payload else None,
            )
        except Exception as e:
            log.warning("InboundGate: cognitiond commit failed for %s: %s", token.commit_id, e)


# ---------------------------------------------------------------------------
# Metadata extraction — accept both camelCase (A2A) and snake_case (MCP _meta)
# ---------------------------------------------------------------------------


def _extract_caller(
    metadata: Optional[Mapping[str, Any]], agent_actor_id: str
) -> tuple[str, list[str], Optional[str], Optional[str]]:
    md = dict(metadata or {})
    initiator = (
        md.get("initiator_subject")
        or md.get("initiatorSubject")
        or md.get("initiator")
        or os.environ.get("HXXPSIN_DEFAULT_INITIATOR")
        or "unknown:anonymous"
    )
    raw_chain = (
        md.get("delegation_chain")
        or md.get("delegationChain")
        or [initiator, agent_actor_id]
    )
    chain = [str(x) for x in raw_chain]
    if agent_actor_id not in chain:
        chain.append(agent_actor_id)
    ticket = md.get("delegation_ticket") or md.get("delegationTicket")
    session_id = md.get("session_id") or md.get("sessionId")
    return str(initiator), chain, (str(ticket) if ticket else None), (str(session_id) if session_id else None)
