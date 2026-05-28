"""Tests for the InboundGate that wraps MCP/A2A tool dispatch.

Verifies:
  - insecure mode skips cognitiond entirely (DEV ONLY)
  - allow-verdict produces a CommitToken; commit is called on success
  - deny-verdict raises GateDenied with the policy reason
  - metadata extraction tolerates both MCP _meta (snake_case) and A2A
    metadata (camelCase) shapes

Uses a fake CognitionClient — does not touch the network.

Run:  python -m pytest tests/test_inbound_gate.py -v
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_agent.inbound_gate import GateDenied, InboundGate  # noqa: E402


@dataclass
class _FakeEvaluateResult:
    decision: dict = field(default_factory=lambda: {"kind": "allow", "reason": ""})
    session_id: str = "sess-1"
    commit_id: str | None = "commit-1"
    trajectory_hash: str = ""
    crs: float = 1.0
    body: dict = field(default_factory=dict)


class _FakeClient:
    def __init__(self, *, decision: str = "allow", reason: str = ""):
        self.decision = decision
        self.reason = reason
        self.evaluate_calls: list[dict] = []
        self.commit_calls: list[dict] = []

    async def evaluate(self, **kwargs: Any) -> _FakeEvaluateResult:
        self.evaluate_calls.append(kwargs)
        return _FakeEvaluateResult(
            decision={"kind": self.decision, "reason": self.reason}
        )

    async def commit(self, *, commit_id: str, response_body):
        self.commit_calls.append({"commit_id": commit_id, "body": response_body})
        return {"ok": True}


@pytest.mark.asyncio
async def test_insecure_mode_short_circuits():
    client = _FakeClient(decision="deny", reason="should not be called")
    gate = InboundGate(client=client, agent_actor_id="spiffe://x", insecure=True)
    token = await gate.authorize(
        tool_name="probe_idor", arguments={"url": "http://t"}, metadata={}
    )
    assert token.commit_id is None
    assert client.evaluate_calls == []
    # commit is a no-op in insecure mode
    await gate.commit(token, result_payload={"ok": True})
    assert client.commit_calls == []


@pytest.mark.asyncio
async def test_allow_verdict_returns_commit_token_and_calls_commit():
    client = _FakeClient(decision="allow")
    gate = InboundGate(client=client, agent_actor_id="spiffe://x", insecure=False)
    token = await gate.authorize(
        tool_name="probe_idor",
        arguments={"url": "http://t"},
        metadata={"initiatorSubject": "alice"},
    )
    assert token.commit_id == "commit-1"
    await gate.commit(token, result_payload={"verdict": "confirmed"})
    assert len(client.commit_calls) == 1
    assert client.commit_calls[0]["commit_id"] == "commit-1"


@pytest.mark.asyncio
async def test_deny_verdict_raises_gate_denied():
    client = _FakeClient(decision="deny", reason="probe family not authorized")
    gate = InboundGate(client=client, agent_actor_id="spiffe://x", insecure=False)
    with pytest.raises(GateDenied) as exc:
        await gate.authorize(
            tool_name="probe_command_injection",
            arguments={"url": "http://t"},
            metadata={"initiatorSubject": "alice"},
        )
    assert "not authorized" in str(exc.value)


@pytest.mark.asyncio
async def test_metadata_camelcase_a2a_shape():
    client = _FakeClient()
    gate = InboundGate(client=client, agent_actor_id="spiffe://agent", insecure=False)
    await gate.authorize(
        tool_name="repeater",
        arguments={"url": "http://x"},
        metadata={
            "initiatorSubject": "alice",
            "delegationChain": ["alice", "secretarius"],
            "delegationTicket": "tkt-1",
            "sessionId": "s-99",
        },
    )
    call = client.evaluate_calls[0]
    assert call["body"]["initiator"] == "alice"
    # actor_id auto-appended to chain when missing
    assert "spiffe://agent" in call["body"]["delegation_chain"]
    assert call["delegation_ticket"] == "tkt-1"
    assert call["session_id"] == "s-99"
    assert call["scope"] == "assistant:tool:hxxpsin:repeater"


@pytest.mark.asyncio
async def test_metadata_snake_case_mcp_shape():
    client = _FakeClient()
    gate = InboundGate(client=client, agent_actor_id="spiffe://agent", insecure=False)
    await gate.authorize(
        tool_name="decode",
        arguments={"value": "abc"},
        metadata={
            "initiator_subject": "bob",
            "delegation_chain": ["bob", "secretarius"],
            "delegation_ticket": "tkt-2",
        },
    )
    call = client.evaluate_calls[0]
    assert call["body"]["initiator"] == "bob"
    assert call["delegation_ticket"] == "tkt-2"
