"""HTTP client for SecurisNexus cognitiond — async port for hxxpsin.

Ported from ``servus/secretarius/cognition_client.py`` (which uses
``requests``). This module uses ``httpx.AsyncClient`` because the rest
of hxxpsin's HTTP surface is async.

Env vars (mirror the servus variants, with ``HXXPSIN_`` prefix so the
two services can carry distinct SVIDs in one shell):

- ``COGNITIOND_URL`` — base URL; default ``http://127.0.0.1:9451``.
- ``HXXPSIN_COGNITION_CLIENT_CERT`` / ``HXXPSIN_COGNITION_CLIENT_KEY``
  — mTLS SVID files. If unset, falls back to the ``SECRETARIUS_*``
  names so a single-tenant local dev environment Just Works.
- ``HXXPSIN_COGNITION_CA_PATH`` — CA bundle used to verify cognitiond.
- ``HXXPSIN_COGNITION_INSECURE=1`` — disable TLS verification (DEV ONLY).
- ``HXXPSIN_COGNITION_TIMEOUT`` — seconds; default 120.

Used by the inbound gate (see [mcp_agent/inbound_gate.py](mcp_agent/inbound_gate.py))
to authorize MCP/A2A tool invocations against SN policy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, MutableMapping, Optional, Sequence, Tuple

import httpx


def _client_cert() -> Optional[Tuple[str, str]]:
    cert = os.environ.get("HXXPSIN_COGNITION_CLIENT_CERT", "") or os.environ.get(
        "SECRETARIUS_COGNITION_CLIENT_CERT", ""
    )
    key = os.environ.get("HXXPSIN_COGNITION_CLIENT_KEY", "") or os.environ.get(
        "SECRETARIUS_COGNITION_CLIENT_KEY", ""
    )
    cert = cert.strip()
    key = key.strip()
    if cert and key:
        return (cert, key)
    return None


def _verify_arg() -> bool | str:
    insecure = (
        os.environ.get("HXXPSIN_COGNITION_INSECURE", "")
        or os.environ.get("SECRETARIUS_COGNITION_INSECURE", "")
    ).lower()
    if insecure in ("1", "true", "yes"):
        return False
    ca = (
        os.environ.get("HXXPSIN_COGNITION_CA_PATH", "")
        or os.environ.get("SECRETARIUS_COGNITION_CA_PATH", "")
    ).strip()
    return ca if ca else True


@dataclass
class CognitiveEvaluateResult:
    session_id: str
    trajectory_hash: str
    crs: float
    decision: Mapping[str, Any]
    body: MutableMapping[str, Any]
    commit_id: Optional[str]


class CognitionClient:
    def __init__(self, base_url: str | None = None) -> None:
        raw = (base_url or os.environ.get("COGNITIOND_URL") or "http://127.0.0.1:9451").rstrip("/")
        self.base_url = raw
        self._cert = _client_cert()
        self._timeout = float(
            os.environ.get("HXXPSIN_COGNITION_TIMEOUT")
            or os.environ.get("SECRETARIUS_COGNITION_TIMEOUT")
            or "120"
        )

    async def evaluate(
        self,
        *,
        actor_id: str,
        scope: str,
        body: dict[str, Any],
        session_id: str | None = None,
        delegation_ticket: str | None = None,
        delegation_chain: Sequence[str] | None = None,
    ) -> CognitiveEvaluateResult:
        payload: dict[str, Any] = {"actor_id": actor_id, "scope": scope, "body": body}
        if session_id:
            payload["session_id"] = session_id
        if delegation_ticket:
            payload["delegation_ticket"] = delegation_ticket
        if delegation_chain:
            payload["delegation_chain"] = list(delegation_chain)
        data = await self._post_json("/v1/cognitive/evaluate", payload)
        return CognitiveEvaluateResult(
            session_id=str(data["session_id"]),
            trajectory_hash=str(data["trajectory_hash"]),
            crs=float(data.get("crs", 0.0)),
            decision=data.get("decision") or {},
            body=dict(data.get("body") or {}),
            commit_id=data.get("commit_id"),
        )

    async def commit(
        self, *, commit_id: str, response_body: dict[str, Any] | None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"commit_id": commit_id}
        if response_body is not None:
            payload["response_body"] = response_body
        return await self._post_json("/v1/cognitive/commit", payload)

    async def health(self) -> dict[str, Any]:
        url = f"{self.base_url}/health"
        async with self._client() as client:
            try:
                r = await client.get(url, timeout=min(self._timeout, 10.0))
            except httpx.HTTPError as e:
                raise RuntimeError(f"cognitiond health unreachable at {url}: {e}") from e
        if r.status_code >= 400:
            raise RuntimeError(f"cognitiond health HTTP {r.status_code}: {r.text[:400]}")
        try:
            return dict(r.json())
        except Exception:
            return {"ok": True, "raw": r.text[:200]}

    async def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        async with self._client() as client:
            r = await client.post(url, json=payload, timeout=self._timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"cognitiond {path} HTTP {r.status_code}: {r.text[:2000]}")
        return dict(r.json())

    def _client(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"verify": _verify_arg()}
        if self._cert is not None:
            kwargs["cert"] = self._cert
        return httpx.AsyncClient(**kwargs)
