"""payload/payload_callback_server — manage the OOB callback HTTP server.

Wraps ``payload_server.PayloadServer`` as a long-lived daemon controlled
by an ``action`` discriminator (start | status | stop | mint_token).
Servers are kept in a process-scoped registry keyed by ``server_id``.

This is the local listener only — to make it publicly reachable, also
start a ``payload_tunnel`` pointed at the returned ``local_url``."""

from __future__ import annotations

import uuid
from typing import Any

from . import REGISTRY


# server_id → PayloadServer
_SERVERS: dict[str, Any] = {}


async def _handler(
    *,
    action: str,
    server_id: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    payload_dir: str | None = None,
    token_kind: str = "probe",
) -> dict[str, Any]:
    from payload_server import PayloadServer  # type: ignore[import-not-found]

    act = (action or "").lower()
    if act == "start":
        srv = PayloadServer(host=host, port=port, payload_dir=payload_dir)
        await srv.start()
        sid = uuid.uuid4().hex[:12]
        _SERVERS[sid] = srv
        return {
            "server_id": sid,
            "local_url": srv.local_url,
            "host": srv.host,
            "port": srv._actual_port,
            "hits": 0,
        }

    if act in ("status", "stop", "mint_token"):
        if not server_id:
            return {"error": f"action={act!r} requires server_id"}
        srv = _SERVERS.get(server_id)
        if srv is None:
            return {"error": f"unknown server_id {server_id!r}"}

        if act == "status":
            return {
                "server_id": server_id,
                "local_url": srv.local_url,
                "hits_total": len(srv.hits),
                "hits": [h.to_dict() for h in srv.hits[-25:]],
            }
        if act == "mint_token":
            token = srv.mint_token(token_kind)
            return {"server_id": server_id, "token": token, "kind": token_kind}
        if act == "stop":
            await srv.stop()
            _SERVERS.pop(server_id, None)
            return {"server_id": server_id, "stopped": True}

    return {"error": f"unknown action {action!r}; expected start|status|stop|mint_token"}


REGISTRY.add(
    agent_id="payload",
    skill_id="payload_callback_server",
    description=(
        "Lifecycle for an OOB callback HTTP server (SSRF/XXE/upload/oauth probes "
        "phone home here). Actions: start, status, stop, mint_token."
    ),
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": ["start", "status", "stop", "mint_token"],
            },
            "server_id": {"type": "string", "description": "Required for status/stop/mint_token"},
            "host": {"type": "string", "description": "Bind host for start (default 127.0.0.1)"},
            "port": {"type": "integer", "description": "Bind port for start (0 = random free port)"},
            "payload_dir": {"type": "string", "description": "Directory of static payload files to serve"},
            "token_kind": {"type": "string", "description": "Label for mint_token (default 'probe')"},
        },
    },
    handler=_handler,
)
