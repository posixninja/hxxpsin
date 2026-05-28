"""payload/payload_tunnel — manage a public tunnel to the callback server.

Wraps ``tunnel.{CloudflaredTunnel, NgrokTunnel, StaticTunnel}`` as a
long-lived daemon controlled by an ``action`` discriminator. Tunnels are
kept in a process-scoped registry keyed by ``tunnel_id``.

Backend selection:
  cloudflared (default)  zero-config TryCloudflare subdomain
  ngrok                  needs auth_token
  static                 operator-supplied stable public URL"""

from __future__ import annotations

import uuid
from typing import Any

from . import REGISTRY


# tunnel_id → Tunnel
_TUNNELS: dict[str, Any] = {}


async def _handler(
    *,
    action: str,
    tunnel_id: str | None = None,
    local_url: str | None = None,
    backend: str = "cloudflared",
    binary: str | None = None,
    auth_token: str | None = None,
    region: str | None = None,
    public_url: str | None = None,
) -> dict[str, Any]:
    from tunnel import (  # type: ignore[import-not-found]
        CloudflaredTunnel,
        NgrokTunnel,
        StaticTunnel,
        TunnelError,
    )

    act = (action or "").lower()
    if act == "start":
        if not local_url:
            return {"error": "action=start requires local_url"}
        be = (backend or "cloudflared").lower()
        try:
            if be == "cloudflared":
                t = CloudflaredTunnel(local_url=local_url, binary=binary or "cloudflared")
            elif be == "ngrok":
                t = NgrokTunnel(
                    local_url=local_url,
                    binary=binary or "ngrok",
                    auth_token=auth_token,
                    region=region,
                )
            elif be == "static":
                if not public_url:
                    return {"error": "backend=static requires public_url"}
                t = StaticTunnel(local_url=local_url, public_url=public_url)
            else:
                return {"error": f"unknown backend {backend!r}"}

            try:
                await t.start()
            except TunnelError as exc:
                return {"error": f"tunnel start failed: {exc}", "backend": be}
        except TunnelError as exc:
            return {"error": f"tunnel build failed: {exc}", "backend": be}

        tid = uuid.uuid4().hex[:12]
        _TUNNELS[tid] = t
        s = t.status()
        return {
            "tunnel_id": tid,
            "backend": s.backend,
            "public_url": s.public_url,
            "local_url": s.local_url,
        }

    if act in ("status", "stop"):
        if not tunnel_id:
            return {"error": f"action={act!r} requires tunnel_id"}
        t = _TUNNELS.get(tunnel_id)
        if t is None:
            return {"error": f"unknown tunnel_id {tunnel_id!r}"}
        if act == "status":
            s = t.status()
            return {
                "tunnel_id": tunnel_id,
                "backend": s.backend,
                "public_url": s.public_url,
                "local_url": s.local_url,
                "started_at": s.started_at,
                "pid": s.pid,
                "note": s.note,
            }
        if act == "stop":
            await t.stop()
            _TUNNELS.pop(tunnel_id, None)
            return {"tunnel_id": tunnel_id, "stopped": True}

    return {"error": f"unknown action {action!r}; expected start|status|stop"}


REGISTRY.add(
    agent_id="payload",
    skill_id="payload_tunnel",
    description=(
        "Lifecycle for a public tunnel (cloudflared / ngrok / static) that "
        "exposes a local callback server to the internet. Actions: start, status, stop."
    ),
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {"type": "string", "enum": ["start", "status", "stop"]},
            "tunnel_id": {"type": "string", "description": "Required for status/stop"},
            "local_url": {"type": "string", "description": "URL of the local payload_server (required for start)"},
            "backend": {
                "type": "string",
                "enum": ["cloudflared", "ngrok", "static"],
                "description": "Tunnel backend (default cloudflared)",
            },
            "binary": {"type": "string", "description": "Override the binary path"},
            "auth_token": {"type": "string", "description": "ngrok auth token"},
            "region": {"type": "string", "description": "ngrok region"},
            "public_url": {"type": "string", "description": "Required when backend=static"},
        },
    },
    handler=_handler,
)
