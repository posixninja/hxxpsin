"""intel/intel_msf — Metasploit workspace integration.

Wraps ``msf_ingest`` to surface MSF data over A2A. Loads the MSFProfile
from hxxpsin's auth_config (optionally overridden by config_path) and
opens an MSFClient on demand.

Actions:
  augment   pull hosts/services/vulns/creds into a Scope-shaped dict
  sessions  list active MSF sessions on a target
  ping      build a client and report which backend connected"""

from __future__ import annotations

from typing import Any

from . import REGISTRY


async def _handler(
    *,
    target: str,
    action: str = "augment",
    workspace: str | None = None,
    config_path: str | None = None,
) -> dict[str, Any]:
    from auth_config import load as load_config  # type: ignore[import-not-found]
    from msf_ingest import (  # type: ignore[import-not-found]
        MSFIngestError,
        MSFIngestResult,
        augment_scope_from_msf,
        make_msf_client,
        pull_sessions_into_result,
    )
    from surface_mapper import Scope  # type: ignore[import-not-found]

    cfg = load_config(extra_path=config_path)
    profile = cfg.msf
    if workspace:
        # Shallow override — don't mutate the loaded profile in place.
        profile = type(profile)(**{**profile.__dict__, "workspace": workspace})

    if not profile.enabled:
        return {"error": "msf integration disabled in config (set [msf].enabled = true)"}

    try:
        client = await make_msf_client(profile)
    except MSFIngestError as exc:
        return {"error": f"msf client connect failed: {exc}"}

    if client is None:
        return {"error": "msf client not built (profile disabled or no usable backend)"}

    try:
        act = (action or "augment").lower()
        if act == "ping":
            return {
                "backend": client.backend,
                "workspace": getattr(client, "workspace", profile.workspace),
                "connected": True,
            }
        if act == "augment":
            scope = Scope(seed=target, started_at=0.0)
            result = await augment_scope_from_msf(scope, client, workspace=profile.workspace)
            return {
                "msf": result.to_dict(),
                "scope": scope.to_dict(),
            }
        if act == "sessions":
            ingest = MSFIngestResult(backend=client.backend, workspace=profile.workspace)
            await pull_sessions_into_result(
                client, target=target, workspace=profile.workspace, result=ingest,
            )
            return {
                "target": target,
                "pulled_sessions": ingest.pulled_sessions,
                "sessions_on_target": ingest.sessions_on_target,
                "notes": ingest.notes,
            }
        return {"error": f"unknown action {action!r}; expected augment|sessions|ping"}
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


REGISTRY.add(
    agent_id="intel",
    skill_id="intel_msf",
    description=(
        "Pull Metasploit workspace data for a target. action=augment merges "
        "MSF hosts/services/vulns into a Scope-shaped dict; action=sessions "
        "lists active sessions on the target; action=ping verifies the backend."
    ),
    input_schema={
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {"type": "string", "description": "Target host or URL"},
            "action": {
                "type": "string",
                "enum": ["augment", "sessions", "ping"],
                "description": "Which MSF operation to run (default 'augment')",
            },
            "workspace": {"type": "string", "description": "Override the MSFProfile workspace"},
            "config_path": {"type": "string", "description": "Override the default config search chain"},
        },
    },
    handler=_handler,
)
