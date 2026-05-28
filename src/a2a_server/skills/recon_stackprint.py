"""recon/recon_stackprint — homepage + JS bundle tech-stack fingerprint.

Wraps ``stackprint.Stackprint``. Mirrors the MCP ``stackprint`` tool
exposed at ``src/mcp_agent/tools.py:stackprint`` so A2A clients have
the same capability."""

from __future__ import annotations

from typing import Any

from . import REGISTRY


async def _handler(*, url: str, timeout: float = 8.0, max_js_bundles: int = 3) -> dict[str, Any]:
    from stackprint import Stackprint  # type: ignore[import-not-found]

    profiler = Stackprint(url, timeout=timeout, max_js_bundles=max_js_bundles)
    profile = await profiler.run()
    return profile.to_dict()


REGISTRY.add(
    agent_id="recon",
    skill_id="recon_stackprint",
    description=(
        "Fingerprint a target's web stack from its homepage + JS bundles. "
        "Returns framework, server, languages, GraphQL endpoints, and probed paths."
    ),
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "timeout": {"type": "number", "description": "Per-request timeout in seconds (default 8.0)"},
            "max_js_bundles": {"type": "integer", "description": "Max JS bundles to download for analysis (default 3)"},
        },
    },
    handler=_handler,
)
