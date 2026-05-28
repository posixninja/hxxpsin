"""payload/payload_encode_variants — produce re-encoded payload variants.

Mirrors the MCP ``encode_variants`` tool. Given a payload string and a
list of encoding schemes, returns one variant per scheme so a probe can
try each against a sink that does its own decoding."""

from __future__ import annotations

from typing import Any

from . import REGISTRY


async def _handler(
    *,
    value: str,
    schemes: list[str] | None = None,
    chain: bool = False,
) -> dict[str, Any]:
    from codec import list_schemes, variants  # type: ignore[import-not-found]

    chosen = schemes or list_schemes()
    return {
        "schemes_applied": chosen,
        "chained": chain,
        "variants": variants(value, chosen, chain=chain),
    }


REGISTRY.add(
    agent_id="payload",
    skill_id="payload_encode_variants",
    description=(
        "Re-encode a payload through every requested scheme (URL, base64, "
        "HTML entities, hex, unicode, JWT segment, …). When chain=true, "
        "applies schemes in sequence to produce nested encodings."
    ),
    input_schema={
        "type": "object",
        "required": ["value"],
        "properties": {
            "value": {"type": "string", "description": "Payload to re-encode"},
            "schemes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Subset of encoding scheme names (default = all)",
            },
            "chain": {"type": "boolean", "description": "Apply schemes sequentially instead of independently"},
        },
    },
    handler=_handler,
)
