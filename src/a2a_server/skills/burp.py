"""Skills under the ``burp`` agent — request crafting and fuzzing.

- ``repeater`` — replay one request N times with header/body replacements
- ``intruder_sniper`` — single-position substitution
- ``intruder_battering_ram`` — same payload across all positions
- ``intruder_pitchfork`` — parallel different payloads
- ``intruder_cluster_bomb`` — cross-product of payload lists

Each wraps the existing classes in [repeater.py](../../repeater.py) and
[intruder.py](../../intruder.py). Position markers in target strings
use ``§…§`` per the existing intruder convention.
"""

from __future__ import annotations

from typing import Any

from . import REGISTRY

REGISTRY.declare_agent(
    "burp",
    name="hxxpsin burp surface",
    description="Repeater + Intruder (sniper / battering ram / pitchfork / cluster bomb).",
)


# ---------------------------------------------------------------------------
# Repeater
# ---------------------------------------------------------------------------


async def _repeater(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    times: int = 1,
    replacements: list[list[str]] | None = None,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    from repeater import Repeater, ReplayRequest  # type: ignore[import-not-found]

    req = ReplayRequest(
        method=method.upper(), url=url, headers=dict(headers or {}), body=body
    )
    rep = Repeater(follow_redirects=follow_redirects)
    pairs = [(p[0], p[1]) for p in (replacements or []) if len(p) == 2] or None
    results = await rep.run(req, times=times, replacements=pairs, verbose=False)
    return {
        "request": {"method": req.method, "url": req.url, "headers": req.headers},
        "responses": [
            {
                "attempt": r.attempt,
                "status": r.status,
                "elapsed_ms": int(r.elapsed * 1000),
                "headers": r.headers,
                "body_preview": (r.body or "")[:2000],
                "error": r.error,
            }
            for r in results
        ],
    }


REGISTRY.add(
    agent_id="burp",
    skill_id="repeater",
    description=(
        "Replay one HTTP request N times with optional header/body "
        "replacements. Host-pinned — provide the exact URL you want hit."
    ),
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "times": {"type": "integer", "default": 1, "minimum": 1, "maximum": 50},
            "replacements": {
                "type": "array",
                "items": {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2},
                "description": "Optional list of [find, replace] pairs applied to URL+headers+body",
            },
            "follow_redirects": {"type": "boolean", "default": True},
        },
    },
    handler=_repeater,
)


# ---------------------------------------------------------------------------
# Intruder — one skill per attack mode
# ---------------------------------------------------------------------------


def _intruder_handler(mode: str):
    async def handler(
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        payloads: list[str] | None = None,
        payload_lists: list[list[str]] | None = None,
        grep: str | None = None,
        max_requests: int = 200,
    ) -> dict[str, Any]:
        from intruder import (  # type: ignore[import-not-found]
            Intruder,
            IntruderRequest,
        )

        req = IntruderRequest(
            method=method.upper(), url=url, headers=dict(headers or {}), body=body
        )
        # sniper / battering_ram use ONE payload list; pitchfork / cluster_bomb
        # use multiple lists (one per § position).
        if mode in ("sniper", "battering_ram"):
            lists = [list(payloads or [])]
        else:
            lists = [list(lst) for lst in (payload_lists or [])]

        del max_requests  # not supported by the underlying class
        intruder = Intruder()
        result = await intruder.run(
            req=req,
            payload_lists=lists,
            mode=mode,
            grep=grep,
            verbose=False,
        )
        if hasattr(result, "to_dict"):
            return result.to_dict()
        return {"raw": str(result)}

    return handler


_INTRUDER_MODES = {
    "intruder_sniper": (
        "sniper",
        "Single position substitution — payload set applied to each § position one at a time.",
    ),
    "intruder_battering_ram": (
        "battering_ram",
        "Same payload across ALL positions per request.",
    ),
    "intruder_pitchfork": (
        "pitchfork",
        "Parallel payload lists — payload_lists[i][k] fills position i on request k.",
    ),
    "intruder_cluster_bomb": (
        "cluster_bomb",
        "Cross-product of payload_lists — every combination across positions.",
    ),
}


for skill_id, (mode_name, description) in _INTRUDER_MODES.items():
    REGISTRY.add(
        agent_id="burp",
        skill_id=skill_id,
        description=description,
        input_schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Use §marker§ for positions"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"},
                "payloads": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "For sniper / battering_ram",
                },
                "payload_lists": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "string"}},
                    "description": "For pitchfork / cluster_bomb — one list per position",
                },
                "grep": {"type": "string"},
                "max_requests": {"type": "integer", "default": 200, "maximum": 5000},
            },
        },
        handler=_intruder_handler(mode_name),
    )
