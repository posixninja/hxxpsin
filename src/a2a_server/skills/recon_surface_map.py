"""recon/recon_surface_map — Stage-0 attack-surface expansion.

Wraps ``surface_mapper.map_surface``: RDAP + full DNS + passive subdomain
enumeration (crt.sh + Wayback) + optional port scan + optional vhost
probing. Returns a Scope dictionary plus a one-line operator summary."""

from __future__ import annotations

from typing import Any

from . import REGISTRY


async def _handler(
    *,
    seed: str,
    auto_scope: bool = True,
    port_scan: str = "none",
    analyze_block: bool = False,
    analyze_block_max: int = 20,
    max_subdomains: int = 200,
    max_vhosts_per_ip: int = 50,
    scope_suffix: str | None = None,
) -> dict[str, Any]:
    from surface_mapper import SurfaceMapperConfig, map_surface, _summary  # type: ignore[import-not-found]

    cfg = SurfaceMapperConfig(
        auto_scope=auto_scope,
        port_scan=port_scan,
        analyze_block=analyze_block,
        analyze_block_max=analyze_block_max,
        max_subdomains=max_subdomains,
        max_vhosts_per_ip=max_vhosts_per_ip,
        scope_suffix=scope_suffix,
    )
    scope = await map_surface(seed, cfg)
    out = scope.to_dict()
    out["summary"] = _summary(scope)
    return out


REGISTRY.add(
    agent_id="recon",
    skill_id="recon_surface_map",
    description=(
        "Expand the attack surface from a seed (host / IP / CIDR): RDAP, "
        "deep DNS, crt.sh + Wayback subdomains, optional port scan and "
        "vhost rotation. Returns a Scope with hosts/whois/asn/vhost hits."
    ),
    input_schema={
        "type": "object",
        "required": ["seed"],
        "properties": {
            "seed": {"type": "string", "description": "Hostname, IP, or CIDR"},
            "auto_scope": {"type": "boolean", "description": "Enable RDAP + passive subdomain enum (default true)"},
            "port_scan": {
                "type": "string",
                "enum": ["none", "web", "full"],
                "description": "Port-scan depth (default 'none')",
            },
            "analyze_block": {"type": "boolean", "description": "Walk discovered CIDR blocks (default false)"},
            "analyze_block_max": {"type": "integer", "description": "Refuse prefixes wider than /<this> (default 20)"},
            "max_subdomains": {"type": "integer", "description": "Cap on enumerated subdomains (default 200)"},
            "max_vhosts_per_ip": {"type": "integer", "description": "Cap on vhost attempts per IP (default 50)"},
            "scope_suffix": {"type": "string", "description": "Override eTLD+1 (operator-supplied)"},
        },
    },
    handler=_handler,
)
