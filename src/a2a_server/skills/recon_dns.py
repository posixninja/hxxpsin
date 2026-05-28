"""recon/recon_dns — comprehensive DNS recon for an apex domain.

Wraps ``dns_recon.full_dns_recon`` — basic record types, SOA, NS, SPF,
DMARC, DKIM, AXFR (if permitted), ANY against authoritative, plus
wildcard detection and hostname harvest."""

from __future__ import annotations

from typing import Any

from . import REGISTRY


async def _handler(
    *,
    domain: str,
    do_axfr: bool = False,
    do_dkim: bool = True,
    do_any: bool = True,
    do_brute: bool = False,
    dkim_selectors: list[str] | None = None,
    brute_wordlist_path: str | None = None,
    brute_concurrency: int = 50,
) -> dict[str, Any]:
    from dns_recon import full_dns_recon  # type: ignore[import-not-found]

    rec = await full_dns_recon(
        domain,
        do_axfr=do_axfr,
        do_dkim=do_dkim,
        do_any=do_any,
        do_brute=do_brute,
        dkim_selectors=dkim_selectors,
        brute_wordlist_path=brute_wordlist_path,
        brute_concurrency=brute_concurrency,
    )
    return rec.to_dict()


REGISTRY.add(
    agent_id="recon",
    skill_id="recon_dns",
    description=(
        "Full DNS recon: A/AAAA/MX/NS/SOA/TXT, SPF/DMARC/DKIM parsing, "
        "AXFR attempts against each NS, wildcard detection, hostname harvest, "
        "and optional subdomain brute force against a bundled ~5k wordlist."
    ),
    input_schema={
        "type": "object",
        "required": ["domain"],
        "properties": {
            "domain": {"type": "string", "description": "Apex domain, e.g. example.com"},
            "do_axfr": {"type": "boolean", "description": "Attempt AXFR zone transfer against each NS (default false — active/intrusive probe)"},
            "do_dkim": {"type": "boolean", "description": "Probe DKIM selectors (default true)"},
            "do_any": {"type": "boolean", "description": "ANY query against authoritative NS (default true)"},
            "do_brute": {"type": "boolean", "description": "Run subdomain brute force against bundled wordlist (default false — noisy)"},
            "dkim_selectors": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific DKIM selectors to probe",
            },
            "brute_wordlist_path": {
                "type": "string",
                "description": "Override bundled subdomain wordlist with a file path",
            },
            "brute_concurrency": {
                "type": "integer",
                "description": "Parallel resolver queries during brute (default 50)",
            },
        },
    },
    handler=_handler,
)
