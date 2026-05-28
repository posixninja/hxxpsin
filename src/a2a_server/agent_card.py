"""Build the JSON returned at ``GET /.well-known/agent.json``.

Shape matches what servus's ``A2AClient.list_skills`` reads
(``servus/secretarius/a2a_client.py:115-140``): one or more ``agents``,
each with an ``id`` and a list of ``skills`` (``id``, ``description``,
``inputSchema``).

hxxpsin advertises seven agents:

- ``scan`` — orchestrators that drive the full pipeline / quick fingerprint /
  triage / per-finding solver
- ``probe`` — one skill per probe family (open_redirect, idor, jwt, …)
- ``burp`` — request crafting: repeater, four intruder modes
- ``recon`` — pre-attack discovery: stackprint, DNS recon, surface mapping
- ``payload`` — payload encoding + OOB callback infra (server + tunnel)
- ``verify`` — post-discovery confirmation: browser execution, vuln-app scoreboards
- ``intel`` — external tool integration (Metasploit workspace)

Each skill module under [skills/](skills/) declares its own metadata; the
agent card pulls from that registry so adding a skill is one-edit.
"""

from __future__ import annotations

from typing import Any

from .skills import REGISTRY


def build_agent_card(*, public_url: str) -> dict[str, Any]:
    agents: list[dict[str, Any]] = []
    for agent_id, agent_meta in REGISTRY.agents():
        agents.append(
            {
                "id": agent_id,
                "name": agent_meta["name"],
                "description": agent_meta["description"],
                "skills": [
                    {
                        "id": skill.skill_id,
                        "description": skill.description,
                        "inputSchema": skill.input_schema,
                    }
                    for skill in REGISTRY.skills_for(agent_id)
                ],
            }
        )
    return {
        "name": "hxxpsin",
        "version": "0.1.0",
        "url": public_url.rstrip("/"),
        "description": (
            "Web-application pentest agent. Recon, classification, "
            "per-probe-family scanners, and a three-stage agentic solver. "
            "All LLM calls flow through servus; inbound calls are gated "
            "by SecurisNexus cognitiond."
        ),
        "agents": agents,
    }
