"""Skill registry. Each submodule registers its skills on import.

The registry is a single global so the agent-card builder and the
JSON-RPC dispatcher share one source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

SkillHandler = Callable[..., Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class Skill:
    agent_id: str
    skill_id: str
    description: str
    input_schema: dict[str, Any]
    handler: SkillHandler


class _Registry:
    def __init__(self) -> None:
        self._agents: dict[str, dict[str, Any]] = {}
        self._skills: list[Skill] = []
        self._by_key: dict[tuple[str, str], Skill] = {}

    def declare_agent(self, agent_id: str, *, name: str, description: str) -> None:
        """Register an agent. Idempotent: re-declaring an existing agent_id
        with the same name+description is a no-op; conflicting metadata
        raises so unrelated typos surface early."""
        existing = self._agents.get(agent_id)
        if existing is not None:
            if existing.get("name") != name or existing.get("description") != description:
                raise ValueError(
                    f"agent {agent_id!r} already declared with different metadata"
                )
            return
        self._agents[agent_id] = {"name": name, "description": description}

    def add(
        self,
        *,
        agent_id: str,
        skill_id: str,
        description: str,
        input_schema: dict[str, Any],
        handler: SkillHandler,
    ) -> None:
        if agent_id not in self._agents:
            raise ValueError(f"unknown agent_id {agent_id!r}; declare_agent first")
        key = (agent_id, skill_id)
        if key in self._by_key:
            raise ValueError(f"duplicate skill {key}")
        skill = Skill(
            agent_id=agent_id,
            skill_id=skill_id,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )
        self._skills.append(skill)
        self._by_key[key] = skill

    def agents(self) -> Iterable[tuple[str, dict[str, Any]]]:
        return self._agents.items()

    def skills_for(self, agent_id: str) -> list[Skill]:
        return [s for s in self._skills if s.agent_id == agent_id]

    def resolve(self, agent_id: str, skill_id: str) -> Skill:
        try:
            return self._by_key[(agent_id, skill_id)]
        except KeyError as e:
            raise KeyError(f"unknown skill {agent_id}/{skill_id}") from e


REGISTRY = _Registry()


# ---------------------------------------------------------------------------
# Agent declarations — done here so individual skill files can be imported
# in any order without worrying about who-declares-first.
# ---------------------------------------------------------------------------

REGISTRY.declare_agent(
    "recon",
    name="hxxpsin recon",
    description="Pre-attack reconnaissance: tech-stack fingerprinting, DNS, surface mapping.",
)
REGISTRY.declare_agent(
    "payload",
    name="hxxpsin payload infrastructure",
    description="Payload generation and OOB callback infrastructure (encoder, callback server, tunnel).",
)
REGISTRY.declare_agent(
    "verify",
    name="hxxpsin verification",
    description="Post-discovery confirmation via real-browser execution and vuln-app scoreboards.",
)
REGISTRY.declare_agent(
    "intel",
    name="hxxpsin external intel",
    description="External tooling integration (Metasploit workspace).",
)


# Eager import order matters — each submodule registers on import.
# scan/probe/burp declare their own agents inside the module.
from . import scan as _scan  # noqa: F401, E402
from . import probe as _probe  # noqa: F401, E402
from . import burp as _burp  # noqa: F401, E402

# New skill modules — agents are pre-declared above.
from . import recon_stackprint as _recon_stackprint  # noqa: F401, E402
from . import recon_dns as _recon_dns  # noqa: F401, E402
from . import recon_surface_map as _recon_surface_map  # noqa: F401, E402
from . import payload_encode_variants as _payload_encode_variants  # noqa: F401, E402
from . import payload_callback_server as _payload_callback_server  # noqa: F401, E402
from . import payload_tunnel as _payload_tunnel  # noqa: F401, E402
from . import verify_browser as _verify_browser  # noqa: F401, E402
from . import verify_challenge_tracker as _verify_challenge_tracker  # noqa: F401, E402
from . import intel_msf as _intel_msf  # noqa: F401, E402
