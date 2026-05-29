"""
adaptive_planner.py — LLM-assisted probe stage prioritization with static fallback.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional


# Default stage set when LLM unavailable or returns invalid JSON
DEFAULT_STAGES = [
    "jwt", "param_miner", "verifier", "open_redirect", "desync",
    "crlf", "ct_probe", "ws_probe", "graphql_probe", "oauth_probe", "race_probe",
    "active_scan", "auto_fuzz", "access_replay",
]


@dataclass
class PlannerResult:
    enabled_stages: list[str] = field(default_factory=lambda: list(DEFAULT_STAGES))
    skip_stages: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    source: str = "static"

    def to_dict(self) -> dict:
        return {
            "enabled_stages": self.enabled_stages,
            "skip_stages": self.skip_stages,
            "notes": self.notes,
            "source": self.source,
        }

    def is_enabled(self, name: str) -> bool:
        if name in self.skip_stages:
            return False
        return name in self.enabled_stages


def static_plan(
    *,
    passive: bool = False,
    active_scan: bool = False,
    auto_fuzz: bool = False,
    has_graphql: bool = False,
    has_race: bool = False,
    has_oauth_urls: bool = False,
) -> PlannerResult:
    enabled = list(DEFAULT_STAGES)
    skip = []
    notes = ["static fallback plan"]

    if passive:
        skip = [s for s in enabled if s not in ("desync",)]
        enabled = [s for s in enabled if s not in skip]

    if not active_scan:
        skip.extend(["active_scan"])
        enabled = [s for s in enabled if s != "active_scan"]

    if not auto_fuzz:
        skip.append("auto_fuzz")
        enabled = [s for s in enabled if s != "auto_fuzz"]

    if not has_graphql:
        skip.append("graphql_probe")
    if not has_race:
        skip.append("race_probe")
    if not has_oauth_urls:
        skip.append("oauth_probe")

    return PlannerResult(enabled_stages=enabled, skip_stages=list(set(skip)), notes=notes, source="static")


async def plan_stages(
    *,
    target: str,
    stack_summary: str,
    category_counts: dict[str, int],
    llm_generate: Optional[callable] = None,
    passive: bool = False,
    active_scan: bool = False,
    auto_fuzz: bool = False,
) -> PlannerResult:
    has_graphql = category_counts.get("GraphQL", 0) > 0 or "graphql" in target.lower()
    has_race = category_counts.get("Race Condition", 0) > 0
    has_oauth = any(
        category_counts.get(k, 0) > 0
        for k in ("Auth/Session", "Open Redirect")
    )

    fallback = static_plan(
        passive=passive,
        active_scan=active_scan,
        auto_fuzz=auto_fuzz,
        has_graphql=has_graphql,
        has_race=has_race,
        has_oauth_urls=has_oauth,
    )

    if llm_generate is None:
        return fallback

    prompt = (
        "You are a web pentest planner. Given recon signals, return ONLY JSON:\n"
        '{"enabled_stages":["jwt","verifier",...],"skip_stages":[],"notes":["reason"]}\n'
        f"Target: {target}\nStack: {stack_summary}\nCategories: {json.dumps(category_counts)}\n"
        f"Flags: passive={passive} active_scan={active_scan} auto_fuzz={auto_fuzz}\n"
        f"Valid stage names: {', '.join(DEFAULT_STAGES)}\n"
    )
    try:
        raw = await llm_generate(prompt, system="Return compact JSON only.")
        text = raw if isinstance(raw, str) else getattr(raw, "text", str(raw))
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return fallback
        data = json.loads(m.group())
        enabled = [s for s in data.get("enabled_stages", []) if s in DEFAULT_STAGES]
        if not enabled:
            return fallback
        return PlannerResult(
            enabled_stages=enabled,
            skip_stages=[s for s in data.get("skip_stages", []) if isinstance(s, str)],
            notes=data.get("notes", []) or ["llm plan"],
            source="llm",
        )
    except Exception:
        return fallback
