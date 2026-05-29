"""
pipeline_state.py — Mutable state shared across scheduled pipeline stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from adaptive_planner import PlannerResult
from classifier import ClassifierResult
from collector import Collector
from http_cache import HttpCache
from scheduler import SchedulerResult
from stackprint import StackProfile
from verifier import VerifyReport


@dataclass
class PipelineState:
    args: Any
    profile: StackProfile
    col: Collector
    out: Path
    start: float
    total_steps: int
    step_offset: int
    har_result: Any = None
    pre_auth_session: Any = None
    scm_probe_result: Any = None

    # Infrastructure
    canary: Any = None
    browser_verifier: Any = None
    http_cache: Optional[HttpCache] = None
    auth_hdrs: dict = field(default_factory=dict)

    # Early pipeline
    grabber_result: Any = None
    pre_snapshot: Any = None
    js_result: Any = None
    dom_xss_result: Any = None
    result: Optional[ClassifierResult] = None
    auto_auth_session: Any = None

    # Probe results (filled by stages)
    jwt_result: Any = None
    param_result: Any = None
    verify_report: Optional[VerifyReport] = None
    redirect_result: Any = None
    active_result: Any = None
    nosql_result: Any = None
    sql_probe_result: Any = None
    auth_bypass_result: Any = None
    idor_result: Any = None
    account_a: Any = None
    account_b: Any = None
    desync_result: Any = None
    auto_fuzz_result: Any = None
    crlf_result: Any = None
    ct_probe_result: Any = None
    ws_probe_result: Any = None
    graphql_result: Any = None
    oauth_result: Any = None
    race_result: Any = None
    access_replay_result: Any = None
    challenge_diff: Any = None
    enrichment_result: Any = None
    data_extract_result: Any = None
    upload_probe_result: Any = None
    sql_dump_result: Any = None
    ldap_dump_result: Any = None
    llm_verification_result: Any = None
    solver_result: Any = None

    planner: Optional[PlannerResult] = None
    scheduler_result: Optional[SchedulerResult] = None
    stage_errors: list[str] = field(default_factory=list)
    stage_artifacts: dict[str, dict] = field(default_factory=dict)

    def passive(self) -> bool:
        return getattr(self.args, "passive", False)

    def ctx(self):
        return getattr(self.args, "_ctx", None)
