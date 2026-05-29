"""Offline tests for MSF integration round 2 — one focused case per bundle.

PR 1 / Bundle B (this file):
  - sessions overlap (target_host vs URL hostname) populates
    sessions_on_target and emits an msf_pull event with session counts.
  - suggest_modules returns ≤ N keyword hints derived from finding categories.

Bundles A, C, D arrive in PR 2 and will be added to this file then.

Run:  python -m pytest tests/test_msf_bundles.py -v
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import msf_ingest  # noqa: E402
from msf_ingest import (  # noqa: E402
    MSFClient, MSFIngestResult, MSFSession,
    pull_sessions_into_result, suggest_modules,
)


# ---------------------------------------------------------------------------
# Fakes — mirror tests/test_msf_ingest.py:FakeClient style
# ---------------------------------------------------------------------------


class FakeSessionClient(MSFClient):
    """In-memory backend that returns a fixed session list."""
    backend = "fake"

    def __init__(self, workspace="default", sessions=None):
        self.workspace = workspace
        self._sessions = sessions or []

    async def connect(self) -> None: return None
    async def disconnect(self) -> None: return None

    async def fetch_sessions(self, workspace):
        return list(self._sessions)


@dataclass
class _Finding:
    """Duck-type for classifier.Finding — only .categories matters here."""
    url: str = ""
    score: int = 0
    categories: list = field(default_factory=list)
    method: str = "GET"


# ---------------------------------------------------------------------------
# Bundle B — sessions overlap + module suggestions
# ---------------------------------------------------------------------------


def test_bundle_b_sessions_overlap_with_target_host():
    """When MSF has live sessions and one of them targets the same host as
    the hxxpsin scan, sessions_on_target captures that subset and the
    msf_pull event carries both counts so the TUI / log can warn the operator
    that they may already own the box."""
    sessions = [
        MSFSession(id=1, session_type="meterpreter",
                   target_host="ctf.corp.local",
                   via_exploit="exploit/unix/webapp/foo",
                   opened_at="2026-05-23 10:00:00"),
        MSFSession(id=2, session_type="shell",
                   target_host="other.local",
                   via_exploit="exploit/multi/handler"),
    ]
    fake = FakeSessionClient(workspace="default", sessions=sessions)
    result = MSFIngestResult(backend="fake", workspace="default")

    events: list[tuple[str, dict]] = []
    def log_cb(ev, fields): events.append((ev, fields))

    asyncio.run(pull_sessions_into_result(
        fake, "https://ctf.corp.local/login", "default", result,
        log_cb=log_cb,
    ))

    assert result.pulled_sessions == 2
    assert len(result.sessions_on_target) == 1
    assert result.sessions_on_target[0]["id"] == 1
    assert result.sessions_on_target[0]["target_host"] == "ctf.corp.local"
    # Event fired with both counts
    assert any(ev == "msf_pull"
               and fields.get("sessions") == 2
               and fields.get("sessions_on_target") == 1
               for ev, fields in events)


def test_bundle_b_sessions_no_target_overlap():
    """With no session matching the target host, sessions_on_target stays
    empty — no spurious warning."""
    sessions = [
        MSFSession(id=5, session_type="meterpreter", target_host="elsewhere.local"),
    ]
    fake = FakeSessionClient(sessions=sessions)
    result = MSFIngestResult(backend="fake")

    asyncio.run(pull_sessions_into_result(
        fake, "https://ctf.corp.local/", "default", result,
    ))
    assert result.pulled_sessions == 1
    assert result.sessions_on_target == []


def test_bundle_b_pull_sessions_no_client_is_noop():
    """client=None must not raise and must not touch the result."""
    result = MSFIngestResult()
    out = asyncio.run(pull_sessions_into_result(
        None, "https://ctf.corp.local/", "default", result,
    ))
    assert out is result
    assert result.pulled_sessions == 0
    assert result.sessions_on_target == []


def test_bundle_b_suggest_modules_for_ssrf_finding():
    """An SSRF-tagged finding gets up to N module-name keyword hints, each
    drawn from the static _CAT_TO_MODULE_KEYWORDS map for that category."""
    finding = _Finding(url="https://t/api/fetch", score=70,
                       categories=["SSRF Surface"])
    hints = asyncio.run(suggest_modules(None, finding, limit=5))
    assert 0 < len(hints) <= 5
    assert all(kw in ("ssrf", "fetch") for kw in hints)


def test_bundle_b_suggest_modules_respects_limit_across_categories():
    """A multi-category finding combines keywords from each category and
    never exceeds the limit. Duplicates across categories must be deduped."""
    finding = _Finding(categories=["File Upload", "Injection",
                                   "Open Redirect", "GraphQL"])
    hints = asyncio.run(suggest_modules(None, finding, limit=3))
    assert len(hints) == 3
    assert len(set(hints)) == 3


def test_bundle_b_suggest_modules_unknown_category_returns_empty():
    """A category not in _CAT_TO_MODULE_KEYWORDS yields []."""
    finding = _Finding(categories=["NotARealCategory"])
    hints = asyncio.run(suggest_modules(None, finding))
    assert hints == []
