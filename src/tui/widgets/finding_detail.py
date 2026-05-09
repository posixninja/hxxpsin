"""Reusable finding detail panel: evidence + optional response diff."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static, TextArea, TabbedContent, TabPane
from textual.containers import Vertical

_PRIORITY_KEYS = [
    "verdict", "confidence", "score", "severity",
    "category", "attack", "test_kind",
    "url", "endpoint", "method",
    "evidence", "payload", "injected", "probe", "signals",
    "bypass_source", "original_status", "new_status",
    "source", "sink",
]


def _finding_summary(f: dict) -> str:
    lines = []
    shown: set[str] = set()

    for key in _PRIORITY_KEYS:
        if key in f:
            val = f[key]
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(f"{key}: {val}")
            shown.add(key)

    extras = [
        (k, v) for k, v in f.items()
        if k not in shown and not k.startswith("_")
    ]
    if extras:
        lines.append("")
        lines.append("--- additional ---")
        for k, v in extras:
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            lines.append(f"{k}: {v}")

    return "\n".join(lines)


class FindingDetail(Vertical):
    """Shows evidence, request snippets, and optional A/B diff for a finding."""

    DEFAULT_CSS = """
    FindingDetail {
        height: 1fr;
    }
    FindingDetail TextArea {
        height: 1fr;
        border: none;
    }
    """

    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Evidence", id="tab-evidence"):
                yield TextArea("", id="evidence-text", read_only=True)
            with TabPane("Diff", id="tab-diff"):
                yield TextArea("", id="diff-text", read_only=True)
            with TabPane("Raw", id="tab-raw"):
                yield TextArea("", id="raw-text", read_only=True)

    def show_finding(self, f: dict) -> None:
        summary = _finding_summary(f)
        evidence = f.get("evidence", "")
        full_evidence = f"{summary}\n\nevidence:\n{evidence}" if evidence and evidence not in summary else summary
        self.query_one("#evidence-text", TextArea).load_text(full_evidence)

        resp_a = f.get("response_a", "")
        resp_b = f.get("response_b", "")
        if resp_a or resp_b:
            diff = f"--- Response A ---\n{resp_a}\n\n--- Response B ---\n{resp_b}"
        else:
            diff = "(no diff available)"
        self.query_one("#diff-text", TextArea).load_text(diff)

        self.query_one("#raw-text", TextArea).load_text(
            "\n".join(f"{k}: {v}" for k, v in f.items() if not k.startswith("_"))
        )
