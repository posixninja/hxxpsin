"""Findings tab — global findings from all probes with filter and detail."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from ..state import AppState
from ..widgets.finding_detail import FindingDetail
from .requests import SendToRepeater


class FindingsScreen(Horizontal):
    """All findings, filterable by category/verdict/probe, with detail panel."""

    BINDINGS = [
        Binding("r", "send_to_repeater", "→ Repeater"),
        Binding("v", "verify_finding", "Verify"),
        Binding("c", "mark_confirmed", "Mark Confirmed"),
    ]

    DEFAULT_CSS = """
    FindingsScreen {
        height: 1fr;
    }
    FindingsScreen #findings-left {
        width: 55%;
        border-right: solid $primary;
    }
    FindingsScreen #findings-right {
        width: 45%;
    }
    FindingsScreen #filter-bar {
        height: 3;
        background: $surface;
        padding: 0 1;
    }
    FindingsScreen DataTable {
        height: 1fr;
    }
    FindingsScreen #action-bar {
        height: 3;
        background: $surface-darken-1;
        padding: 0 1;
    }
    FindingsScreen #action-bar Button {
        min-width: 12;
        margin-right: 1;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._filtered: list[dict] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="findings-left"):
            with Horizontal(id="filter-bar"):
                yield Label("Filter: ")
                yield Input(placeholder="category / url / verdict", id="find-filter")
                yield Label(" Min score: ")
                yield Input(placeholder="0.0", id="score-filter", restrict=r"[0-9.]*")
            yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="action-bar"):
                yield Button("→ Repeater", id="act-repeater", variant="primary")
                yield Button("→ Intruder", id="act-intruder", variant="primary")
                yield Button("Verify (LLM)", id="act-verify", variant="warning")
                yield Button("Mark Confirmed", id="act-confirm", variant="success")

        with Vertical(id="findings-right"):
            yield FindingDetail(id="finding-detail")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Score", "Category", "Verdict", "Method", "URL", "Probe")
        self._refresh_table()

    def _refresh_table(self, text_filter: str = "", min_score: float = 0.0) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        findings = self._state.findings
        if text_filter:
            ft = text_filter.lower()
            findings = [
                f for f in findings
                if ft in f.get("category", "").lower()
                or ft in f.get("url", "").lower()
                or ft in f.get("endpoint", "").lower()
                or ft in f.get("verdict", "").lower()
            ]
        if min_score > 0:
            findings = [
                f for f in findings
                if float(f.get("score", f.get("confidence", 0)) or 0) >= min_score
            ]
        self._filtered = findings
        for f in findings:
            score = f.get("score", f.get("confidence", ""))
            score_str = f"{float(score):.2f}" if score else ""
            table.add_row(
                score_str,
                f.get("category", f.get("attack", "")),
                f.get("verdict", ""),
                f.get("method", ""),
                (f.get("url", f.get("endpoint", "")) or "")[:60],
                f.get("_probe", ""),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._filtered):
            f = self._filtered[idx]
            self.query_one("#finding-detail", FindingDetail).show_finding(f)

    def on_input_changed(self, event: Input.Changed) -> None:
        text = self.query_one("#find-filter", Input).value
        score_raw = self.query_one("#score-filter", Input).value
        try:
            min_score = float(score_raw) if score_raw else 0.0
        except ValueError:
            min_score = 0.0
        self._refresh_table(text, min_score)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        table = self.query_one("#findings-table", DataTable)
        idx = table.cursor_row
        finding = self._filtered[idx] if 0 <= idx < len(self._filtered) else None

        if btn == "act-repeater" and finding:
            url = finding.get("url", finding.get("endpoint", ""))
            method = finding.get("method", "GET")
            req = {"method": method, "url": url, "headers": {}, "body": ""}
            self.post_message(SendToRepeater(req))
            self.app.notify("Sent to Repeater")

        elif btn == "act-intruder" and finding:
            url = finding.get("url", finding.get("endpoint", ""))
            req = {"method": "GET", "url": url, "headers": {}, "body": ""}
            self.app._send_to_intruder(req)
            self.app.notify("Sent to Intruder")

        elif btn == "act-verify":
            self.app.notify("LLM verification: run pipeline with --llm-verify flag")

        elif btn == "act-confirm" and finding:
            finding["verdict"] = "confirmed"
            self.app.notify("Marked as confirmed")
            self._refresh_table()

    def action_send_to_repeater(self) -> None:
        self.query_one("#act-repeater", Button).press()

    def action_verify_finding(self) -> None:
        self.query_one("#act-verify", Button).press()

    def action_mark_confirmed(self) -> None:
        self.query_one("#act-confirm", Button).press()

    def refresh_data(self) -> None:
        self._refresh_table()
