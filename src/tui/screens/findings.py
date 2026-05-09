"""Findings tab — global findings from all probes with filter and detail."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from ..state import AppState
from ..widgets.context_panel import ContextPanel
from ..widgets.finding_detail import FindingDetail
from .requests import SendToRepeater


def _finding_key(f: dict) -> str:
    url = f.get("url", f.get("endpoint", ""))
    cat = f.get("category", f.get("attack", ""))
    probe = f.get("_probe", "")
    return hashlib.md5(f"{url}:{cat}:{probe}".encode()).hexdigest()


def _load_confirmed_keys(state: AppState) -> set[str]:
    if not state.out_dir:
        return set()
    p = Path(state.out_dir) / "confirmed.json"
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text()).keys())
    except Exception:
        return set()


def _persist_confirmed(state: AppState, finding: dict) -> None:
    if not state.out_dir:
        return
    p = Path(state.out_dir) / "confirmed.json"
    try:
        confirmed = json.loads(p.read_text()) if p.exists() else {}
        confirmed[_finding_key(finding)] = {
            "url": finding.get("url", finding.get("endpoint", "")),
            "category": finding.get("category", finding.get("attack", "")),
            "probe": finding.get("_probe", ""),
        }
        p.write_text(json.dumps(confirmed, indent=2))
    except Exception:
        pass


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
    FindingsScreen ContextPanel {
        height: 14;
        border-top: solid $primary;
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
                yield Button("Verify (LLM)", id="act-verify", variant="warning")
                yield Button("Mark Confirmed", id="act-confirm", variant="success")

        with Vertical(id="findings-right"):
            yield FindingDetail(id="finding-detail")
            yield Static("Context", classes="panel-title")
            yield ContextPanel(self._state, id="finding-context")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        # Width-capped columns: long category strings (e.g. "JS Auth Pattern")
        # were stretching the column and squeezing URL/Probe out of view.
        table.add_column("Score",    width=6)
        table.add_column("Category", width=16)
        table.add_column("Verdict",  width=12)
        table.add_column("Method",   width=7)
        table.add_column("URL")           # absorbs remaining space
        table.add_column("Probe",    width=10)
        self._refresh_table()

    def _refresh_table(self, text_filter: str = "", min_score: float = 0.0) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        findings = list(self._state.findings)

        # Patch confirmed verdicts from disk
        confirmed_keys = _load_confirmed_keys(self._state)
        if confirmed_keys:
            for f in findings:
                if _finding_key(f) in confirmed_keys:
                    f["verdict"] = "confirmed"

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
        if not findings:
            self.query_one("#findings-table", DataTable).add_row(
                "—", "No findings — run a scan or load an output directory", "", "", "", ""
            )
            return
        for f in findings:
            score = f.get("score", f.get("confidence", ""))
            score_str = f"{float(score):.2f}" if score else ""
            url = f.get("url", f.get("endpoint", "")) or ""
            display_url = ("…" + url[-87:]) if len(url) > 90 else url
            cat = f.get("category", f.get("attack", "")) or ""
            if len(cat) > 15:
                cat = cat[:14] + "…"
            table.add_row(
                score_str,
                cat,
                f.get("verdict", ""),
                f.get("method", ""),
                display_url,
                f.get("_probe", ""),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._filtered):
            f = self._filtered[idx]
            self.query_one("#finding-detail", FindingDetail).show_finding(f)
            self.query_one("#finding-context", ContextPanel).update_finding(f)

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
            self.post_message(SendToRepeater(req, source="Findings"))
            self.app.notify("Sent to Repeater")

        elif btn == "act-verify":
            self.app.notify("LLM verification: run pipeline with --llm-verify flag")

        elif btn == "act-confirm" and finding:
            finding["verdict"] = "confirmed"
            _persist_confirmed(self._state, finding)
            self.app.notify("Marked as confirmed (saved to confirmed.json)")
            self._refresh_table()

    def action_send_to_repeater(self) -> None:
        self.query_one("#act-repeater", Button).press()

    def action_verify_finding(self) -> None:
        self.query_one("#act-verify", Button).press()

    def action_mark_confirmed(self) -> None:
        self.query_one("#act-confirm", Button).press()

    def refresh_data(self) -> None:
        self._refresh_table()
