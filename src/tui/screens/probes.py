"""Probes tab — per-probe result drill-down with TabbedContent."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static, TabbedContent, TabPane, TextArea

from ..state import AppState
from ..widgets.finding_detail import FindingDetail

_PROBE_TABS = [
    ("jwt",       "JWT",      ["attack", "endpoint", "verdict", "confidence"]),
    ("idor",      "IDOR",     ["url", "test_kind", "verdict", "confidence"]),
    ("desync",    "Desync",   ["severity", "probe", "url", "signals"]),
    ("active",    "Active",   ["category", "url", "verdict", "evidence"]),
    ("nosql",     "NoSQL",    ["url", "payload", "verdict"]),
    ("crlf",      "CRLF",     ["url", "injected", "verdict"]),
    ("upload",    "Upload",   ["endpoint", "test_name", "verdict"]),
    ("dom_xss",   "DOM XSS",  ["url", "source", "sink", "verdict"]),
    ("access_replay", "Access Replay", ["url", "original_status", "new_status", "bypass_source"]),
    ("ws",        "WebSocket", ["url", "category", "severity"]),
    ("auto_fuzz", "AutoFuzz", ["url", "position", "payload", "anomaly"]),
]


class ProbeTab(Vertical):
    """One probe's result DataTable + detail panel."""

    DEFAULT_CSS = """
    ProbeTab {
        height: 1fr;
    }
    ProbeTab DataTable {
        height: 1fr;
    }
    ProbeTab #probe-detail {
        height: 12;
        border-top: solid $primary;
    }
    ProbeTab #probe-action-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
    }
    ProbeTab #probe-action-bar Button {
        min-width: 16;
        margin-right: 1;
    }
    """

    def __init__(self, probe_key: str, columns: list[str], state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._probe_key = probe_key
        self._columns = columns
        self._state = state
        self._findings: list[dict] = []

    def compose(self) -> ComposeResult:
        yield DataTable(id=f"probe-table-{self._probe_key}", cursor_type="row", zebra_stripes=True)
        yield FindingDetail(id="probe-detail")
        with Horizontal(id="probe-action-bar"):
            yield Button("Re-run (all)", id="btn-rerun-all", variant="warning")
            yield Button("Run on Selection", id="btn-rerun-sel", variant="default")

    def on_mount(self) -> None:
        table = self.query_one(f"#probe-table-{self._probe_key}", DataTable)
        table.add_columns(*self._columns)
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(f"#probe-table-{self._probe_key}", DataTable)
        table.clear()
        self._findings = self._state.probe_results.get(self._probe_key, [])
        for f in self._findings:
            row = []
            for col in self._columns:
                val = f.get(col, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:3])
                row.append(str(val)[:60])
            table.add_row(*row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._findings):
            self.query_one("#probe-detail", FindingDetail).show_finding(self._findings[idx])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-rerun-all":
            self.app.notify(
                f"Re-running {self._probe_key} probe on all requests... (manual probe API coming soon)"
            )
        elif event.button.id == "btn-rerun-sel":
            sel = self._state.selected_requests
            count = len(sel) if sel else "?"
            self.app.notify(
                f"Re-running {self._probe_key} on {count} selected requests... (coming soon)"
            )

    def refresh_data(self) -> None:
        self._refresh()


class ProbesScreen(Vertical):
    """Probes tab: TabbedContent over each probe type."""

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._probe_tabs: list[ProbeTab] = []

    def compose(self) -> ComposeResult:
        with TabbedContent():
            for probe_key, label, columns in _PROBE_TABS:
                with TabPane(label, id=f"probes-{probe_key}"):
                    tab = ProbeTab(probe_key, columns, self._state, id=f"probe-tab-{probe_key}")
                    self._probe_tabs.append(tab)
                    yield tab

    def refresh_data(self) -> None:
        for tab in self._probe_tabs:
            tab.refresh_data()
