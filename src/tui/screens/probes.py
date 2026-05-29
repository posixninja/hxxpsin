"""Probes tab — per-probe result drill-down with TabbedContent."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Static, TabbedContent, TabPane

from ..state import AppState
from ..widgets.finding_detail import FindingDetail

_PROBE_TABS = [
    ("fingerprint",  "Fingerprint",  ["category", "tech", "url", "verdict"]),
    ("js",           "JS",           ["type", "category", "url", "verdict"]),
    ("jwt",          "JWT",          ["attack", "endpoint", "verdict", "confidence"]),
    ("idor",         "IDOR",         ["url", "test_kind", "verdict", "confidence"]),
    ("desync",       "Desync",       ["severity", "probe", "url", "signals"]),
    ("active",       "Active",       ["category", "url", "verdict", "evidence"]),
    ("nosql",        "NoSQL",        ["url", "payload", "verdict"]),
    ("crlf",         "CRLF",         ["url", "injected", "verdict"]),
    ("upload",       "Upload",       ["endpoint", "test_name", "verdict"]),
    ("dom_xss",      "DOM XSS",      ["url", "source", "sink", "verdict"]),
    ("access_replay","Access Replay",["url", "original_status", "new_status", "bypass_source"]),
    ("dns_recon",    "DNS Recon",    ["url", "category", "verdict"]),
    ("ws",           "WebSocket",    ["url", "category", "severity"]),
    ("auto_fuzz",    "AutoFuzz",     ["url", "position", "payload", "anomaly"]),
    ("graphql",      "GraphQL",      ["test", "url", "severity", "evidence"]),
    ("race",         "Race",         ["method", "url", "evidence", "responses_differ"]),
    ("oauth",        "OAuth",        ["test", "url", "severity", "evidence"]),
]

_STATUS_ICONS = {
    "done":    "✓",
    "running": "…",
    "failed":  "✗",
}


class ProbeTab(Vertical):
    """One probe's result DataTable + detail panel + status line."""

    DEFAULT_CSS = """
    ProbeTab {
        height: 1fr;
    }
    ProbeTab .probe-status {
        height: 1;
        padding: 0 1;
        color: $text-muted;
        background: $surface-darken-1;
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
        yield Static("○  Not run", id=f"probe-status-{self._probe_key}", classes="probe-status")
        yield DataTable(id=f"probe-table-{self._probe_key}", cursor_type="row", zebra_stripes=True)
        yield FindingDetail(id="probe-detail")
        with Horizontal(id="probe-action-bar"):
            yield Button("Re-run on Selection", id="btn-rerun-sel", variant="default")

    def on_mount(self) -> None:
        table = self.query_one(f"#probe-table-{self._probe_key}", DataTable)
        table.add_columns(*self._columns)
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one(f"#probe-table-{self._probe_key}", DataTable)
        table.clear()
        self._findings = self._state.probe_results.get(self._probe_key, [])

        status = self._state.probe_status.get(self._probe_key, "")
        icon = _STATUS_ICONS.get(status, "○")
        if status == "done" and self._findings:
            status_msg = f"{icon}  {len(self._findings)} finding(s)"
        elif status == "done":
            status_msg = f"{icon}  Done — no findings"
        elif status == "running":
            status_msg = f"{icon}  Running…"
        elif status == "failed":
            status_msg = f"{icon}  Failed — check alerts bar"
        else:
            status_msg = "○  Not run"
        try:
            self.query_one(f"#probe-status-{self._probe_key}", Static).update(status_msg)
        except Exception:
            pass

        if not self._findings:
            placeholder = ["—"] + ["" for _ in range(len(self._columns) - 1)]
            if len(self._columns) > 1:
                placeholder[1] = "Probe not run — run a scan or use Re-run on Selection"
            table.add_row(*placeholder)
            return

        for f in self._findings:
            row = []
            for col in self._columns:
                val = f.get(col, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:3])
                row.append(str(val)[:90])
            table.add_row(*row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._findings):
            self.query_one("#probe-detail", FindingDetail).show_finding(self._findings[idx])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-rerun-sel":
            sel = self._state.selected_requests
            if not sel:
                self.app.notify(
                    "No requests selected — go to Requests tab and press Space to select rows",
                    timeout=5,
                )
                try:
                    from textual.widgets import TabbedContent as TC
                    self.app.query_one("#main-tabs", TC).active = "tab-requests"
                except Exception:
                    pass
                return
            self.app.notify(
                f"Running {self._probe_key.upper()} on {len(sel)} request(s)…",
                timeout=4,
            )
            for req in sel:
                self.app._run_probe_on_request(self._probe_key, req)

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
