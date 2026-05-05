"""Requests tab — primary entity hub with action bar."""
from __future__ import annotations

from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Static
from textual import on

from ..state import AppState
from ..advisor import suggest
from ..widgets.request_viewer import RequestViewer

_PROBE_BADGES = {
    "idor": "IDR",
    "jwt": "JWT",
    "active": "ACT",
    "nosql": "NSQ",
    "crlf": "CRL",
    "upload": "UPL",
    "dom_xss": "XSS",
    "desync": "DSY",
    "report": "RPT",
}


class SendToRepeater(Message):
    def __init__(self, req: dict) -> None:
        super().__init__()
        self.req = req


class RequestsScreen(Horizontal):
    """Main request browser with action bar and raw request/response panel."""

    BINDINGS = [
        Binding("r", "send_to_repeater", "→ Repeater"),
        Binding("i", "send_to_intruder", "→ Intruder"),
        Binding("space", "toggle_select", "Select"),
        Binding("/", "focus_filter", "Filter"),
    ]

    DEFAULT_CSS = """
    RequestsScreen {
        height: 1fr;
    }
    RequestsScreen #left-panel {
        width: 55%;
        border-right: solid $primary;
    }
    RequestsScreen #right-panel {
        width: 45%;
    }
    RequestsScreen #filter-bar {
        height: 3;
        background: $surface;
        padding: 0 1;
    }
    RequestsScreen DataTable {
        height: 1fr;
    }
    RequestsScreen #action-bar {
        height: 3;
        background: $surface-darken-1;
        padding: 0 1;
    }
    RequestsScreen #action-bar Button {
        min-width: 8;
        margin-right: 1;
    }
    RequestsScreen #suggestions-panel {
        height: 6;
        border-top: solid $primary;
        background: $surface-darken-1;
        padding: 0 1;
        overflow-y: auto;
    }
    RequestsScreen .suggestion-high { color: $error; }
    RequestsScreen .suggestion-med  { color: $warning; }
    RequestsScreen .suggestion-low  { color: $text-muted; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._filtered: list[dict] = []
        self._selected_idx: set[int] = set()

    def compose(self) -> ComposeResult:
        with Vertical(id="left-panel"):
            with Horizontal(id="filter-bar"):
                yield Label("Filter: ")
                yield Input(placeholder="url / method / status", id="filter-input")
            yield DataTable(id="req-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="action-bar"):
                yield Button("Classify", id="act-classify", variant="default")
                yield Button("IDOR", id="act-idor", variant="warning")
                yield Button("JWT", id="act-jwt", variant="warning")
                yield Button("SQLi", id="act-sqli", variant="warning")
                yield Button("CRLF", id="act-crlf", variant="warning")
                yield Button("Param", id="act-param", variant="default")
                yield Button("→ Repeater", id="act-repeater", variant="primary")
                yield Button("→ Intruder", id="act-intruder", variant="primary")

        with Vertical(id="right-panel"):
            yield RequestViewer(id="req-viewer")
            yield Static("Suggestions", classes="panel-title")
            yield Vertical(id="suggestions-panel")

    def on_mount(self) -> None:
        table = self.query_one("#req-table", DataTable)
        table.add_columns("#", "Method", "URL", "St", "Len", "⚡")
        self._refresh_table()

    def _badge_for_req(self, req: dict) -> str:
        url = req.get("url", "")
        badges = []
        for probe, tag in _PROBE_BADGES.items():
            results = self._state.probe_results.get(probe, [])
            if any(r.get("url", "") == url or r.get("endpoint", "") == url for r in results):
                badges.append(tag)
        return " ".join(badges)

    def _refresh_table(self, filter_text: str = "") -> None:
        table = self.query_one("#req-table", DataTable)
        table.clear()
        reqs = self._state.requests
        if filter_text:
            ft = filter_text.lower()
            reqs = [r for r in reqs if ft in r.get("url", "").lower()
                    or ft in r.get("method", "").lower()
                    or ft in str(r.get("response_status", "") or r.get("response", {}).get("status", ""))]
        self._filtered = reqs
        for i, req in enumerate(reqs):
            method = req.get("method", "?")
            url = req.get("url", "")
            resp = req.get("response", {}) or {}
            status = req.get("response_status") or resp.get("status", "")
            body = req.get("response_body") or resp.get("body") or ""
            length = len(body) if body else 0
            badge = self._badge_for_req(req)
            display_url = url[40:] if len(url) > 80 else url
            table.add_row(str(i + 1), method, display_url, str(status), str(length), badge)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._filtered):
            req = self._filtered[idx]
            self.query_one("#req-viewer", RequestViewer).show_request(req)
            self._update_suggestions(req)

    def _update_suggestions(self, req: dict) -> None:
        panel = self.query_one("#suggestions-panel", Vertical)
        panel.remove_children()
        suggestions = suggest(req, self._state)
        if not suggestions:
            panel.mount(Static("No high-confidence suggestions for this request.", classes="suggestion-low"))
            return
        for s in suggestions[:6]:
            if s.confidence >= 0.7:
                css_class = "suggestion-high"
            elif s.confidence >= 0.5:
                css_class = "suggestion-med"
            else:
                css_class = "suggestion-low"
            reasons = " · ".join(s.reasons)
            panel.mount(Static(
                f"{s.confidence_bar} {s.label:<22} {reasons}",
                classes=css_class,
            ))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter-input":
            self._refresh_table(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        sel = self._get_selection()
        btn = event.button.id

        if btn == "act-repeater":
            for req in sel:
                self.post_message(SendToRepeater(req))
            if sel:
                self.app.notify(f"Sent {len(sel)} request(s) to Repeater")

        elif btn == "act-intruder":
            if sel:
                self.app._send_to_intruder(sel[0])
                self.app.notify("Sent to Intruder")

        elif btn in ("act-classify", "act-idor", "act-jwt", "act-sqli",
                     "act-crlf", "act-param"):
            probe_map = {
                "act-classify": "classify",
                "act-idor": "idor",
                "act-jwt": "jwt",
                "act-sqli": "sqli",
                "act-crlf": "crlf",
                "act-param": "param",
            }
            probe = probe_map.get(btn, btn)
            self.app.notify(
                f"Running {probe} on {len(sel)} request(s)... (manual probe API coming soon)"
            )

    def _get_selection(self) -> list[dict]:
        table = self.query_one("#req-table", DataTable)
        idx = table.cursor_row
        if self._selected_idx:
            return [self._filtered[i] for i in sorted(self._selected_idx)
                    if i < len(self._filtered)]
        if 0 <= idx < len(self._filtered):
            return [self._filtered[idx]]
        return []

    def action_send_to_repeater(self) -> None:
        sel = self._get_selection()
        for req in sel:
            self.post_message(SendToRepeater(req))
        if sel:
            self.app.notify(f"Sent {len(sel)} request(s) to Repeater")

    def action_send_to_intruder(self) -> None:
        sel = self._get_selection()
        if sel:
            self.app._send_to_intruder(sel[0])

    def action_toggle_select(self) -> None:
        table = self.query_one("#req-table", DataTable)
        idx = table.cursor_row
        if idx in self._selected_idx:
            self._selected_idx.discard(idx)
        else:
            self._selected_idx.add(idx)
        self._state.selected_requests = list(self._selected_idx)

    def action_focus_filter(self) -> None:
        self.query_one("#filter-input", Input).focus()

    def refresh_data(self) -> None:
        self._refresh_table()
