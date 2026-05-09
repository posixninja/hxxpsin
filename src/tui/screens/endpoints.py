"""Endpoints tab — path-pattern grouped view with probe actions."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Label, ListItem, ListView, Static

from ..state import AppState
from ..widgets.context_panel import ContextPanel
from .requests import SendToRepeater


def _normalize_path(path: str) -> str:
    """Replace numeric/UUID segments with {id}/{uuid}."""
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}",
        path,
    )
    return path


def _group_by_endpoint(requests: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for req in requests:
        url = req.get("url", "")
        try:
            p = urlparse(url)
            pattern = _normalize_path(p.path or "/")
        except Exception:
            pattern = "/"
        groups[pattern].append(req)
    return dict(groups)


class EndpointsScreen(Horizontal):
    """Endpoint pattern browser with probe action bar."""

    BINDINGS = [
        Binding("r", "send_to_repeater", "→ Repeater"),
        Binding("i", "send_to_intruder", "→ Intruder"),
    ]

    DEFAULT_CSS = """
    EndpointsScreen {
        height: 1fr;
    }
    EndpointsScreen #ep-list-panel {
        width: 38%;
        border-right: solid $primary;
    }
    EndpointsScreen #ep-detail-panel {
        width: 62%;
    }
    EndpointsScreen .panel-title {
        background: $primary-darken-2;
        padding: 0 1;
        height: 1;
    }
    EndpointsScreen #ep-action-bar {
        height: 3;
        background: $surface-darken-1;
        padding: 0 1;
    }
    EndpointsScreen #ep-action-bar Button {
        min-width: 12;
        margin-right: 1;
    }
    EndpointsScreen DataTable {
        height: 1fr;
    }
    EndpointsScreen ListView {
        height: 1fr;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._groups: dict[str, list[dict]] = {}
        self._selected_pattern: str = ""
        self._selected_req: dict | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="ep-list-panel"):
            yield Static("Endpoints", classes="panel-title")
            yield ListView(id="ep-list")

        with Vertical(id="ep-detail-panel"):
            yield Static("Requests for endpoint:", id="ep-header", classes="panel-title")
            yield DataTable(id="ep-req-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="ep-action-bar"):
                yield Button("→ Repeater",  id="act-repeater",    variant="primary")
                yield Button("→ Intruder",  id="act-intruder",    variant="primary")
                yield Button("Auth Bypass", id="act-auth-bypass", variant="warning")
                yield Button("Desync",      id="act-desync",      variant="warning")
                yield Button("BFLA Test",   id="act-bfla",        variant="warning")
                yield Button("Param Mine",  id="act-param",       variant="default")
                yield Button("Fuzz Methods",id="act-fuzz-methods",variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#ep-req-table", DataTable)
        table.add_columns("Method", "URL", "Status", "Length")
        self._refresh_list()

    def _refresh_list(self) -> None:
        lv = self.query_one("#ep-list", ListView)
        lv.clear()
        self._groups = _group_by_endpoint(self._state.requests)
        if not self._groups:
            lv.append(ListItem(Label("No endpoints — load requests first")))
            return
        for pattern, reqs in sorted(self._groups.items()):
            methods = sorted(set(r.get("method", "?") for r in reqs))
            label = f"{pattern}  [{','.join(methods)}] ({len(reqs)})"
            lv.append(ListItem(Label(label)))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        patterns = list(sorted(self._groups.keys()))
        idx = self.query_one("#ep-list", ListView).index
        if idx is not None and 0 <= idx < len(patterns):
            pattern = patterns[idx]
            self._selected_pattern = pattern
            self._selected_req = None
            self._show_endpoint(pattern)

    def _show_endpoint(self, pattern: str) -> None:
        self.query_one("#ep-header", Static).update(f"Requests for: {pattern}")
        table = self.query_one("#ep-req-table", DataTable)
        table.clear()
        reqs = self._groups.get(pattern, [])
        if not reqs:
            table.add_row("—", "No requests for this endpoint", "", "")
            return
        for req in reqs:
            resp = req.get("response", {}) or {}
            status = req.get("response_status") or resp.get("status", "")
            body = req.get("response_body") or resp.get("body") or ""
            table.add_row(
                req.get("method", "?"),
                req.get("url", ""),
                str(status),
                str(len(body) if body else 0),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        reqs = self._groups.get(self._selected_pattern, [])
        idx = event.cursor_row
        self._selected_req = reqs[idx] if 0 <= idx < len(reqs) else None

    def _require_selection(self) -> bool:
        """Notify and return False if nothing is selected."""
        if not self._selected_pattern or not self._groups.get(self._selected_pattern):
            self.app.notify("Select an endpoint first", severity="warning")
            return False
        return True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if not self._require_selection():
            return

        reqs = self._groups.get(self._selected_pattern, [])
        req = self._selected_req or (reqs[0] if reqs else None)

        if btn == "act-repeater":
            if req:
                self.post_message(SendToRepeater(req, source="Endpoints"))

        elif btn == "act-intruder":
            if req:
                self.app._send_to_intruder(req)

        elif btn == "act-auth-bypass":
            self.post_message(ContextPanel.Action("probe_tab", probe="active", req=req))

        elif btn == "act-desync":
            self.post_message(ContextPanel.Action("probe_tab", probe="desync", req=req))

        elif btn == "act-bfla":
            self.post_message(ContextPanel.Action("probe_tab", probe="active", req=req))

        elif btn == "act-param":
            if req:
                intruder = self.app.query_one("#screen-intruder")
                intruder.load_request(req, payload_set="cache_headers")
                self.app.query_one("#main-tabs").active = "tab-intruder"
                self.app.notify(f"Loaded into Intruder for param mining: {self._selected_pattern}")

        elif btn == "act-fuzz-methods":
            if req:
                intruder = self.app.query_one("#screen-intruder")
                intruder.load_request(req, payload_set="methods")
                self.app.query_one("#main-tabs").active = "tab-intruder"
                self.app.notify(f"Fuzzing HTTP methods on: {self._selected_pattern}")

    def action_send_to_repeater(self) -> None:
        req = self._selected_req or next(
            iter(self._groups.get(self._selected_pattern, [])), None
        )
        if req:
            self.post_message(SendToRepeater(req, source="Endpoints"))

    def action_send_to_intruder(self) -> None:
        req = self._selected_req or next(
            iter(self._groups.get(self._selected_pattern, [])), None
        )
        if req:
            self.app._send_to_intruder(req)

    def refresh_data(self) -> None:
        self._refresh_list()
