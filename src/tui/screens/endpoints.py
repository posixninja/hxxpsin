"""Endpoints tab — path-pattern grouped view with probe actions."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Label, ListItem, ListView, Static, TextArea

from ..state import AppState
from ..widgets.request_viewer import RequestViewer


def _normalize_path(path: str) -> str:
    """Replace numeric/UUID segments with {id}."""
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{uuid}", path)
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

    DEFAULT_CSS = """
    EndpointsScreen {
        height: 1fr;
    }
    EndpointsScreen #ep-list-panel {
        width: 40%;
        border-right: solid $primary;
    }
    EndpointsScreen #ep-detail-panel {
        width: 60%;
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

    def compose(self) -> ComposeResult:
        with Vertical(id="ep-list-panel"):
            yield Static("Endpoints", classes="panel-title" if False else "")
            yield ListView(id="ep-list")

        with Vertical(id="ep-detail-panel"):
            yield Static("Requests for endpoint:", id="ep-header")
            yield DataTable(id="ep-req-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="ep-action-bar"):
                yield Button("Auth Bypass", id="act-auth-bypass", variant="warning")
                yield Button("Desync", id="act-desync", variant="warning")
                yield Button("BFLA Test", id="act-bfla", variant="warning")
                yield Button("Param Mine", id="act-param", variant="default")
                yield Button("Fuzz Methods", id="act-fuzz-methods", variant="default")

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
    """

    def on_mount(self) -> None:
        table = self.query_one("#ep-req-table", DataTable)
        table.add_columns("Method", "URL", "Status", "Length")
        self._refresh_list()

    def _refresh_list(self) -> None:
        lv = self.query_one("#ep-list", ListView)
        lv.clear()
        self._groups = _group_by_endpoint(self._state.requests)
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
            self._show_endpoint(pattern)

    def _show_endpoint(self, pattern: str) -> None:
        self.query_one("#ep-header", Static).update(f"Requests for: {pattern}")
        table = self.query_one("#ep-req-table", DataTable)
        table.clear()
        for req in self._groups.get(pattern, []):
            resp = req.get("response", {}) or {}
            status = req.get("response_status") or resp.get("status", "")
            body = req.get("response_body") or resp.get("body") or ""
            table.add_row(
                req.get("method", "?"),
                req.get("url", ""),
                str(status),
                str(len(body) if body else 0),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        reqs = self._groups.get(self._selected_pattern, [])
        if not reqs:
            self.app.notify("Select an endpoint first", severity="warning")
            return
        probe_names = {
            "act-auth-bypass": "auth bypass",
            "act-desync": "desync probe",
            "act-bfla": "BFLA test",
            "act-param": "param miner",
            "act-fuzz-methods": "method fuzzer",
        }
        name = probe_names.get(btn, btn)
        self.app.notify(
            f"Running {name} on {len(reqs)} requests for {self._selected_pattern}..."
            " (manual probe API coming soon)"
        )

    def refresh_data(self) -> None:
        self._refresh_list()
