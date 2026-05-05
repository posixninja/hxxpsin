"""Repeater tab — manual request editor backed by src/repeater.py."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Label, ListItem, ListView, Static, TextArea
from textual import work

from ..state import AppState, RepeaterSession
from ..widgets.request_viewer import RequestViewer


def _raw_to_dict(raw: str) -> dict:
    """Parse a raw HTTP request string into a dict."""
    lines = raw.splitlines()
    if not lines:
        return {"method": "GET", "url": "", "headers": {}, "body": ""}
    first = lines[0].split()
    method = first[0] if first else "GET"
    url = first[1] if len(first) > 1 else ""
    headers = {}
    body_start = 1
    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_start = i + 1
            break
        if ": " in line:
            k, _, v = line.partition(": ")
            headers[k.strip()] = v.strip()
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    return {"method": method, "url": url, "headers": headers, "body": body}


def _req_to_raw(req: dict) -> str:
    method = req.get("method", "GET")
    url = req.get("url", "")
    headers = req.get("headers", {})
    body = req.get("body") or ""
    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


class RepeaterScreen(Horizontal):
    """Repeater: editable request + response viewer, session management."""

    BINDINGS = [
        Binding("ctrl+enter", "send_request", "Send"),
        Binding("s", "save_session", "Save"),
        Binding("d", "diff_response", "Diff"),
    ]

    DEFAULT_CSS = """
    RepeaterScreen {
        height: 1fr;
    }
    RepeaterScreen #session-panel {
        width: 25%;
        border-right: solid $primary;
    }
    RepeaterScreen #editor-panel {
        width: 75%;
    }
    RepeaterScreen #session-actions {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
    }
    RepeaterScreen #session-actions Button {
        margin-right: 1;
    }
    RepeaterScreen ListView {
        height: 1fr;
    }
    RepeaterScreen #send-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
    }
    RepeaterScreen #send-bar Button {
        min-width: 10;
        margin-right: 1;
    }
    RepeaterScreen .panel-label {
        background: $primary-darken-2;
        padding: 0 1;
        height: 1;
    }
    RepeaterScreen TextArea {
        height: 1fr;
        border: none;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._prev_response: str = ""
        self._current_session_idx: int = -1

    def compose(self) -> ComposeResult:
        with Vertical(id="session-panel"):
            yield Static("Sessions", classes="panel-label")
            yield ListView(id="session-list")
            with Horizontal(id="session-actions"):
                yield Button("New", id="btn-new-session", variant="default")
                yield Button("Del", id="btn-del-session", variant="error")

        with Vertical(id="editor-panel"):
            yield Static("Request", classes="panel-label")
            yield TextArea("", id="req-editor")
            with Horizontal(id="send-bar"):
                yield Button("Send (Ctrl+Enter)", id="btn-send", variant="primary")
                yield Button("Save", id="btn-save", variant="default")
                yield Button("Diff", id="btn-diff", variant="default")
                yield Label("", id="send-status")
            yield Static("Response", classes="panel-label")
            yield TextArea("", id="resp-viewer", read_only=True)

    def on_mount(self) -> None:
        self._refresh_session_list()

    def _refresh_session_list(self) -> None:
        lv = self.query_one("#session-list", ListView)
        lv.clear()
        for s in self._state.repeater_sessions:
            status = f" [{s.last_status}]" if s.last_status else ""
            lv.append(ListItem(Label(f"{s.label}{status}")))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._state.repeater_sessions):
            self._current_session_idx = idx
            sess = self._state.repeater_sessions[idx]
            self.query_one("#req-editor", TextArea).load_text(sess.raw_request)
            self.query_one("#resp-viewer", TextArea).load_text(sess.last_response)

    def load_request(self, req: dict, auth_headers: dict | None = None) -> None:
        """Load a request dict (from other tabs) into the editor."""
        if auth_headers:
            req = dict(req)
            req["headers"] = {**req.get("headers", {}), **auth_headers}
        raw = _req_to_raw(req)
        label = f"{req.get('method', 'GET')} {req.get('url', '')}"[:40]
        session = RepeaterSession(label=label, raw_request=raw)
        self._state.repeater_sessions.append(session)
        self._current_session_idx = len(self._state.repeater_sessions) - 1
        self._refresh_session_list()
        self.query_one("#req-editor", TextArea).load_text(raw)
        self.query_one("#resp-viewer", TextArea).load_text("")

    @work(thread=True)
    def _do_send(self, raw_request: str) -> None:
        """Send the request in a background thread using src/repeater.py."""
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
            from repeater import Repeater, ReplayRequest
            req_dict = _raw_to_dict(raw_request)
            replay_req = ReplayRequest(
                method=req_dict["method"],
                url=req_dict["url"],
                headers=req_dict["headers"],
                body=req_dict["body"] or None,
            )
            import asyncio
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(
                Repeater(verify_tls=False, follow_redirects=True, timeout=15).run(replay_req)
            )
            loop.close()
            if results:
                r = results[0]
                response_text = f"HTTP {r.status}\n"
                for k, v in (r.headers or {}).items():
                    response_text += f"{k}: {v}\n"
                response_text += f"\n{r.body or ''}"
                status = r.status
            else:
                response_text = "(no response)"
                status = 0
        except Exception as exc:
            response_text = f"Error: {exc}"
            status = 0

        def update_ui() -> None:
            self._prev_response = self.query_one("#resp-viewer", TextArea).text
            self.query_one("#resp-viewer", TextArea).load_text(response_text)
            self.query_one("#send-status", Label).update(f"Status: {status}")
            if self._current_session_idx >= 0:
                sess = self._state.repeater_sessions[self._current_session_idx]
                sess.last_response = response_text
                sess.last_status = status
                self._refresh_session_list()

        self.app.call_from_thread(update_ui)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn-send":
            self.action_send_request()
        elif btn == "btn-save":
            self.action_save_session()
        elif btn == "btn-diff":
            self.action_diff_response()
        elif btn == "btn-new-session":
            session = RepeaterSession(label="New session", raw_request="GET / HTTP/1.1\nHost: target.com\n")
            self._state.repeater_sessions.append(session)
            self._current_session_idx = len(self._state.repeater_sessions) - 1
            self._refresh_session_list()
            self.query_one("#req-editor", TextArea).load_text(session.raw_request)
        elif btn == "btn-del-session":
            idx = self._current_session_idx
            if 0 <= idx < len(self._state.repeater_sessions):
                self._state.repeater_sessions.pop(idx)
                self._current_session_idx = max(0, idx - 1)
                self._refresh_session_list()

    def action_send_request(self) -> None:
        raw = self.query_one("#req-editor", TextArea).text
        if self._current_session_idx >= 0:
            self._state.repeater_sessions[self._current_session_idx].raw_request = raw
        self.query_one("#send-status", Label).update("Sending...")
        self._do_send(raw)

    def action_save_session(self) -> None:
        raw = self.query_one("#req-editor", TextArea).text
        if self._current_session_idx >= 0:
            self._state.repeater_sessions[self._current_session_idx].raw_request = raw
            self._refresh_session_list()
            self.app.notify("Session saved")
        else:
            label = raw.splitlines()[0][:40] if raw else "session"
            session = RepeaterSession(label=label, raw_request=raw)
            self._state.repeater_sessions.append(session)
            self._current_session_idx = len(self._state.repeater_sessions) - 1
            self._refresh_session_list()
            self.app.notify("Session saved")

    def action_diff_response(self) -> None:
        current = self.query_one("#resp-viewer", TextArea).text
        if self._prev_response:
            diff_lines = []
            prev_lines = self._prev_response.splitlines()
            curr_lines = current.splitlines()
            for i, (p, c) in enumerate(zip(prev_lines, curr_lines)):
                if p != c:
                    diff_lines.append(f"- {p}")
                    diff_lines.append(f"+ {c}")
                else:
                    diff_lines.append(f"  {c}")
            self.query_one("#resp-viewer", TextArea).load_text("\n".join(diff_lines))
        else:
            self.app.notify("No previous response to diff against")
