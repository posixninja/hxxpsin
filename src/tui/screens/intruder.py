"""Intruder tab — payload fuzzing backed by src/intruder.py."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Label, Select, Static, TextArea
from textual import work

from ..state import AppState

_ATTACK_MODES = ["sniper", "battering_ram", "pitchfork", "cluster_bomb"]
_PAYLOAD_SETS = [
    "xss", "sqli", "lfi", "cmdi", "ssti", "xxe", "nosql",
    "ldap", "crlf", "redirect", "ids", "usernames", "passwords",
]


class IntruderScreen(Horizontal):
    """Intruder: request template + payload config + results table."""

    BINDINGS = [
        Binding("ctrl+r", "run_attack", "Run"),
        Binding("ctrl+s", "stop_attack", "Stop"),
    ]

    DEFAULT_CSS = """
    IntruderScreen {
        height: 1fr;
    }
    IntruderScreen #intruder-config {
        width: 45%;
        border-right: solid $primary;
    }
    IntruderScreen #intruder-results {
        width: 55%;
    }
    IntruderScreen .config-label {
        background: $primary-darken-2;
        padding: 0 1;
        height: 1;
    }
    IntruderScreen TextArea {
        height: 1fr;
        min-height: 10;
        border: none;
    }
    IntruderScreen #attack-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
    }
    IntruderScreen #attack-bar Button {
        min-width: 10;
        margin-right: 1;
    }
    IntruderScreen DataTable {
        height: 1fr;
    }
    IntruderScreen Select {
        width: 18;
        margin-right: 1;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._running = False

    def compose(self) -> ComposeResult:
        with Vertical(id="intruder-config"):
            yield Static("Request Template (mark injection points with §value§)", classes="config-label")
            yield TextArea(
                "GET / HTTP/1.1\nHost: target.com\n",
                id="intruder-req",
            )
            with Horizontal(id="attack-bar"):
                yield Select(
                    [(m, m) for m in _ATTACK_MODES],
                    id="attack-mode",
                    prompt="Attack mode",
                    value="sniper",
                )
                yield Select(
                    [(p, p) for p in _PAYLOAD_SETS],
                    id="payload-set",
                    prompt="Payload set",
                    value="sqli",
                )
                yield Button("Run", id="btn-run", variant="success")
                yield Button("Stop", id="btn-stop", variant="error")
                yield Label("", id="attack-status")

        with Vertical(id="intruder-results"):
            yield Static("Results", classes="config-label")
            yield DataTable(id="intruder-table", cursor_type="row", zebra_stripes=True)
            yield TextArea("", id="intruder-detail", read_only=True)

    def on_mount(self) -> None:
        table = self.query_one("#intruder-table", DataTable)
        table.add_columns("#", "Payload", "Status", "Length", "Elapsed", "Match")

    def load_request(self, req: dict) -> None:
        """Load a request dict into the template editor."""
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
        self.query_one("#intruder-req", TextArea).load_text("\n".join(lines))

    @work(thread=True)
    def _do_attack(self, raw_template: str, mode: str, payload_set: str) -> None:
        """Run intruder attack in background thread."""
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
            from intruder import Intruder, IntruderRequest, load_payloads

            payloads = load_payloads(payload_set)
            if not payloads:
                self.app.call_from_thread(
                    self.query_one("#attack-status", Label).update,
                    "No payloads loaded",
                )
                return

            lines = raw_template.splitlines()
            first = lines[0].split() if lines else []
            method = first[0] if first else "GET"
            url = first[1] if len(first) > 1 else ""
            headers: dict = {}
            body_lines = []
            in_body = False
            for line in lines[1:]:
                if not line.strip() and not in_body:
                    in_body = True
                    continue
                if in_body:
                    body_lines.append(line)
                elif ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.strip()] = v.strip()
            body = "\n".join(body_lines) or None

            intruder_req = IntruderRequest(
                method=method, url=url, headers=headers, body=body,
            )
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(
                Intruder(verify_tls=False, timeout=10, mode=mode).run(
                    intruder_req, payloads[:100]
                )
            )
            loop.close()

            def add_rows() -> None:
                table = self.query_one("#intruder-table", DataTable)
                for r in results:
                    table.add_row(
                        str(r.num),
                        str(r.payloads[0] if r.payloads else "")[:30],
                        str(r.status or ""),
                        str(r.length or ""),
                        f"{r.elapsed:.2f}s" if r.elapsed else "",
                        "✓" if r.grep_match else "",
                    )
                self.query_one("#attack-status", Label).update(
                    f"Done: {len(results)} requests"
                )
                self._state.intruder_results = [
                    {
                        "num": r.num,
                        "payload": r.payloads[0] if r.payloads else "",
                        "status": r.status,
                        "length": r.length,
                        "elapsed": r.elapsed,
                        "grep_match": r.grep_match,
                    }
                    for r in results
                ]
                self._running = False

            self.app.call_from_thread(add_rows)

        except Exception as exc:
            def show_err() -> None:
                self.query_one("#attack-status", Label).update(f"Error: {exc}")
                self._running = False
            self.app.call_from_thread(show_err)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        results = self._state.intruder_results
        if 0 <= idx < len(results):
            r = results[idx]
            detail = "\n".join(f"{k}: {v}" for k, v in r.items())
            self.query_one("#intruder-detail", TextArea).load_text(detail)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            self.action_run_attack()
        elif event.button.id == "btn-stop":
            self._running = False

    def action_run_attack(self) -> None:
        if self._running:
            self.app.notify("Attack already running", severity="warning")
            return
        raw = self.query_one("#intruder-req", TextArea).text
        mode_widget = self.query_one("#attack-mode", Select)
        payload_widget = self.query_one("#payload-set", Select)
        mode = str(mode_widget.value) if mode_widget.value else "sniper"
        payload_set = str(payload_widget.value) if payload_widget.value else "sqli"
        self._running = True
        self.query_one("#intruder-table", DataTable).clear()
        self.query_one("#attack-status", Label).update("Running...")
        self._do_attack(raw, mode, payload_set)

    def action_stop_attack(self) -> None:
        self._running = False
        self.query_one("#attack-status", Label).update("Stopped")
