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
        Binding("ctrl+m", "add_marker",   "Add §"),
        Binding("ctrl+shift+m", "clear_markers", "Clear §"),
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
    IntruderScreen #marker-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
        border-top: solid $primary-darken-2;
    }
    IntruderScreen #marker-bar Button {
        min-width: 10;
        margin-right: 1;
    }
    IntruderScreen #marker-status {
        color: $text-muted;
        content-align: left middle;
        padding-left: 1;
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
            with Horizontal(id="marker-bar"):
                yield Button("Add §", id="btn-add-marker", variant="primary")
                yield Button("Auto §", id="btn-auto-marker", variant="default")
                yield Button("Clear §", id="btn-clear-markers", variant="warning")
                yield Label("", id="marker-status")
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
        table.add_row("—", "Run an attack (Ctrl+R) to see results here", "", "", "", "")

    def load_request(self, req: dict, payload_set: str = "") -> None:
        """Load a request dict into the template editor, auto-marking an injection point."""
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = req.get("headers", {})
        body = req.get("body") or ""

        # Auto-mark an injection point so the backend has a position to fuzz.
        # If the request has a body, wrap the whole body; otherwise wrap the
        # last non-empty path segment in the URL.
        # Skip auto-marking if caller already placed §markers§.
        if "§" in body or "§" in url:
            marked_body = body
            marked_url = url
        elif body:
            marked_body = f"§{body}§"
            marked_url = url
        else:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(url)
            segments = [s for s in p.path.split("/") if s]
            if segments:
                segments[-1] = f"§{segments[-1]}§"
                marked_path = "/" + "/".join(segments)
                marked_url = urlunparse(p._replace(path=marked_path))
            else:
                marked_url = url + "§1§"
            marked_body = ""

        lines = [f"{method} {marked_url}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if marked_body:
            lines.append("")
            lines.append(marked_body)

        self.query_one("#intruder-req", TextArea).load_text("\n".join(lines))

        if payload_set and payload_set in _PAYLOAD_SETS:
            sel = self.query_one("#payload-set", Select)
            sel.value = payload_set

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
            total_payloads = len(payloads)
            capped = payloads[:100]
            status_msg = f"{len(capped)} payloads — running…"
            if total_payloads > 100:
                status_msg = f"Using first 100 of {total_payloads} payloads — running…"
                self.app.call_from_thread(
                    self.app.notify,
                    f"Payload set has {total_payloads} entries — capped at 100 for this run",
                    severity="warning",
                    timeout=6,
                )
            self.app.call_from_thread(
                self.query_one("#attack-status", Label).update,
                status_msg,
            )

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
            intruder_result = loop.run_until_complete(
                Intruder(verify_tls=False, timeout=10, mode=mode).run(
                    intruder_req, [capped]
                )
            )
            loop.close()
            results = intruder_result.results

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

            self.app.call_from_thread(add_rows)

        except Exception as exc:
            def show_err() -> None:
                self.query_one("#attack-status", Label).update(f"Error: {exc}")
            self.app.call_from_thread(show_err)
        finally:
            self._running = False

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
        elif event.button.id == "btn-add-marker":
            self.action_add_marker()
        elif event.button.id == "btn-auto-marker":
            self.action_auto_marker()
        elif event.button.id == "btn-clear-markers":
            self.action_clear_markers()

    # ── injection-point markers ───────────────────────────────────────────────

    def action_add_marker(self) -> None:
        """Wrap the current TextArea selection in §...§. If nothing is selected,
        insert §§ at the cursor so the user can type the value between them."""
        ta = self.query_one("#intruder-req", TextArea)
        sel = ta.selected_text or ""
        status = self.query_one("#marker-status", Label)
        if sel:
            ta.replace(f"§{sel}§", ta.selection.start, ta.selection.end)
            status.update(f"Marked: §{sel[:30]}§")
        else:
            # Insert empty markers at cursor
            ta.insert("§§")
            status.update("Inserted §§ — type the value between them")

    def action_clear_markers(self) -> None:
        ta = self.query_one("#intruder-req", TextArea)
        text = ta.text
        n = text.count("§")
        if n == 0:
            self.query_one("#marker-status", Label).update("No markers to clear")
            return
        ta.load_text(text.replace("§", ""))
        self.query_one("#marker-status", Label).update(f"Cleared {n // 2} marker pair(s)")

    def action_auto_marker(self) -> None:
        """Auto-detect parameters in the request and wrap their values in §§.

        Marks: every URL query value, every form-encoded body field's value,
        and every top-level JSON body field's value. Leaves headers alone."""
        ta = self.query_one("#intruder-req", TextArea)
        raw = ta.text
        if not raw.strip():
            return

        lines = raw.splitlines()
        if not lines:
            return

        # Strip any existing markers first so re-running doesn't double-wrap
        if "§" in raw:
            raw = raw.replace("§", "")
            lines = raw.splitlines()

        marked = 0

        # 1. URL query string on the request line
        first_parts = lines[0].split(maxsplit=1)
        if len(first_parts) == 2 and "?" in first_parts[1]:
            method, url = first_parts
            base, _, query = url.partition("?")
            new_pairs: list[str] = []
            for pair in query.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    new_pairs.append(f"{k}=§{v}§")
                    marked += 1
                else:
                    new_pairs.append(pair)
            lines[0] = f"{method} {base}?{'&'.join(new_pairs)}"

        # 2. Body — form-encoded or JSON
        try:
            blank = next(i for i, line in enumerate(lines[1:], 1) if not line.strip())
        except StopIteration:
            blank = None

        if blank and blank + 1 < len(lines):
            body = "\n".join(lines[blank + 1:])
            new_body = body
            stripped = body.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                # JSON: mark top-level string/number values
                import json as _json
                try:
                    obj = _json.loads(body)
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if isinstance(v, (str, int, float, bool)):
                                obj[k] = f"§{v}§"
                                marked += 1
                        new_body = _json.dumps(obj, ensure_ascii=False, indent=2)
                except Exception:
                    pass
            elif "=" in body and "&" in body or ("=" in body and not body.strip().startswith("<")):
                # form-encoded
                pairs = body.split("&")
                new_pairs = []
                for pair in pairs:
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        new_pairs.append(f"{k}=§{v}§")
                        marked += 1
                    else:
                        new_pairs.append(pair)
                new_body = "&".join(new_pairs)
            lines = lines[:blank + 1] + [new_body]

        ta.load_text("\n".join(lines))
        self.query_one("#marker-status", Label).update(
            f"Auto-marked {marked} param(s)" if marked else "No params detected"
        )

    def action_run_attack(self) -> None:
        if self._running:
            self.app.notify("Attack already running", severity="warning")
            return
        raw = self.query_one("#intruder-req", TextArea).text
        if "§" not in raw:
            self.app.notify(
                "No §injection§ markers found — wrap the value to fuzz with §…§",
                severity="warning",
                timeout=6,
            )
            return
        mode_widget = self.query_one("#attack-mode", Select)
        payload_widget = self.query_one("#payload-set", Select)
        mode = str(mode_widget.value) if mode_widget.value else "sniper"
        payload_set = str(payload_widget.value) if payload_widget.value else "sqli"
        self._running = True
        self.query_one("#intruder-table", DataTable).clear()
        self.query_one("#attack-status", Label).update("Starting…")
        self._do_attack(raw, mode, payload_set)

    def action_stop_attack(self) -> None:
        self._running = False
        self.query_one("#attack-status", Label).update("Stopped")
