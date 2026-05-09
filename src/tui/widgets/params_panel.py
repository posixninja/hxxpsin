"""
params_panel.py — Request parameter inspector.

Shows every GET query param, POST body field (JSON / form-encoded / multipart),
and cookie as a selectable table row.  Clicking a row or pressing Space toggles
its selection.  The action bar sends the selected param(s) to Intruder with the
current value wrapped in §§ — ready to fuzz.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Label, Static


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_type(value: str) -> str:
    """Guess the parameter's data type from its value."""
    if value.lower() in ("true", "false"):
        return "boolean"
    try:
        int(value)
        return "integer"
    except ValueError:
        pass
    try:
        float(value)
        return "float"
    except ValueError:
        pass
    if len(value) > 20 and "." in value and value.count(".") == 2:
        return "jwt?"
    return "string"


def _extract_all_params(req: dict) -> list[dict]:
    """
    Parse every parameter from a request dict.
    Returns a list of dicts: {source, name, value, type}
    """
    params: list[dict] = []

    # ── GET query params ──────────────────────────────────────────────────
    try:
        qs = urlparse(req.get("url", "")).query
        if qs:
            for name, vals in parse_qs(qs, keep_blank_values=True).items():
                params.append({
                    "source": "query",
                    "name":   name,
                    "value":  vals[0] if vals else "",
                    "type":   _infer_type(vals[0] if vals else ""),
                })
    except Exception:
        pass

    # ── POST body ─────────────────────────────────────────────────────────
    body = req.get("body") or ""
    if body:
        hdrs = req.get("headers") or {}
        ct = next((v for k, v in hdrs.items() if k.lower() == "content-type"), "")

        if "application/json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    _flatten_json(obj, params, prefix="")
            except Exception:
                pass

        elif "application/x-www-form-urlencoded" in ct:
            try:
                for name, vals in parse_qs(body, keep_blank_values=True).items():
                    val = vals[0] if vals else ""
                    params.append({
                        "source": "body (form)",
                        "name":   name,
                        "value":  val,
                        "type":   _infer_type(val),
                    })
            except Exception:
                pass

        elif "multipart/form-data" in ct:
            # Best-effort: parse part names from raw multipart
            import re
            for m in re.finditer(r'name="([^"]+)"[^\n]*\n\n([^\n-]+)', body):
                name, val = m.group(1), m.group(2).strip()
                params.append({
                    "source": "body (multipart)",
                    "name":   name,
                    "value":  val[:80],
                    "type":   _infer_type(val),
                })

        else:
            # Unknown content-type but body exists — try JSON then form
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    _flatten_json(obj, params, prefix="")
            except Exception:
                try:
                    for name, vals in parse_qs(body, keep_blank_values=True).items():
                        val = vals[0] if vals else ""
                        params.append({
                            "source": "body",
                            "name":   name,
                            "value":  val,
                            "type":   _infer_type(val),
                        })
                except Exception:
                    pass

    # ── Cookie header ─────────────────────────────────────────────────────
    hdrs = req.get("headers") or {}
    cookie_hdr = next((v for k, v in hdrs.items() if k.lower() == "cookie"), "")
    if cookie_hdr:
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, val = part.partition("=")
                params.append({
                    "source": "cookie",
                    "name":   name.strip(),
                    "value":  val.strip()[:60],
                    "type":   _infer_type(val.strip()),
                })

    # ── Request headers ───────────────────────────────────────────────────
    # Skip headers that carry no injection surface
    _SKIP_HEADERS = frozenset({
        "host", "connection", "accept-encoding", "accept-language",
        "accept-charset", "pragma", "cache-control", "upgrade-insecure-requests",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
        "te", "dnt",
    })
    for hdr_name, hdr_val in (hdrs or {}).items():
        if hdr_name.lower() in _SKIP_HEADERS:
            continue
        if hdr_name.lower() == "cookie":
            continue  # already broken out above
        params.append({
            "source": "header",
            "name":   hdr_name,
            "value":  str(hdr_val)[:80],
            "type":   _infer_type(str(hdr_val)),
        })

    return params


def _flatten_json(obj: dict, out: list[dict], prefix: str) -> None:
    """Flatten nested JSON into dot-notation params."""
    for k, v in obj.items():
        name = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flatten_json(v, out, name)
        else:
            val = str(v)
            out.append({
                "source": "body (JSON)",
                "name":   name,
                "value":  val[:80],
                "type":   _infer_type(val),
            })


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------

class ParamsPanel(Vertical):
    """
    Displays every parameter from a request with selection and Intruder routing.

    Keyboard:
      Space   toggle selection on focused row
      a       select all
      i       send selected to Intruder (or all if none selected)
    """

    class SendToIntruder(Message):
        """Posted when user wants to fuzz one or more params."""
        def __init__(self, req: dict, param_names: list[str]) -> None:
            super().__init__()
            self.req = req
            self.param_names = param_names   # params to wrap in §§

    BINDINGS = [
        Binding("space", "toggle_select", "Select", show=False),
        Binding("a",     "select_all",    "All",    show=False),
        Binding("i",     "send_selected", "→ Intruder", show=False),
    ]

    DEFAULT_CSS = """
    ParamsPanel {
        height: 1fr;
        background: $surface;
    }
    ParamsPanel #param-header {
        height: 1;
        padding: 0 1;
        background: $surface-darken-1;
        color: $text-muted;
    }
    ParamsPanel DataTable {
        height: 1fr;
    }
    ParamsPanel #param-action-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
        border-top: solid $primary;
    }
    ParamsPanel #param-action-bar Button {
        margin-right: 1;
        min-width: 14;
    }
    ParamsPanel #param-count {
        content-align: right middle;
        width: 1fr;
        color: $text-muted;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._req: dict | None = None
        self._params: list[dict] = []
        self._selected: set[int] = set()

    def compose(self) -> ComposeResult:
        yield Static("No request selected", id="param-header")
        yield DataTable(id="param-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(id="param-action-bar"):
            yield Button("✓ All",              id="btn-sel-all",  variant="default")
            yield Button("✗ Clear",            id="btn-sel-clear",variant="default")
            yield Button("→ Intruder (sel)",   id="btn-send-sel", variant="warning")
            yield Button("→ Intruder (all §§)",id="btn-send-all", variant="primary")
            yield Label("", id="param-count")

    def on_mount(self) -> None:
        t = self.query_one("#param-table", DataTable)
        t.add_columns("✓", "Name", "Value", "Source", "Type")

    # ── public API ────────────────────────────────────────────────────────

    def update_request(self, req: dict | None) -> None:
        self._req = req
        self._params = _extract_all_params(req) if req else []
        self._selected.clear()
        self._rebuild_table()

    # ── table management ──────────────────────────────────────────────────

    def _rebuild_table(self) -> None:
        t = self.query_one("#param-table", DataTable)
        t.clear()

        if not self._params:
            t.add_row("", "No parameters found in this request", "", "", "")
            self._update_count()
            return

        url = (self._req or {}).get("url", "")
        method = (self._req or {}).get("method", "GET")
        hdrs = (self._req or {}).get("headers") or {}
        ct = next((v for k, v in hdrs.items() if k.lower() == "content-type"), "")
        header_text = f"{method} {url[:60]}{'…' if len(url)>60 else ''}  ·  {ct}" if ct else f"{method} {url[:80]}"
        self.query_one("#param-header", Static).update(header_text)

        for i, p in enumerate(self._params):
            check = "☑" if i in self._selected else "☐"
            val_display = p["value"]
            if len(val_display) > 40:
                val_display = val_display[:38] + "…"
            t.add_row(check, p["name"], val_display, p["source"], p["type"])

        self._update_count()

    def _update_count(self) -> None:
        n = len(self._selected)
        total = len(self._params)
        text = f"{n} selected  /  {total} params" if total else ""
        try:
            self.query_one("#param-count", Label).update(text)
        except Exception:
            pass

    def _toggle_row(self, idx: int) -> None:
        if idx in self._selected:
            self._selected.discard(idx)
        else:
            self._selected.add(idx)
        if 0 <= idx < len(self._params):
            t = self.query_one("#param-table", DataTable)
            check = "☑" if idx in self._selected else "☐"
            t.update_cell_at((idx, 0), check)
        self._update_count()

    # ── events ────────────────────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._toggle_row(event.cursor_row)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn-sel-all":
            self.action_select_all()
        elif btn == "btn-sel-clear":
            self._selected.clear()
            self._rebuild_table()
        elif btn == "btn-send-sel":
            self.action_send_selected()
        elif btn == "btn-send-all":
            self._send([p["name"] for p in self._params])

    # ── actions ───────────────────────────────────────────────────────────

    def action_toggle_select(self) -> None:
        t = self.query_one("#param-table", DataTable)
        self._toggle_row(t.cursor_row)

    def action_select_all(self) -> None:
        self._selected = set(range(len(self._params)))
        self._rebuild_table()

    def action_send_selected(self) -> None:
        names = [self._params[i]["name"] for i in sorted(self._selected)
                 if i < len(self._params)]
        if not names:
            # Nothing selected → send all
            names = [p["name"] for p in self._params]
        self._send(names)

    def _send(self, param_names: list[str]) -> None:
        if self._req and param_names:
            self.post_message(self.SendToIntruder(self._req, param_names))
