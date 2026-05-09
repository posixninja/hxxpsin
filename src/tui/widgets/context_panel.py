"""Context panel — reusable widget showing clickable actions for any selected entity."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

_ID_PATH_RE = re.compile(r"/\d{1,10}(?:/|$)|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)")

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.message import Message
from textual.widgets import Button, Static

from ..advisor import suggest
from ..state import AppState


# Probe key → (kind, target)
# kind: "run_probe"  execute the probe directly on the selected request
#       "probe_tab"  navigate to Probes tab + select sub-tab (complex probes)
#       "nav_tab"    navigate to an arbitrary main tab
_ACTION_MAP: dict[str, tuple[str, str]] = {
    # Directly runnable — no full pipeline needed
    "crlf":        ("run_probe", "crlf"),
    "jwt":         ("run_probe", "jwt"),
    "js":          ("run_probe", "js"),
    "fingerprint": ("run_probe", "fingerprint"),
    # Navigation only — require pipeline context or multiple accounts
    "idor":       ("probe_tab", "idor"),
    "active":     ("probe_tab", "active"),
    "upload":     ("probe_tab", "upload"),
    "desync":     ("probe_tab", "desync"),
    "nosql":      ("probe_tab", "nosql"),
    "enrichment": ("nav_tab",   "tab-enrichment"),
    "ws":         ("probe_tab", "ws"),
    "ct":         ("probe_tab", "ct"),
}

# Probes that fire a real runner vs. just navigate
_RUNNABLE = frozenset({"crlf", "jwt", "js", "fingerprint"})


def _extract_params(req: dict) -> list[tuple[str, str]]:
    """Return (name, value) pairs from GET query string and POST body."""
    params: list[tuple[str, str]] = []
    url = req.get("url", "")
    # GET params
    try:
        qs = urlparse(url).query
        if qs:
            for name, vals in parse_qs(qs, keep_blank_values=True).items():
                params.append((name, vals[0] if vals else ""))
    except Exception:
        pass
    # POST body — JSON or form-encoded
    body = req.get("body") or ""
    if body:
        ct = (req.get("headers") or {})
        ct = next((v for k, v in ct.items() if k.lower() == "content-type"), "")
        if "application/json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        params.append((k, str(v)[:40]))
            except Exception:
                pass
        elif "application/x-www-form-urlencoded" in ct or not ct:
            try:
                for name, vals in parse_qs(body, keep_blank_values=True).items():
                    params.append((name, vals[0] if vals else ""))
            except Exception:
                pass
    return params


class ContextPanel(ScrollableContainer):
    """Context-aware action panel.

    Shows for any request (or finding) what can be done next:
    always-on routing buttons plus ranked, clickable probe suggestions.
    Clicking fires a ContextPanel.Action message that bubbles up to HxxpsinApp.

    Buttons use `name` (not `id`) so multiple panel instances in the same
    screen don't produce duplicate-ID DOM violations.
    """

    class Action(Message):
        """Posted when the user clicks any button in the panel."""

        def __init__(
            self,
            kind: str,          # "repeater" | "intruder" | "probe_tab" | "nav_tab"
            *,
            probe: str = "",    # probe key (for probe_tab)
            tab_id: str = "",   # main-tab id (for nav_tab)
            req: dict | None = None,
        ) -> None:
            super().__init__()
            self.kind = kind
            self.probe = probe
            self.tab_id = tab_id
            self.req = req

    DEFAULT_CSS = """
    ContextPanel {
        height: 1fr;
        background: $surface-darken-1;
        padding: 0 1 1 1;
        overflow-y: auto;
    }
    ContextPanel .cp-section {
        color: $text-muted;
        margin-top: 1;
        height: 1;
    }
    ContextPanel .cp-entity-type {
        color: $accent;
        margin-top: 1;
        height: 1;
        text-style: bold;
    }
    ContextPanel .cp-entity {
        color: $text-muted;
        margin-bottom: 1;
        height: 1;
    }
    ContextPanel .cp-route-row {
        height: 3;
        margin-bottom: 1;
    }
    ContextPanel .cp-route-row Button {
        margin-right: 1;
        min-width: 14;
    }
    ContextPanel .cp-sugg-row {
        height: 3;
        margin-bottom: 0;
    }
    ContextPanel .cp-sugg-row Button {
        width: 1fr;
        text-align: left;
    }
    ContextPanel .cp-high Button { color: $error; }
    ContextPanel .cp-med  Button { color: $warning; }
    ContextPanel .cp-low  Button { color: $text-muted; }
    ContextPanel .cp-pinned Button { color: $success; }
    ContextPanel .cp-empty {
        color: $text-muted;
        margin-top: 2;
        height: 1;
    }
    ContextPanel .cp-hint {
        color: $text-muted;
        padding: 0 1;
        height: auto;
        margin-bottom: 1;
    }
    """

    def __init__(self, state: AppState, **kwargs) -> None:
        super().__init__(**kwargs)
        self._state = state
        self._req: dict | None = None

    def compose(self) -> ComposeResult:
        yield Static("Select an entry to see context", classes="cp-empty")

    # ── public API ────────────────────────────────────────────────────────

    def update_entity(self, req: dict | None) -> None:
        """Show context for a request dict."""
        self._req = req
        self._rebuild(req, pinned_probe=None)

    def update_finding(self, finding: dict) -> None:
        """Show context for a finding — reconstructs a minimal req and pins the source probe tab."""
        url = finding.get("url") or finding.get("endpoint", "")
        method = finding.get("method", "GET")
        req: dict = {
            "method": method,
            "url": url,
            "headers": finding.get("request_headers") or {},
            "body": finding.get("request_body"),
            "response": {
                "status": finding.get("response_status", ""),
                "body": finding.get("response_body", ""),
            },
        }
        self._req = req
        self._rebuild(req, pinned_probe=finding.get("_probe"))

    # ── internals ─────────────────────────────────────────────────────────

    def _rebuild(self, req: dict | None, pinned_probe: str | None) -> None:
        self.remove_children()
        if req is None:
            self.mount(Static("Select an entry to see context", classes="cp-empty"))
            return

        # ── Host node (synthetic req from sitemap host click) ────────────
        if req.get("_host_node"):
            host_url = req.get("url", "")
            short_host = ("…" + host_url[-55:]) if len(host_url) > 57 else host_url
            self.mount(Static("[HOST]  Origin", classes="cp-entity-type"))
            self.mount(Static(short_host, classes="cp-entity"))
            self.mount(Static("Actions for Host:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("▶ Fingerprint", name="probe:fingerprint", variant="primary"))
            row.mount(Button("→ Spider", name="action:spider", variant="default"))
            return

        url = req.get("url", "")
        method = req.get("method", "GET")
        resp = req.get("response") or {}
        status = req.get("response_status") or resp.get("status", "")
        short_url = ("…" + url[-55:]) if len(url) > 57 else url

        resource_type = req.get("resource_type", "")
        _STATIC = frozenset({"image", "font", "stylesheet", "media"})
        is_static = resource_type in _STATIC
        is_script = resource_type == "script" or url.endswith((".js", ".ts", ".mjs"))
        is_ws = resource_type == "websocket" or url.startswith(("ws://", "wss://"))
        is_api = resource_type in ("xhr", "fetch") or method in ("POST", "PUT", "PATCH", "DELETE")
        is_doc = resource_type == "document" or (not resource_type and not is_script and not is_ws and not is_static and not is_api)

        # Derive display label
        if is_script:
            etype = "[JS]  JavaScript File"
        elif is_ws:
            etype = "[WS]  WebSocket Endpoint"
        elif resource_type == "stylesheet":
            etype = "[CSS]  Stylesheet"
        elif resource_type == "image":
            etype = "[IMG]  Image Asset"
        elif resource_type in ("font", "media"):
            etype = f"[{resource_type.upper()}]  {resource_type.capitalize()} Asset"
        elif is_api:
            etype = "[API]  API Endpoint"
        elif is_doc:
            etype = "[HTML]  HTML Page"
        else:
            etype = f"[{resource_type.upper() or '?'}]  HTTP Request"

        self.mount(Static(etype, classes="cp-entity-type"))
        self.mount(Static(f"{method}  {short_url}  {status}", classes="cp-entity"))

        # Pinned probe (findings view)
        if pinned_probe and pinned_probe in _ACTION_MAP:
            row = Horizontal(classes="cp-sugg-row cp-pinned")
            self.mount(row)
            row.mount(Button(
                f"Go to {pinned_probe.upper()} probe results",
                name=f"pin:{pinned_probe}",
                variant="success",
            ))

        # ── Entity-type-driven action layout ─────────────────────────────

        # ── Image ────────────────────────────────────────────────────────
        if resource_type == "image":
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("→ Repeater", name="repeater", variant="primary"))
            if _ID_PATH_RE.search(urlparse(url).path):
                row.mount(Button("→ IDOR probe", name="probe:idor", variant="warning"))
            self.mount(Static("Check: auth required? CORS headers? CDN caching?", classes="cp-hint"))
            return

        # ── CSS ──────────────────────────────────────────────────────────
        if resource_type == "stylesheet":
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("→ Repeater", name="repeater", variant="primary"))
            self.mount(Static("Check: X-SourceMap header · /*# sourceMappingURL= */ · external @import URLs", classes="cp-hint"))
            return

        # ── Font ─────────────────────────────────────────────────────────
        if resource_type == "font":
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("→ Repeater", name="repeater", variant="default"))
            self.mount(Static("Check: access control — is this font auth-gated?", classes="cp-hint"))
            return

        # ── Media ────────────────────────────────────────────────────────
        if resource_type == "media":
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("→ Repeater", name="repeater", variant="primary"))
            if _ID_PATH_RE.search(urlparse(url).path):
                row.mount(Button("→ IDOR probe", name="probe:idor", variant="warning"))
            self.mount(Static("Check: access control · auth required? · direct object reference?", classes="cp-hint"))
            return

        if is_script:
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("▶ JS Analysis", name="probe:js", variant="primary"))
            row.mount(Button("→ Repeater", name="repeater", variant="default"))
            return

        if is_ws:
            self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
            row = Horizontal(classes="cp-route-row")
            self.mount(row)
            row.mount(Button("→ WebSocket probe", name="probe:ws", variant="warning"))
            return

        # ── Replayable HTTP (document, API, auth, admin, upload) ─────────
        params = _extract_params(req)
        has_params = bool(params)

        self.mount(Static(f"Actions for {etype}:", classes="cp-section"))
        route_row = Horizontal(classes="cp-route-row")
        self.mount(route_row)
        route_row.mount(Button("→ Repeater", name="repeater", variant="primary"))
        if has_params:
            route_row.mount(Button("→ Intruder", name="intruder", variant="primary"))

        if has_params:
            self.mount(Static("Injectable parameters:", classes="cp-section"))
            params_row = Horizontal(classes="cp-route-row")
            self.mount(params_row)
            for name, _ in params[:8]:
                params_row.mount(Button(f"§{name}§", name=f"inject:{name}", variant="warning"))

        suggestions = suggest(req, self._state)
        if suggestions:
            self.mount(Static("Probe suggestions:", classes="cp-section"))
            for s in suggestions[:8]:
                if s.confidence >= 0.7:
                    css = "cp-high"
                elif s.confidence >= 0.5:
                    css = "cp-med"
                else:
                    css = "cp-low"
                reasons = " · ".join(s.reasons[:2])
                action_prefix = "▶" if s.probe in _RUNNABLE else "→"
                label = f"{action_prefix} {s.confidence_bar}  {s.label}  —  {reasons}"
                row = Horizontal(classes=f"cp-sugg-row {css}")
                self.mount(row)
                row.mount(Button(label, name=f"probe:{s.probe}", variant="default"))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        name = event.button.name or ""
        req = self._req
        event.stop()

        if name == "repeater":
            self.post_message(self.Action("repeater", req=req))

        elif name == "intruder":
            self.post_message(self.Action("intruder", req=req))

        elif name.startswith("probe:"):
            probe = name[len("probe:"):]
            kind, target = _ACTION_MAP.get(probe, ("probe_tab", probe))
            self.post_message(self.Action(kind, probe=probe, tab_id=target, req=req))

        elif name.startswith("pin:"):
            probe = name[len("pin:"):]
            kind, target = _ACTION_MAP.get(probe, ("probe_tab", probe))
            self.post_message(self.Action(kind, probe=probe, tab_id=target, req=req))

        elif name == "action:spider":
            self.post_message(self.Action("spider", req=req))

        elif name.startswith("inject:"):
            param_name = name[len("inject:"):]
            self.post_message(self.Action("intruder_param", probe=param_name, req=req))
