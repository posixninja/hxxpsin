"""Dashboard tab — session import, live sitemap, and compact run status.

The Dashboard is the high-level overview: a colored, live-updating sitemap
takes the bulk of the space while a compact right column shows scan progress,
alerts, and a short log tail. Clicking a sitemap node loads its request into
the Spider tab so you can drill in.
"""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Button, Input, Label, ProgressBar, Static, Tree

from ..state import AppState
from ..widgets.chat_panel import ChatPanel
from .spider import (
    _build_severity_index,
    _build_site_map,
    _populate_tree,
    SendToRepeater,
)


class DashboardScreen(Vertical):
    """Sitemap-centric dashboard: live tree on the left, status on the right."""

    BINDINGS = [
        Binding("ctrl+n", "new_session", "New Session"),
        Binding("r", "send_to_repeater", "→ Repeater"),
    ]

    DEFAULT_CSS = """
    DashboardScreen {
        height: 1fr;
        padding: 1;
    }
    DashboardScreen #session-bar {
        height: 3;
        background: $surface-darken-1;
        border: solid $primary-darken-2;
        padding: 0 1;
        margin-bottom: 1;
    }
    DashboardScreen #session-bar Label {
        width: auto;
        content-align: left middle;
        padding-right: 1;
    }
    DashboardScreen #session-bar Input {
        width: 1fr;
    }
    DashboardScreen #session-bar Button {
        min-width: 8;
        margin-left: 1;
    }
    DashboardScreen #panels {
        height: 2fr;
    }
    DashboardScreen #dash-chat {
        height: 1fr;
        min-height: 12;
        margin-top: 1;
    }
    DashboardScreen #sitemap-panel {
        width: 75%;
        border: solid $primary;
        padding: 0 1;
        margin-right: 1;
    }
    DashboardScreen #sitemap-panel Tree {
        height: 1fr;
    }
    DashboardScreen #side-panel {
        width: 25%;
        layout: vertical;
    }
    DashboardScreen #status-block {
        height: auto;
        max-height: 7;
        border: solid $primary-darken-2;
        padding: 0 1;
        margin-bottom: 1;
    }
    DashboardScreen #alerts-block {
        height: 1fr;
        border: solid $primary-darken-2;
        padding: 0 1;
        margin-bottom: 1;
    }
    DashboardScreen #log-block {
        height: 8;
        border: solid $primary-darken-2;
        padding: 0 1;
    }
    DashboardScreen .panel-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
    }
    DashboardScreen #status-target {
        color: $warning;
        height: 1;
    }
    DashboardScreen #status-step {
        color: $text-muted;
        height: 1;
    }
    DashboardScreen ProgressBar {
        height: 1;
    }
    DashboardScreen #status-line {
        color: $text-muted;
        height: 1;
    }
    DashboardScreen #log-text {
        height: 1fr;
    }
    DashboardScreen #alerts-text {
        height: 1fr;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._current_req: dict | None = None
        self._state.add_listener(self._on_state_event)

    def _chat_controller(self):
        """Lazily attach a ChatController to the app so it survives panel
        rebuilds and one MCP subprocess is shared across the session."""
        from ..mcp_chat.controller import ChatController
        ctrl = getattr(self.app, "_chat_controller_instance", None)
        if ctrl is None:
            ctrl = ChatController(state=self._state)
            setattr(self.app, "_chat_controller_instance", ctrl)
        return ctrl

    def compose(self) -> ComposeResult:
        # Session import bar
        with Horizontal(id="session-bar"):
            yield Label("Import:", markup=False)
            yield Input(placeholder="path/to/output/dir", id="import-path")
            yield Button("Load", id="btn-load", variant="default")
            yield Button("New Session  Ctrl+N", id="btn-new", variant="success")

        with Horizontal(id="panels"):
            # Live colored sitemap (takes most of the space)
            with Vertical(id="sitemap-panel"):
                yield Static("Sitemap (live)", classes="panel-header", markup=False)
                yield Tree("Sitemap", id="dash-tree")

            # Compact right column: status / alerts / log tail
            with Vertical(id="side-panel"):
                with Vertical(id="status-block"):
                    yield Static("Status", classes="panel-header", markup=False)
                    yield Label("(no target)", id="status-target")
                    yield Label("", id="status-step")
                    yield ProgressBar(
                        total=13, show_eta=False, show_percentage=False,
                        id="status-bar",
                    )
                    yield Label("idle", id="status-line")

                with Vertical(id="alerts-block"):
                    yield Static("Alerts", classes="panel-header", markup=False)
                    with ScrollableContainer():
                        yield Static("(no alerts)", id="alerts-text")

                with Vertical(id="log-block"):
                    yield Static("Log", classes="panel-header", markup=False)
                    with ScrollableContainer():
                        yield Static("", id="log-text")

        # Full-width chat row below the sitemap/side-panel — gets its own
        # share of the dashboard height so it doesn't compete with the
        # Status / Alerts / Log blocks for vertical space.
        yield ChatPanel(self._chat_controller(), id="dash-chat")

    def on_mount(self) -> None:
        self.query_one("#status-bar").display = False
        self._rebuild_sitemap()
        self._refresh_status()
        self._refresh_alerts()
        self._refresh_log()

    # ── state events ─────────────────────────────────────────────────────────

    def _on_state_event(self, event: str, data=None) -> None:
        if event == "step":
            self.app.call_from_thread(self._refresh_status)
            self.app.call_from_thread(self._refresh_log)
        elif event in ("canary", "challenge"):
            self.app.call_from_thread(self._refresh_alerts)
        elif event == "err":
            self.app.call_from_thread(self._refresh_log)
        elif event in ("loaded", "requests_updated", "findings_updated"):
            self.app.call_from_thread(self._rebuild_sitemap)
            self.app.call_from_thread(self._refresh_status)
            self.app.call_from_thread(self._refresh_alerts)
        elif event == "request_added":
            # Live: rebuild incrementally during a running scan
            self.app.call_from_thread(self._rebuild_sitemap)

    # ── sitemap ──────────────────────────────────────────────────────────────

    def _rebuild_sitemap(self) -> None:
        try:
            tree = self.query_one("#dash-tree", Tree)
        except Exception:
            return

        tree.clear()
        reqs = self._state.requests
        if not reqs:
            tree.root.set_label("Sitemap  (no requests yet — run a scan or import)")
            return

        sev_index = _build_severity_index(self._state)
        n_confirmed = sum(1 for _, (s, _) in sev_index.items() if s == "confirmed")
        n_likely = sum(1 for _, (s, _) in sev_index.items() if s == "likely")
        sev_summary = ""
        if n_confirmed or n_likely:
            sev_summary = f"  [red]{n_confirmed}⚠[/red] [yellow]{n_likely}△[/yellow]"
        tree.root.set_label(f"Sitemap  ({len(reqs)} requests){sev_summary}")

        site_map = _build_site_map(reqs)
        _populate_tree(tree, site_map, sev_index=sev_index)
        tree.root.expand()

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        data = event.node.data
        if data:
            reqs = data.get("reqs") or []
            if reqs:
                self._current_req = reqs[0]

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        # Double-action: hopping straight to Spider for deep inspection.
        data = event.node.data
        if not data:
            return
        reqs = data.get("reqs") or []
        if reqs:
            self._current_req = reqs[0]

    # ── status / alerts / log ────────────────────────────────────────────────

    def _refresh_status(self) -> None:
        state = self._state
        try:
            target_label = self.query_one("#status-target", Label)
            step_label = self.query_one("#status-step", Label)
            status_line = self.query_one("#status-line", Label)
            bar = self.query_one("#status-bar", ProgressBar)
        except Exception:
            return

        target_label.update(state.target or "(no target)")

        if state.scan_status == "running":
            bar.display = True
            status_line.update("running")
            if state.scan_step_total:
                bar.total = state.scan_step_total
                bar.progress = state.scan_step_n
                step_label.update(
                    f"[{state.scan_step_n}/{state.scan_step_total}] "
                    f"{state.scan_step_label}"[:60]
                )
        elif state.scan_status == "done":
            bar.display = False
            step_label.update("complete")
            status_line.update(state.out_dir or "done")
        else:
            bar.display = False
            step_label.update("")
            status_line.update(
                f"loaded: {state.out_dir}" if state.out_dir else "idle"
            )

    def _refresh_alerts(self) -> None:
        state = self._state
        try:
            alerts_text = self.query_one("#alerts-text", Static)
        except Exception:
            return

        lines: list[str] = []
        for hit in state.canary_hits[-15:]:
            tag = hit.get("tag", "?")
            addr = hit.get("remote_address", "?")
            lines.append(f"[red][DNS][/red] {tag} @ {addr}")
        for trig in state.challenge_triggers[-15:]:
            name = trig.get("name", "?")
            lines.append(f"[yellow][CHAL][/yellow] {name}")

        if lines:
            alerts_text.update("\n".join(lines[-30:]))
        else:
            alerts_text.update("(no alerts)")

    def _refresh_log(self) -> None:
        state = self._state
        try:
            log_text = self.query_one("#log-text", Static)
        except Exception:
            return
        if state.step_log:
            log_text.update("\n".join(state.step_log[-6:]))
        else:
            log_text.update("")

    # ── button handlers ──────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-load":
            path = self.query_one("#import-path", Input).value.strip()
            if not path:
                self.app.notify("Enter a path to load", severity="warning")
                return
            p = Path(path)
            if not p.is_dir():
                self.app.notify(f"Directory not found: {path}", severity="error")
                return
            self._state.load_output_dir(str(p))
            self.app.notify(f"Loaded: {path}", timeout=4)

        elif event.button.id == "btn-new":
            self.action_new_session()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "import-path":
            self.query_one("#btn-load", Button).press()

    # ── actions ───────────────────────────────────────────────────────────────

    def action_new_session(self) -> None:
        from .wizard import WizardScreen

        def _on_result(config: dict | None) -> None:
            if config is None:
                return
            self._state.target = config["target"]
            self._state.out_dir = config["out"]
            # Stash config so Spider's "Spider now" / probes can re-use the
            # auth, scope, and other wizard fields without re-prompting.
            self._state.session_config = dict(config)

            mode = config.get("mode", "automatic")
            if mode == "manual":
                # Manual: do NOT auto-run anything. User drives crawl/probes
                # from Spider, Repeater, and Probes tabs.
                self._state.scan_status = "idle"
                self._refresh_status()
                self.app.notify(
                    f"Manual session: {config['target']}  — "
                    "use Spider tab to crawl, run probes from Spider/Repeater",
                    timeout=8,
                )
                self.app._switch_tab("tab-spider")
            else:
                self._state.scan_status = "running"
                self._refresh_status()
                self.app._run_scan(config)

        self.app.push_screen(WizardScreen(), _on_result)

    def action_send_to_repeater(self) -> None:
        if self._current_req:
            self.post_message(SendToRepeater(self._current_req, source="Dashboard"))
        else:
            self.app.notify("Highlight a sitemap node first", severity="warning")

    # ── public ────────────────────────────────────────────────────────────────

    def refresh_data(self) -> None:
        self._rebuild_sitemap()
        self._refresh_status()
        self._refresh_alerts()
        self._refresh_log()
