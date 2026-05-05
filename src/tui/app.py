"""HxxpsinApp — main Textual application."""
from __future__ import annotations

import asyncio
import sys
import types
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.css.query import NoMatches
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Label, ListItem,
    ListView, ProgressBar, RichLog, Static, TabbedContent, TabPane,
)
from textual import work

from .state import AppState
from .screens.target import TargetScreen
from .screens.requests import RequestsScreen, SendToRepeater
from .screens.endpoints import EndpointsScreen
from .screens.findings import FindingsScreen
from .screens.enrichment import EnrichmentScreen, LoadAuthIntoRepeater
from .screens.repeater import RepeaterScreen
from .screens.intruder import IntruderScreen
from .screens.probes import ProbesScreen
from .screens.report import ReportScreen


_PROBE_STEPS = [
    ("stackprint",    "Stackprint fingerprint"),
    ("crawl",         "Playwright crawl"),
    ("classify",      "Classify findings"),
    ("desync",        "Desync probe"),
    ("jwt",           "JWT attack analysis"),
    ("param",         "Param miner"),
    ("verify",        "Verify (active probes)"),
    ("active",        "Active injection scan"),
    ("crlf",          "CRLF probe"),
    ("enrichment",    "Enrichment"),
    ("idor",          "Cross-account IDOR"),
    ("upload",        "Upload probe"),
    ("access_replay", "Access replay"),
]


# ---------------------------------------------------------------------------
# New Target Modal
# ---------------------------------------------------------------------------

class NewTargetModal(ModalScreen):
    """Modal for configuring and launching a new scan target."""

    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    DEFAULT_CSS = """
    NewTargetModal {
        align: center middle;
    }
    NewTargetModal #modal-box {
        width: 74;
        height: 90%;
        border: solid $primary;
        background: $surface;
        layout: vertical;
    }
    NewTargetModal #modal-title {
        background: $primary-darken-2;
        padding: 0 2;
        height: 1;
    }
    NewTargetModal #modal-scroll {
        height: 1fr;
        padding: 0 2;
    }
    NewTargetModal .field-label {
        color: $text-muted;
        margin-top: 1;
    }
    NewTargetModal #modal-actions {
        height: 5;
        padding: 1 2;
        background: $surface-darken-1;
        border-top: solid $primary;
    }
    NewTargetModal #modal-actions Button {
        margin-right: 1;
    }
    NewTargetModal Checkbox {
        margin-top: 1;
    }
    NewTargetModal #scope-note {
        color: $text-muted;
        margin-top: 1;
        margin-bottom: 1;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static("New Target", id="modal-title")

            with ScrollableContainer(id="modal-scroll"):
                yield Static("Target URL *", classes="field-label")
                yield Input(
                    value=self._state.target or "",
                    placeholder="https://target.com",
                    id="new-target-url",
                )

                yield Static("In-scope hosts (comma-separated, beyond the primary host)", classes="field-label")
                yield Input(
                    value=", ".join(self._state.allowed_hosts),
                    placeholder="api.target.com, cdn.target.com",
                    id="new-allowed-hosts",
                )

                yield Static("Excluded URL patterns (regex, comma-separated)", classes="field-label")
                yield Input(
                    value=", ".join(self._state.excluded_patterns),
                    placeholder=r"/logout, /static/, \.png$",
                    id="new-excluded-patterns",
                )

                yield Static("Output directory (leave blank for auto)", classes="field-label")
                yield Input(
                    value="",
                    placeholder="output/my-scan  (auto: output/<host>-<timestamp>)",
                    id="new-out-dir",
                )

                yield Static("Auth (path to auth.json storage state, or blank for auto-auth)", classes="field-label")
                yield Input(value="", placeholder="auth.json", id="new-auth")

                yield Checkbox("Active scan (--active-scan)", id="chk-active", value=False)
                yield Checkbox("Auto-fuzz (--auto-fuzz)", id="chk-autofuzz", value=False)
                yield Checkbox("Quick mode (no browser crawl)", id="chk-quick", value=False)
                yield Checkbox("Allow writes (PUT/DELETE clicks)", id="chk-writes", value=False)

                yield Static(
                    "Scope note: the primary host is always in scope. "
                    "Extra hosts and exclude patterns are applied to the crawler.",
                    id="scope-note",
                )

            with Horizontal(id="modal-actions"):
                yield Button("Add to List", id="btn-add", variant="primary")
                yield Button("Add + Launch", id="btn-launch", variant="success")
                yield Button("Cancel", id="btn-cancel", variant="default")

    def _build_config(self) -> dict | None:
        url = self.query_one("#new-target-url", Input).value.strip()
        if not url:
            self.app.notify("Target URL is required", severity="error")
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        allowed_raw = self.query_one("#new-allowed-hosts", Input).value.strip()
        excluded_raw = self.query_one("#new-excluded-patterns", Input).value.strip()
        out_dir = self.query_one("#new-out-dir", Input).value.strip()
        auth = self.query_one("#new-auth", Input).value.strip()

        if not out_dir:
            host = (urlparse(url).hostname or "target").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_dir = str(Path(__file__).resolve().parents[2] / "output" / f"{host}-{ts}")

        return {
            "target": url,
            "allowed_hosts": [h.strip() for h in allowed_raw.split(",") if h.strip()],
            "excluded_patterns": [p.strip() for p in excluded_raw.split(",") if p.strip()],
            "out": out_dir,
            "auth": auth or None,
            "active_scan": self.query_one("#chk-active", Checkbox).value,
            "auto_fuzz": self.query_one("#chk-autofuzz", Checkbox).value,
            "quick": self.query_one("#chk-quick", Checkbox).value,
            "allow_writes": self.query_one("#chk-writes", Checkbox).value,
        }

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return

        config = self._build_config()
        if config is None:
            return

        # "add-only" returns config with launch=False; "add+launch" sets launch=True
        config["launch"] = (event.button.id == "btn-launch")
        self.dismiss(config)


# ---------------------------------------------------------------------------
# Step runner modal
# ---------------------------------------------------------------------------

class StepRunnerModal(ModalScreen):
    """Modal overlay showing all pipeline steps and their status."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    StepRunnerModal {
        align: center middle;
    }
    StepRunnerModal #modal-box {
        width: 70;
        height: 30;
        border: solid $primary;
        background: $surface;
        padding: 1 2;
    }
    StepRunnerModal #step-table {
        height: 1fr;
    }
    StepRunnerModal #modal-close {
        margin-top: 1;
        width: 12;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static("Step Runner  (Esc to close)")
            yield DataTable(id="step-table", cursor_type="row")
            yield Button("Close", id="modal-close", variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#step-table", DataTable)
        table.add_columns("Step", "Status")
        for key, label in _PROBE_STEPS:
            status = self._state.probe_status.get(key, "○ not run")
            table.add_row(label, status)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-close":
            self.dismiss()


# ---------------------------------------------------------------------------
# Alerts bar
# ---------------------------------------------------------------------------

class AlertsBar(Horizontal):
    """Persistent bottom bar: scan progress (left) + canary alerts (right)."""

    DEFAULT_CSS = """
    AlertsBar {
        height: 3;
        background: $surface-darken-2;
        padding: 0 1;
        border-top: solid $primary-darken-2;
    }
    AlertsBar #scan-progress-col {
        width: 1fr;
        layout: vertical;
    }
    AlertsBar #step-label {
        height: 1;
        color: $text-muted;
    }
    AlertsBar ProgressBar {
        height: 1;
    }
    AlertsBar #scan-idle-label {
        height: 2;
        color: $text-muted;
        content-align: left middle;
    }
    AlertsBar #alerts-col {
        width: 44;
        layout: vertical;
        border-left: solid $primary-darken-2;
        padding: 0 1;
    }
    AlertsBar #alerts-label {
        height: 2;
        color: $warning;
        content-align: left middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="scan-progress-col"):
            yield Label("idle", id="scan-idle-label")
            yield Label("", id="step-label")
            yield ProgressBar(total=13, show_eta=False, show_percentage=False, id="scan-bar")
        with Vertical(id="alerts-col"):
            yield Label("Alerts: (none)", id="alerts-label")

    def on_mount(self) -> None:
        self.query_one("#scan-bar").display = False
        self.query_one("#step-label").display = False

    def start_scan(self, total: int = 13) -> None:
        bar = self.query_one("#scan-bar", ProgressBar)
        bar.total = total
        bar.progress = 0
        bar.display = True
        self.query_one("#step-label").display = True
        self.query_one("#scan-idle-label").display = False

    def advance_step(self, n: int, total: int, label: str) -> None:
        bar = self.query_one("#scan-bar", ProgressBar)
        bar.total = total
        bar.progress = n
        self.query_one("#step-label", Label).update(f"[{n}/{total}] {label}")

    def finish_scan(self, msg: str = "Scan complete") -> None:
        self.query_one("#scan-bar").display = False
        self.query_one("#step-label").display = False
        self.query_one("#scan-idle-label", Label).update(msg)
        self.query_one("#scan-idle-label").display = True

    def update_alert(self, msg: str) -> None:
        self.query_one("#alerts-label", Label).update(f"🔴 {msg}")

    def update_status(self, msg: str) -> None:
        self.query_one("#scan-idle-label", Label).update(msg)


# ---------------------------------------------------------------------------
# Scan progress overlay
# ---------------------------------------------------------------------------

class ScanProgressOverlay(ModalScreen):
    """Non-blocking overlay showing live scan progress log."""

    BINDINGS = [Binding("escape", "dismiss", "Hide (scan continues)")]

    DEFAULT_CSS = """
    ScanProgressOverlay {
        align: center middle;
    }
    ScanProgressOverlay #overlay-box {
        width: 80;
        height: 24;
        border: solid $success;
        background: $surface;
        padding: 1 2;
    }
    ScanProgressOverlay RichLog {
        height: 1fr;
        border: none;
    }
    ScanProgressOverlay #overlay-close {
        margin-top: 1;
        width: 20;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="overlay-box"):
            yield Static("Scan in progress — Esc to hide (scan keeps running)")
            yield RichLog(id="scan-log", highlight=True, markup=True)
            yield Button("Hide overlay", id="overlay-close", variant="default")

    def append_line(self, line: str) -> None:
        try:
            self.query_one("#scan-log", RichLog).write(line)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class HxxpsinApp(App):
    """hxxpsin Burp Suite-style TUI."""

    TITLE = "hxxpsin"
    CSS_PATH = None

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("?", "step_runner", "Steps"),
        Binding("ctrl+n", "new_target", "New Target"),
        Binding("ctrl+p", "show_progress", "Progress"),
        Binding("ctrl+l", "reload_data", "Reload"),
    ]

    DEFAULT_CSS = """
    HxxpsinApp {
        background: $surface;
    }
    TabbedContent {
        height: 1fr;
    }
    .panel-title {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
    }
    """

    def __init__(self, load_dir: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self._state = AppState()
        self._load_dir = load_dir
        self._scan_overlay: ScanProgressOverlay | None = None

        # Wire pipeline callback into main.py
        try:
            src_path = str(Path(__file__).resolve().parents[1])
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            import main as _main_mod
            _main_mod.set_progress_cb(self._on_pipeline_event)
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            with TabPane("Target", id="tab-target"):
                yield TargetScreen(self._state, id="screen-target")
            with TabPane("Requests", id="tab-requests"):
                yield RequestsScreen(self._state, id="screen-requests")
            with TabPane("Endpoints", id="tab-endpoints"):
                yield EndpointsScreen(self._state, id="screen-endpoints")
            with TabPane("Findings", id="tab-findings"):
                yield FindingsScreen(self._state, id="screen-findings")
            with TabPane("Enrichment", id="tab-enrichment"):
                yield EnrichmentScreen(self._state, id="screen-enrichment")
            with TabPane("Repeater", id="tab-repeater"):
                yield RepeaterScreen(self._state, id="screen-repeater")
            with TabPane("Intruder", id="tab-intruder"):
                yield IntruderScreen(self._state, id="screen-intruder")
            with TabPane("Probes", id="tab-probes"):
                yield ProbesScreen(self._state, id="screen-probes")
            with TabPane("Report", id="tab-report"):
                yield ReportScreen(self._state, id="screen-report")
        yield AlertsBar(id="alerts-bar")
        yield Footer()

    def on_mount(self) -> None:
        if self._load_dir:
            self._state.load_output_dir(self._load_dir)
            self._refresh_all()
            self.notify(f"Loaded: {self._load_dir}")

    # ── inter-tab message routing ─────────────────────────────────────────

    def on_send_to_repeater(self, msg: SendToRepeater) -> None:
        repeater = self.query_one("#screen-repeater", RepeaterScreen)
        repeater.load_request(msg.req)
        self.query_one("#main-tabs", TabbedContent).active = "tab-repeater"

    def on_load_auth_into_repeater(self, msg: LoadAuthIntoRepeater) -> None:
        repeater = self.query_one("#screen-repeater", RepeaterScreen)
        req = {"method": "GET", "url": self._state.target or "/", "headers": msg.headers, "body": ""}
        repeater.load_request(req, auth_headers=msg.headers)
        self.query_one("#main-tabs", TabbedContent).active = "tab-repeater"
        self.notify("Auth headers loaded into Repeater")

    def _send_to_intruder(self, req: dict) -> None:
        intruder = self.query_one("#screen-intruder", IntruderScreen)
        intruder.load_request(req)
        self.query_one("#main-tabs", TabbedContent).active = "tab-intruder"

    # ── pipeline event handler (called from background thread) ───────────

    def _on_pipeline_event(self, event: str, *args) -> None:
        self._state.on_pipeline_event(event, *args)

        if event == "step":
            n, total, label = args
            line = f"[{n}/{total}] {label}"
            def _upd(n=n, total=total, label=label, line=line) -> None:
                try:
                    bar = self.query_one("#alerts-bar", AlertsBar)
                    if n == 1:
                        bar.start_scan(total)
                    bar.advance_step(n, total, label)
                except NoMatches:
                    pass
                if self._scan_overlay:
                    self._scan_overlay.append_line(f"[bold]{line}[/bold]")
            self.call_from_thread(_upd)

        elif event == "err":
            msg = args[0]
            def _upd_err(msg=msg) -> None:
                if self._scan_overlay:
                    self._scan_overlay.append_line(f"  {msg}")
            self.call_from_thread(_upd_err)

        elif event == "collector":
            out_path, req_count = args
            def _upd_collector(p=out_path, n=req_count) -> None:
                try:
                    import json
                    from pathlib import Path as _Path
                    data = json.loads((_Path(p) / "collector.json").read_text())
                    self._state.requests = data.get("requests", [])
                    self._state.out_dir = p
                    self.query_one("#alerts-bar", AlertsBar).update_status(
                        f"Crawl done: {n} requests"
                    )
                    try:
                        self.query_one("#screen-target", TargetScreen).refresh_data()
                        self.query_one("#screen-requests", RequestsScreen).refresh_data()
                        self.query_one("#screen-endpoints", EndpointsScreen).refresh_data()
                    except NoMatches:
                        pass
                except Exception:
                    pass
            self.call_from_thread(_upd_collector)

        elif event == "canary":
            hit = args[0]
            alert_msg = f"DNS hit: {hit.get('tag', '?')} @ {hit.get('remote_address', '?')}"
            def _upd_canary(m=alert_msg) -> None:
                try:
                    self.query_one("#alerts-bar", AlertsBar).update_alert(m)
                except NoMatches:
                    pass
            self.call_from_thread(_upd_canary)

        elif event == "challenge":
            trigger = args[0]
            alert_msg = f"Challenge: {trigger.get('name', '?')}"
            def _upd_chal(m=alert_msg) -> None:
                try:
                    self.query_one("#alerts-bar", AlertsBar).update_alert(m)
                except NoMatches:
                    pass
            self.call_from_thread(_upd_chal)

    # ── scan runner ───────────────────────────────────────────────────────

    @work(thread=True, exclusive=True)
    def _run_scan(self, config: dict) -> None:
        """Run cmd_scan or cmd_quick in a background thread."""
        try:
            src_path = str(Path(__file__).resolve().parents[1])
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            import main as _main_mod

            # Build a namespace that matches what argparse produces
            args = types.SimpleNamespace(
                target=config["target"],
                out=config["out"],
                auth=config.get("auth"),
                auth_a=None,
                auth_b=None,
                auth_headers=None,
                auth_name=None,
                auth_email_domain=None,
                auth_email=None,
                auth_password=None,
                auth_username=None,
                active_scan=config.get("active_scan", False),
                auto_fuzz=config.get("auto_fuzz", False),
                allow_writes=config.get("allow_writes", False),
                no_auto_auth=False,
                auto_auth=False,
                no_param_mine=False,
                no_access_replay=False,
                no_upload_probe=False,
                no_sql_dump=False,
                ignore_cdn_block=False,
                headed=False,
                har=None,
                har_include_assets=False,
                max_pages=80,
                max_depth=4,
                timeout=15.0,
                oob=None,
                llm=None,
                llm_host=None,
                llm_model=None,
                llm_budget=None,
                param_mine_top=10,
                # Scope fields (used by crawl pipeline to populate CrawlConfig)
                allowed_hosts=config.get("allowed_hosts", []),
                excluded_patterns=config.get("excluded_patterns", []),
            )

            # Monkey-patch CrawlConfig construction in the pipeline to inject scope.
            # We do this by patching the crawler module's CrawlConfig after import,
            # so the pipeline picks up our allowed_hosts/excluded_patterns.
            try:
                import crawler as _crawler_mod
                _orig_crawlconfig = _crawler_mod.CrawlConfig
                _allowed = args.allowed_hosts
                _excluded = args.excluded_patterns

                class _ScopedCrawlConfig(_orig_crawlconfig):
                    def __init__(self, *a, **kw):
                        kw.setdefault("allowed_hosts", _allowed)
                        kw.setdefault("excluded_patterns", _excluded)
                        super().__init__(*a, **kw)

                _crawler_mod.CrawlConfig = _ScopedCrawlConfig
            except Exception:
                pass

            _main_mod.set_progress_cb(self._on_pipeline_event)

            loop = asyncio.new_event_loop()
            if config.get("quick"):
                loop.run_until_complete(_main_mod.cmd_quick(args))
            else:
                loop.run_until_complete(_main_mod.cmd_scan(args))
            loop.close()

            # Restore original CrawlConfig
            try:
                _crawler_mod.CrawlConfig = _orig_crawlconfig
            except Exception:
                pass

            # Load results into state and refresh UI
            def _done() -> None:
                self._state.load_output_dir(config["out"])
                self._refresh_all()
                try:
                    self.query_one("#alerts-bar", AlertsBar).finish_scan("Scan complete")
                except NoMatches:
                    pass
                self.notify(f"Scan complete → {config['out']}", timeout=8)
                self._scan_overlay = None

            self.call_from_thread(_done)

        except Exception as exc:
            def _err(exc=exc) -> None:
                self.notify(f"Scan error: {exc}", severity="error", timeout=10)
                try:
                    self.query_one("#alerts-bar", AlertsBar).finish_scan("Scan failed")
                except NoMatches:
                    pass
                self._scan_overlay = None
            self.call_from_thread(_err)

    # ── actions ───────────────────────────────────────────────────────────

    def action_new_target(self) -> None:
        def _on_dismiss(config: dict | None) -> None:
            if not config:
                return

            # Add to target list (dedup by URL)
            existing_urls = {t["target"] for t in self._state.targets}
            if config["target"] not in existing_urls:
                self._state.targets.append(config)

            # Update active scope to match this target
            self._state.target = config["target"]
            self._state.allowed_hosts = config.get("allowed_hosts", [])
            self._state.excluded_patterns = config.get("excluded_patterns", [])

            # Refresh the Target tab's target list
            try:
                self.query_one("#screen-target", TargetScreen).refresh_data()
            except NoMatches:
                pass

            if not config.get("launch"):
                self.notify(f"Added: {config['target']}", timeout=4)
                return

            # Launch scan
            overlay = ScanProgressOverlay()
            self._scan_overlay = overlay
            self.push_screen(overlay)
            self.notify(f"Scan started → {config['target']}", timeout=5)
            try:
                self.query_one("#alerts-bar", AlertsBar).start_scan()
            except NoMatches:
                pass
            self._run_scan(config)

        self.push_screen(NewTargetModal(self._state), _on_dismiss)

    def action_show_progress(self) -> None:
        if self._scan_overlay is not None:
            self.push_screen(self._scan_overlay)
        else:
            self.notify("No scan in progress", severity="information")

    def action_step_runner(self) -> None:
        self.push_screen(StepRunnerModal(self._state))

    def action_reload_data(self) -> None:
        if self._state.out_dir:
            self._state.load_output_dir(self._state.out_dir)
            self._refresh_all()
            self.notify("Data reloaded")
        else:
            self.notify("No output directory set", severity="warning")

    def _refresh_all(self) -> None:
        for screen_id in [
            "screen-target", "screen-requests", "screen-endpoints",
            "screen-findings", "screen-enrichment", "screen-probes", "screen-report",
        ]:
            try:
                widget = self.query_one(f"#{screen_id}")
                widget.refresh_data()
            except (NoMatches, AttributeError):
                pass
