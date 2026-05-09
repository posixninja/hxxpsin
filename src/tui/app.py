"""HxxpsinApp — main Textual application."""
from __future__ import annotations

from typing import Any

import asyncio
import sys
import types
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import (
    Footer, Header, Label, ProgressBar, Static, TabbedContent, TabPane,
)
from textual import work

from .state import AppState
from .screens.dashboard import DashboardScreen
from .screens.spider import SpiderScreen, SendToRepeater
from .screens.findings import FindingsScreen
from .screens.enrichment import EnrichmentScreen, LoadAuthIntoRepeater
from .screens.repeater import RepeaterScreen
from .screens.intruder import IntruderScreen
from .screens.probes import ProbesScreen
from .screens.report import ReportScreen
from .widgets.context_panel import ContextPanel
from .widgets.params_panel import ParamsPanel


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
# Main App
# ---------------------------------------------------------------------------

class HxxpsinApp(App):
    """hxxpsin Burp Suite-style TUI."""

    TITLE = "hxxpsin"
    CSS_PATH = None

    BINDINGS = [
        Binding("ctrl+q", "quit",         "Quit"),
        Binding("escape", "go_back",      "Back", show=False, priority=True),
        Binding("ctrl+n", "new_session",  "New Session"),
        Binding("ctrl+l", "reload_data",  "Reload"),
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
        self._stop_requested = False
        self._scan_loop: asyncio.AbstractEventLoop | None = None

        # Tab navigation history — enables ESC to go back
        self._tab_history: list[str] = []
        self._current_main_tab: str = "tab-dashboard"
        self._nav_back_in_flight: bool = False

        # Wire pipeline callback into main.py
        try:
            src_path = str(Path(__file__).resolve().parents[1])
            if src_path not in sys.path:
                sys.path.insert(0, src_path)
            import main as _main_mod
            _main_mod.set_progress_cb(self._on_pipeline_event)
        except Exception:
            pass

        # Register as a state listener so "loaded" / "requests_updated" events
        # automatically refresh all screens on the main thread.
        self._state.add_listener(self._on_state_event)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield DashboardScreen(self._state, id="screen-dashboard")
            with TabPane("Spider", id="tab-spider"):
                yield SpiderScreen(self._state, id="screen-spider")
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

    def on_params_panel_send_to_intruder(self, msg: ParamsPanel.SendToIntruder) -> None:
        """Wrap all selected param names in §§ and load into Intruder."""
        self._send_to_intruder_params(msg.req, msg.param_names)

    def on_send_to_repeater(self, msg: SendToRepeater) -> None:
        repeater = self.query_one("#screen-repeater", RepeaterScreen)
        repeater.load_request(msg.req, source=msg.source)
        self._switch_tab("tab-repeater")

    def on_load_auth_into_repeater(self, msg: LoadAuthIntoRepeater) -> None:
        repeater = self.query_one("#screen-repeater", RepeaterScreen)
        req = {"method": "GET", "url": self._state.target or "/", "headers": msg.headers, "body": ""}
        repeater.load_request(req, auth_headers=msg.headers, source="Enrichment")
        self._switch_tab("tab-repeater")
        self.notify("Auth headers loaded into Repeater")

    def _send_to_intruder(self, req: dict) -> None:
        intruder = self.query_one("#screen-intruder", IntruderScreen)
        intruder.load_request(req)
        self._switch_tab("tab-intruder")

    def _send_to_intruder_params(self, req: dict, param_names: list[str]) -> None:
        """Wrap every listed param in §§ and send to Intruder."""
        for name in param_names:
            self._send_to_intruder_param(req, name)
            req = dict(req)   # work on updated version for next param

        intruder = self.query_one("#screen-intruder", IntruderScreen)
        intruder.load_request(req)
        self._switch_tab("tab-intruder")
        self.notify(
            f"Intruder: {len(param_names)} param(s) marked — "
            f"{', '.join('§'+n+'§' for n in param_names[:4])}"
        )

    def _send_to_intruder_param(self, req: dict, param_name: str) -> None:
        """Load request into Intruder with a specific parameter wrapped in §§."""
        import re as _re
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        import json as _json

        intruder = self.query_one("#screen-intruder", IntruderScreen)

        # Clone the request and mark the target param with §§
        req = dict(req)
        url = req.get("url", "")
        body = req.get("body") or ""
        marked = False

        # Try GET query param first
        p = urlparse(url)
        if p.query:
            qs = parse_qs(p.query, keep_blank_values=True)
            if param_name in qs:
                qs[param_name] = [f"§{qs[param_name][0]}§"]
                new_query = urlencode(qs, doseq=True)
                req["url"] = urlunparse(p._replace(query=new_query))
                marked = True

        # Try POST JSON body
        if not marked and body:
            try:
                obj = _json.loads(body)
                if isinstance(obj, dict) and param_name in obj:
                    obj[param_name] = f"§{obj[param_name]}§"
                    req["body"] = _json.dumps(obj, ensure_ascii=False)
                    marked = True
            except Exception:
                pass

        # Try form-encoded body
        if not marked and body:
            try:
                from urllib.parse import parse_qs as _pqs, urlencode as _enc
                fields = _pqs(body, keep_blank_values=True)
                if param_name in fields:
                    fields[param_name] = [f"§{fields[param_name][0]}§"]
                    encoded = _enc(fields, doseq=True)
                    # urlencode percent-encodes § (U+00A7 → %C2%A7); restore the marker
                    req["body"] = encoded.replace("%C2%A7", "§")
                    marked = True
            except Exception:
                pass

        intruder.load_request(req)
        self._switch_tab("tab-intruder")
        self.notify(f"Intruder: fuzzing §{param_name}§")

    def on_context_panel_action(self, msg: ContextPanel.Action) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        req = msg.req

        if msg.kind == "repeater":
            if req:
                repeater = self.query_one("#screen-repeater", RepeaterScreen)
                repeater.load_request(req, source="Context")
                self._switch_tab("tab-repeater")

        elif msg.kind == "intruder":
            if req:
                self._send_to_intruder(req)

        elif msg.kind == "intruder_param":
            if req:
                self._send_to_intruder_param(req, msg.probe)  # probe holds param name

        elif msg.kind == "run_probe":
            if req:
                self._run_probe_on_request(msg.probe, req)

        elif msg.kind == "probe_tab":
            self._switch_tab("tab-probes")
            try:
                probes_tabs = self.query_one("#screen-probes TabbedContent", TabbedContent)
                probes_tabs.active = f"probes-{msg.probe}"
            except NoMatches:
                pass

        elif msg.kind == "nav_tab":
            self._switch_tab(msg.tab_id)

        elif msg.kind == "spider":
            self._switch_tab("tab-spider")

    @work(thread=True)
    def _run_probe_on_request(self, probe: str, req: dict) -> None:
        """Execute a single probe on one request dict in a background thread."""
        try:
            src_path = str(Path(__file__).resolve().parents[1])
            if src_path not in sys.path:
                sys.path.insert(0, src_path)

            from tui.probe_runner import RUNNERS
            runner = RUNNERS.get(probe)
            if not runner:
                self.call_from_thread(
                    self.notify, f"No runner for '{probe}' — use full scan", severity="warning"
                )
                return

            url_short = (req.get("url") or "")[:50]

            def _start() -> None:
                self._state.probe_status[probe] = "running"
                try:
                    self.query_one("#alerts-bar", AlertsBar).update_status(
                        f"Running {probe.upper()}…  {url_short}"
                    )
                    self.query_one("#screen-probes").refresh_data()
                except NoMatches:
                    pass
                self.notify(f"{probe.upper()} started on {url_short}", timeout=3)

            self.call_from_thread(_start)

            loop = asyncio.new_event_loop()
            try:
                findings = loop.run_until_complete(runner(req))
            finally:
                loop.close()

            def _done(findings=findings) -> None:
                existing = self._state.probe_results.setdefault(probe, [])
                seen_urls = {f.get("url", f.get("endpoint", "")) for f in existing}
                new = [f for f in findings
                       if f.get("url", f.get("endpoint", "")) not in seen_urls]
                existing.extend(new)
                self._state.probe_status[probe] = "done"
                for f in new:
                    f.setdefault("_probe", probe)
                    self._state.findings.append(f)
                # Notify subscribers (Spider sitemap recolors, Findings tab refreshes)
                if new:
                    self._state.emit("findings_updated", probe)

                count = len(findings)
                label = f"{count} finding(s)" if count else "no findings"
                severity = "warning" if count else "information"
                self.notify(
                    f"{probe.upper()} done: {label}",
                    severity=severity, timeout=6,
                )
                try:
                    self.query_one("#alerts-bar", AlertsBar).update_status(
                        f"{probe.upper()} done: {label}"
                    )
                    self.query_one("#screen-probes").refresh_data()
                except NoMatches:
                    pass

                # Jump to the relevant sub-tab on the Probes screen so the user
                # actually lands on the results, not on whatever tab was open.
                if count:
                    self._switch_tab("tab-probes")
                    try:
                        probes_tabs = self.query_one(
                            "#screen-probes TabbedContent", TabbedContent,
                        )
                        probes_tabs.active = f"probes-{probe}"
                    except NoMatches:
                        pass

            self.call_from_thread(_done)

        except Exception as exc:
            def _err(exc=exc) -> None:
                self._state.probe_status[probe] = "failed"
                self.notify(f"{probe} error: {exc}", severity="error", timeout=10)
                try:
                    self.query_one("#alerts-bar", AlertsBar).update_status(f"{probe} failed")
                    self.query_one("#screen-probes").refresh_data()
                except NoMatches:
                    pass
            self.call_from_thread(_err)

    # ── pipeline event handler (called from background thread) ───────────

    def _on_pipeline_event(self, event: str, *args) -> None:
        self._state.on_pipeline_event(event, *args)

        if event == "step":
            n, total, label = args
            def _upd(n=n, total=total, label=label) -> None:
                try:
                    bar = self.query_one("#alerts-bar", AlertsBar)
                    if n == 1:
                        bar.start_scan(total)
                    bar.advance_step(n, total, label)
                except NoMatches:
                    pass
            self.call_from_thread(_upd)

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
                passive=config.get("passive", False),
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
            self._scan_loop = loop
            try:
                if config.get("quick"):
                    loop.run_until_complete(_main_mod.cmd_quick(args))
                else:
                    loop.run_until_complete(_main_mod.cmd_scan(args))
            finally:
                self._scan_loop = None
                pending = asyncio.all_tasks(loop)
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
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

            self.call_from_thread(_done)

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            # Persist the full traceback so the user can debug — a notify toast
            # is too short to show a stack trace.
            try:
                err_file = Path(config["out"]) / "scan_error.log"
                err_file.parent.mkdir(parents=True, exist_ok=True)
                err_file.write_text(f"{exc}\n\n{tb}")
            except Exception:
                pass

            def _err(exc=exc, out=config.get("out", "?")) -> None:
                self.notify(
                    f"Scan error: {exc}  →  see {out}/scan_error.log",
                    severity="error", timeout=15,
                )
                self._state.step_log.append(f"[scan error] {exc}")
                try:
                    self.query_one("#alerts-bar", AlertsBar).finish_scan("Scan failed")
                except NoMatches:
                    pass
                self._state.scan_status = "done"
                self._state.emit("err", str(exc))
            self.call_from_thread(_err)

    def _on_state_event(self, event: str, data: Any) -> None:
        """Called by AppState.emit() — may be from any thread."""
        if event in ("loaded", "requests_updated"):
            self.call_from_thread(self._refresh_all)
        elif event == "crawl_starting":
            self.call_from_thread(self._on_crawl_starting)
        elif event == "request_added":
            req = data
            self.call_from_thread(self._add_request_to_tree, req)

    def _on_crawl_starting(self) -> None:
        pass  # Dashboard shows progress; Spider rebuilds live

    def _add_request_to_tree(self, req: dict) -> None:
        pass  # Spider handles request_added events via its own state listener

    # ── tab history ───────────────────────────────────────────────────────

    def _switch_tab(self, tab_id: str) -> None:
        """Switch main tab and record history synchronously at the call site."""
        if not tab_id:
            return
        if tab_id != self._current_main_tab:
            self._tab_history.append(self._current_main_tab)
            if len(self._tab_history) > 20:
                self._tab_history.pop(0)
            self._current_main_tab = tab_id
        self._nav_back_in_flight = True   # suppress event handler from double-pushing
        self.query_one("#main-tabs", TabbedContent).active = tab_id

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Track USER-INITIATED tab switches (clicking the tab bar)."""
        if event.control.id != "main-tabs":
            return
        if self._nav_back_in_flight:
            self._nav_back_in_flight = False
            return
        new_tab = event.pane.id or ""
        if not new_tab or new_tab == self._current_main_tab:
            return
        # User clicked the tab bar — push to history
        self._tab_history.append(self._current_main_tab)
        if len(self._tab_history) > 20:
            self._tab_history.pop(0)
        self._current_main_tab = new_tab

    def action_go_back(self) -> None:
        """ESC: return to the previously active main tab."""
        if not self._tab_history:
            return
        prev = self._tab_history.pop()
        self._current_main_tab = prev
        self._nav_back_in_flight = True
        self.query_one("#main-tabs", TabbedContent).active = prev

    # ── actions ───────────────────────────────────────────────────────────

    def action_quit(self) -> None:
        import os
        self._stop_requested = True

        # Cancel tasks in any background event loops (scan, spider)
        for loop in [self._scan_loop]:
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(
                    lambda l=loop: [t.cancel() for t in asyncio.all_tasks(l)]
                )
        pass  # Spider manages its own lifecycle

        self.workers.cancel_all()
        self.exit()
        # Force-exit after 2 s if threads are still alive
        import threading
        def _force() -> None:
            import time
            time.sleep(2)
            os._exit(0)
        t = threading.Thread(target=_force, daemon=True)
        t.start()

    def action_new_session(self) -> None:
        """Ctrl+N: open the New Session wizard from anywhere."""
        self._switch_tab("tab-dashboard")
        try:
            self.query_one("#screen-dashboard", DashboardScreen).action_new_session()
        except NoMatches:
            pass

    def action_reload_data(self) -> None:
        if self._state.out_dir:
            self._state.load_output_dir(self._state.out_dir)
            self._refresh_all()
            self.notify("Data reloaded")
        else:
            self.notify("No output directory set", severity="warning")

    def _refresh_all(self) -> None:
        for screen_id in [
            "screen-dashboard", "screen-spider",
            "screen-findings", "screen-enrichment", "screen-probes", "screen-report",
        ]:
            try:
                widget = self.query_one(f"#{screen_id}")
                widget.refresh_data()
            except (NoMatches, AttributeError):
                pass
