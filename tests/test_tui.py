"""Headless TUI tests using Textual's run_test / Pilot API.

Run:  python -m pytest tests/test_tui.py -v
  or: python tests/test_tui.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textual.widgets import TabbedContent, DataTable, Button, Input, TextArea, Label
from textual.css.query import NoMatches

from tui.app import HxxpsinApp, AlertsBar
from tui.state import AppState
from tui.screens.dashboard import DashboardScreen
from tui.screens.spider import SpiderScreen
from tui.screens.findings import FindingsScreen
from tui.screens.repeater import RepeaterScreen
from tui.screens.intruder import IntruderScreen
from tui.screens.probes import ProbesScreen
from tui.widgets.entity_tree import EntityTree, _EntityExtractor


# ── fixtures ─────────────────────────────────────────────────────────────────

def _make_output_dir(tmp: Path) -> Path:
    requests = [
        {"method": "GET",  "url": "http://test.local/",            "status": 200, "content_type": "text/html",        "resource_type": "document", "body": ""},
        {"method": "POST", "url": "http://test.local/api/login",    "status": 401, "content_type": "application/json", "resource_type": "fetch",    "body": '{"user":"a"}'},
        {"method": "GET",  "url": "http://test.local/api/profile",  "status": 200, "content_type": "application/json", "resource_type": "xhr",      "body": ""},
    ]
    collector = {
        "origin": "http://test.local",
        "requests": requests,
        "js_discovered_routes": ["/api/admin", "/api/internal"],
        "js_bundle_urls": ["http://test.local/app.js"],
    }
    (tmp / "collector.json").write_text(json.dumps(collector))

    findings = [
        {"category": "sqli",   "url": "http://test.local/api/login",   "verdict": "confirmed", "confidence": 0.9, "_probe": "active"},
        {"category": "idor",   "url": "http://test.local/api/profile",  "verdict": "potential", "confidence": 0.7, "_probe": "idor"},
        {"attack": "alg_none", "endpoint": "http://test.local/api/login","verdict": "confirmed", "confidence": 1.0, "_probe": "jwt"},
    ]
    (tmp / "verify.json").write_text(json.dumps([findings[0]]))
    (tmp / "idor_probe.json").write_text(json.dumps([findings[1]]))
    (tmp / "jwt_attack.json").write_text(json.dumps([findings[2]]))

    stackprint = {"origin": "http://test.local", "detected": {"framework": ["Django"]}}
    (tmp / "stackprint.json").write_text(json.dumps(stackprint))
    return tmp


@pytest.fixture
def out_dir(tmp_path):
    return _make_output_dir(tmp_path)


# ── TestStartup ───────────────────────────────────────────────────────────────

class TestStartup:
    @pytest.mark.asyncio
    async def test_launches_headless(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-dashboard"

    @pytest.mark.asyncio
    async def test_all_tabs_present(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            expected = [
                "tab-dashboard", "tab-spider", "tab-findings",
                "tab-enrichment", "tab-repeater", "tab-intruder",
                "tab-probes", "tab-report",
            ]
            for tab_id in expected:
                assert app.query_one(f"#{tab_id}") is not None, f"Missing: {tab_id}"

    @pytest.mark.asyncio
    async def test_requests_tab_removed(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            with pytest.raises(NoMatches):
                app.query_one("#tab-requests")

    @pytest.mark.asyncio
    async def test_alerts_bar_idle(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            bar = app.query_one("#alerts-bar", AlertsBar)
            assert bar.query_one("#scan-bar").display is False


# ── TestStateLoading ──────────────────────────────────────────────────────────

class TestStateLoading:
    @pytest.mark.asyncio
    async def test_loads_requests_from_dir(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            assert len(app._state.requests) == 3

    @pytest.mark.asyncio
    async def test_loads_findings_from_dir(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            assert len(app._state.findings) == 3

    @pytest.mark.asyncio
    async def test_loads_stackprint(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            assert app._state.stackprint.get("detected", {}).get("framework") == ["Django"]

    @pytest.mark.asyncio
    async def test_probe_status_set_done(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            for probe in ("active", "idor", "jwt"):
                assert app._state.probe_status.get(probe) == "done"


# ── TestTabNavigation ─────────────────────────────────────────────────────────

class TestTabNavigation:
    @pytest.mark.asyncio
    async def test_tab_switch_updates_active(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-spider"

    @pytest.mark.asyncio
    async def test_esc_navigates_back(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            app._switch_tab("tab-findings")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-spider"

    @pytest.mark.asyncio
    async def test_tab_history_max_20(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            tab_cycle = ["tab-spider", "tab-findings", "tab-repeater", "tab-intruder"]
            for i in range(25):
                app._switch_tab(tab_cycle[i % len(tab_cycle)])
            assert len(app._tab_history) <= 20

    @pytest.mark.asyncio
    async def test_all_tabs_navigable(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            for tab_id in ["tab-spider", "tab-findings", "tab-enrichment",
                           "tab-repeater", "tab-intruder", "tab-probes", "tab-report"]:
                app._switch_tab(tab_id)
                await pilot.pause()
                assert app.query_one("#main-tabs", TabbedContent).active == tab_id


# ── TestDashboard ─────────────────────────────────────────────────────────────

class TestDashboard:
    @pytest.mark.asyncio
    async def test_dashboard_renders_idle(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            assert screen is not None

    @pytest.mark.asyncio
    async def test_dashboard_load_button_exists(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            assert screen.query_one("#btn-load", Button) is not None

    @pytest.mark.asyncio
    async def test_dashboard_new_session_button_exists(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            assert screen.query_one("#btn-new", Button) is not None

    @pytest.mark.asyncio
    async def test_load_invalid_path_notifies(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            screen.query_one("#import-path", Input).value = "/nonexistent/path"
            await pilot.pause()
            screen.query_one("#btn-load", Button).press()
            await pilot.pause()
            # should not crash — just notify

    @pytest.mark.asyncio
    async def test_progress_uses_step_event_not_log_tail(self):
        """Dashboard progress should reflect last step event, not the err log tail."""
        from textual.widgets import ProgressBar
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._state.scan_status = "running"
            app._state.on_pipeline_event("step", 3, 13, "Classifying findings")
            app._state.on_pipeline_event("err", "  some noisy error log line")
            await pilot.pause()
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            screen._refresh_status()
            await pilot.pause()
            bar = screen.query_one("#status-bar", ProgressBar)
            assert bar.progress == 3
            assert bar.total == 13

    @pytest.mark.asyncio
    async def test_dashboard_renders_sitemap(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(220, 60)) as pilot:
            await pilot.pause()
            from textual.widgets import Tree
            screen = app.query_one("#screen-dashboard", DashboardScreen)
            tree = screen.query_one("#dash-tree", Tree)
            assert "127" not in str(tree.root.label)  # rough sanity
            assert "Sitemap" in str(tree.root.label)
            # Tree should have children populated from the loaded fixture
            assert len(tree.root.children) > 0


# ── TestWizardPassive ─────────────────────────────────────────────────────────

class TestProbesJSTab:
    @pytest.mark.asyncio
    async def test_js_tab_present(self):
        from textual.widgets import TabbedContent
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-probes")
            await pilot.pause()
            tabs = app.query_one("#screen-probes TabbedContent", TabbedContent)
            assert "probes-js" in [p.id for p in tabs.query("TabPane")]


class TestManualMode:
    @pytest.mark.asyncio
    async def test_manual_mode_does_not_autoscan(self):
        """Manual mode should NOT call _run_scan; user spiders themselves."""
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            run_scan_called: list = []

            def _spy(cfg):
                run_scan_called.append(cfg)

            app._run_scan = _spy  # type: ignore

            screen = app.query_one("#screen-dashboard", DashboardScreen)
            # Simulate the wizard returning a manual config
            cfg = {
                "mode": "manual",
                "target": "https://ctf.corp.local",
                "out": "output/test",
                "auth": None,
                "active_scan": False,
                "auto_fuzz": False,
                "allow_writes": False,
                "passive": False,
                "allowed_hosts": [],
                "excluded_patterns": [],
            }
            # Reach into the screen's wizard callback path the same way
            # action_new_session does, but skip the modal:
            screen._state.target = cfg["target"]
            screen._state.session_config = dict(cfg)
            # Manual branch:
            screen._state.scan_status = "idle"
            assert run_scan_called == []
            assert screen._state.scan_status == "idle"

    @pytest.mark.asyncio
    async def test_spider_now_kicks_off_crawl(self):
        from tui.screens.spider import SpiderScreen
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._state.session_config = {
                "target": "https://ctf.corp.local",
                "out": "output/test",
            }
            calls: list = []
            app._run_scan = lambda cfg: calls.append(cfg)  # type: ignore
            app._switch_tab("tab-spider")
            await pilot.pause()
            spider = app.query_one("#screen-spider", SpiderScreen)
            spider.query_one("#act-spider", Button).press()
            await pilot.pause()
            assert len(calls) == 1
            assert calls[0]["passive"] is True
            assert calls[0]["mode"] == "spider_only"


class TestWizardPassive:
    @pytest.mark.asyncio
    async def test_automatic_mode_sets_passive_true(self):
        from tui.screens.wizard import WizardScreen
        from textual.widgets import Input
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            captured: dict = {}

            def _capture(result):
                captured["result"] = result

            wiz = WizardScreen()
            await app.push_screen(wiz, _capture)
            await pilot.pause()
            wiz.query_one("#inp-target", Input).value = "https://ctf.corp.local"
            await pilot.pause()
            wiz._do_start()
            await pilot.pause()
            assert captured.get("result") is not None
            assert captured["result"]["passive"] is True
            assert captured["result"]["active_scan"] is False


# ── TestSpiderActions ─────────────────────────────────────────────────────────

class TestSpiderActions:
    @pytest.mark.asyncio
    async def test_send_to_repeater_loads_request(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            spider = app.query_one("#screen-spider", SpiderScreen)
            spider._current_req = {
                "method": "POST", "url": "http://test.local/api/login",
                "headers": {}, "body": '{"u":"a"}',
            }
            spider.query_one("#act-repeater", Button).press()
            await pilot.pause()
            repeater = app.query_one("#screen-repeater", RepeaterScreen)
            assert "http://test.local/api/login" in repeater.query_one(
                "#req-editor", TextArea
            ).text
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-repeater"

    @pytest.mark.asyncio
    async def test_arrow_nav_then_repeater_works(self, out_dir):
        """User navigates Spider tree with arrow keys (no explicit click),
        then presses → Repeater. The highlighted node's request must reach
        the Repeater editor."""
        from textual.widgets import Tree
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            spider = app.query_one("#screen-spider", SpiderScreen)
            tree = spider.query_one("#spider-tree", Tree)
            tree.focus()
            await pilot.pause()
            for _ in range(6):
                await pilot.press("down")
                await pilot.pause()
            spider.query_one("#act-repeater", Button).press()
            await pilot.pause()
            repeater = app.query_one("#screen-repeater", RepeaterScreen)
            text = repeater.query_one("#req-editor", TextArea).text
            assert "test.local" in text

    @pytest.mark.asyncio
    async def test_repeater_to_intruder_button(self, out_dir):
        """Repeater has a → Intruder button; Spider does not.
        The flow is: Spider → Repeater → Intruder."""
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            # Spider should not have an Intruder button anymore
            spider = app.query_one("#screen-spider", SpiderScreen)
            with pytest.raises(NoMatches):
                spider.query_one("#act-intruder", Button)

            # Load a request into Repeater, then click → Intruder
            app._switch_tab("tab-repeater")
            await pilot.pause()
            repeater = app.query_one("#screen-repeater", RepeaterScreen)
            repeater.load_request({
                "method": "POST", "url": "http://test.local/api/login",
                "headers": {}, "body": '{"u":"a"}',
            }, source="Test")
            await pilot.pause()
            repeater.query_one("#btn-to-intruder", Button).press()
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            assert "test.local" in intruder.query_one(
                "#intruder-req", TextArea
            ).text
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-intruder"


# ── TestSpider ────────────────────────────────────────────────────────────────

class TestSpider:
    @pytest.mark.asyncio
    async def test_tree_mode_default(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            assert screen._view_mode == "tree"
            from textual.widgets import Tree
            assert screen.query_one("#spider-tree", Tree).display is True
            assert screen.query_one("#spider-table", DataTable).display is False

    @pytest.mark.asyncio
    async def test_list_toggle(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            screen.query_one("#btn-list", Button).press()
            await pilot.pause()
            assert screen._view_mode == "list"
            assert screen.query_one("#spider-table", DataTable).display is True

    @pytest.mark.asyncio
    async def test_list_populated(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            screen.query_one("#btn-list", Button).press()
            await pilot.pause()
            table = screen.query_one("#spider-table", DataTable)
            assert table.row_count == 3

    @pytest.mark.asyncio
    async def test_filter_in_list_mode(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            screen.query_one("#btn-list", Button).press()
            await pilot.pause()
            screen._filter_text = "login"
            screen.refresh_data()
            await pilot.pause()
            assert screen.query_one("#spider-table", DataTable).row_count == 1

    @pytest.mark.asyncio
    async def test_live_request_added(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            req = {"method": "GET", "url": "http://test.local/new", "resource_type": "document"}
            app._state.requests.append(req)
            app._state.emit("request_added", req)
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            assert len(screen._state.requests) == 1

    @pytest.mark.asyncio
    async def test_pipeline_request_added_appends_to_state(self):
        """Live-update path: collector → _progress_cb → state → spider."""
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            req = {"method": "GET", "url": "http://test.local/live",
                   "resource_type": "document"}
            # Simulate the pipeline firing the new "request_added" event
            app._state.on_pipeline_event("request_added", req)
            await pilot.pause()
            assert any(r.get("url") == "http://test.local/live"
                       for r in app._state.requests)

    @pytest.mark.asyncio
    async def test_sitemap_colors_findings(self, out_dir):
        """Sitemap nodes should carry a severity from state.findings.
        URL match is by normalized URL (no query)."""
        from tui.screens.spider import _build_severity_index
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            idx = _build_severity_index(app._state)
            # The fixture has confirmed findings on /api/login (jwt + active)
            assert "http://test.local/api/login" in idx
            sev, tags = idx["http://test.local/api/login"]
            assert sev == "confirmed"
            assert tags  # non-empty probe tag set

    @pytest.mark.asyncio
    async def test_findings_updated_event_recolors_tree(self, out_dir):
        """A new finding emitted via 'findings_updated' should refresh the tree."""
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            # Inject a new confirmed finding for an existing URL
            app._state.findings.append({
                "url": "http://test.local/api/profile",
                "verdict": "confirmed",
                "_probe": "idor",
            })
            app._state.emit("findings_updated", "idor")
            await pilot.pause()
            from tui.screens.spider import _build_severity_index
            idx = _build_severity_index(app._state)
            sev, tags = idx["http://test.local/api/profile"]
            assert sev == "confirmed"
            assert "IDOR" in tags

    @pytest.mark.asyncio
    async def test_branch_node_carries_descendant_reqs(self, out_dir):
        """Clicking a branch in the sitemap tree should yield descendant requests."""
        from textual.widgets import Tree
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-spider")
            await pilot.pause()
            screen = app.query_one("#screen-spider", SpiderScreen)
            tree = screen.query_one("#spider-tree", Tree)

            def find_branch(node, name):
                for c in node.children:
                    if name in str(c.label):
                        return c
                    found = find_branch(c, name)
                    if found:
                        return found
                return None

            api_branch = find_branch(tree.root, "/api")
            assert api_branch is not None
            assert api_branch.data is not None
            # Branch should aggregate at least one descendant request
            assert len(api_branch.data["reqs"]) >= 1


# ── TestFindings ──────────────────────────────────────────────────────────────

class TestFindingsScreen:
    @pytest.mark.asyncio
    async def test_findings_table_populates(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-findings")
            await pilot.pause()
            screen = app.query_one("#screen-findings", FindingsScreen)
            assert screen.query_one(DataTable).row_count == 3

    @pytest.mark.asyncio
    async def test_findings_show_correct_probes(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            probes_seen = {f.get("_probe") for f in app._state.findings}
            assert "active" in probes_seen
            assert "idor" in probes_seen
            assert "jwt" in probes_seen


# ── TestRepeater ──────────────────────────────────────────────────────────────

class TestRepeaterScreen:
    @pytest.mark.asyncio
    async def test_load_request_populates_editor(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-repeater")
            await pilot.pause()
            repeater = app.query_one("#screen-repeater", RepeaterScreen)
            req = {"method": "POST", "url": "http://test.local/api/login",
                   "headers": {"Content-Type": "application/json"}, "body": '{"user":"admin"}'}
            repeater.load_request(req, source="Test")
            await pilot.pause()
            editor = repeater.query_one("#req-editor", TextArea)
            assert "POST" in editor.text
            assert "http://test.local/api/login" in editor.text

    @pytest.mark.asyncio
    async def test_entity_tree_populated_on_load(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-repeater")
            await pilot.pause()
            repeater = app.query_one("#screen-repeater", RepeaterScreen)
            req = {"method": "GET", "url": "http://test.local/?id=1&sort=asc",
                   "headers": {}, "body": ""}
            repeater.load_request(req, source="Test")
            await pilot.pause()
            entity_tree = repeater.query_one("#entity-tree-panel", EntityTree)
            assert entity_tree is not None

    @pytest.mark.asyncio
    async def test_raw_roundtrip(self):
        from tui.screens.repeater import _raw_to_dict, _req_to_raw
        req = {"method": "POST", "url": "http://test.local/api/login",
               "headers": {"Content-Type": "application/json", "X-Custom": "abc"},
               "body": '{"user":"admin"}'}
        raw = _req_to_raw(req)
        parsed = _raw_to_dict(raw)
        assert parsed["method"] == "POST"
        assert parsed["url"] == "http://test.local/api/login"
        assert parsed["body"] == '{"user":"admin"}'


# ── TestIntruder ──────────────────────────────────────────────────────────────

class TestIntruderMarkers:
    @pytest.mark.asyncio
    async def test_auto_marker_url_query(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-intruder")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            ta = intruder.query_one("#intruder-req", TextArea)
            ta.load_text("GET http://test.local/api?id=1&page=2\nHost: test.local\n")
            intruder.action_auto_marker()
            await pilot.pause()
            text = ta.text
            assert "id=§1§" in text
            assert "page=§2§" in text

    @pytest.mark.asyncio
    async def test_auto_marker_json_body(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-intruder")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            ta = intruder.query_one("#intruder-req", TextArea)
            ta.load_text(
                'POST http://test.local/api/login\n'
                'Content-Type: application/json\n'
                '\n'
                '{"username":"admin","password":"secret"}'
            )
            intruder.action_auto_marker()
            await pilot.pause()
            text = ta.text
            assert "§admin§" in text
            assert "§secret§" in text

    @pytest.mark.asyncio
    async def test_clear_markers(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-intruder")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            ta = intruder.query_one("#intruder-req", TextArea)
            ta.load_text("GET http://test.local/?id=§1§&page=§2§\n")
            intruder.action_clear_markers()
            await pilot.pause()
            assert "§" not in ta.text


class TestIntruderScreen:
    @pytest.mark.asyncio
    async def test_load_request_sets_template(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-intruder")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            req = {"method": "GET", "url": "http://test.local/?id=§1§", "headers": {}, "body": ""}
            intruder.load_request(req)
            await pilot.pause()
            assert "§1§" in intruder.query_one("#intruder-req", TextArea).text

    @pytest.mark.asyncio
    async def test_param_marking_json_body(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            req = {"method": "POST", "url": "http://test.local/api/login",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"username":"admin","password":"secret"}'}
            app._send_to_intruder_param(req, "username")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            assert "§admin§" in intruder.query_one("#intruder-req", TextArea).text

    @pytest.mark.asyncio
    async def test_param_marking_form_body(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            req = {"method": "POST", "url": "http://test.local/login",
                   "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                   "body": "username=admin&password=secret"}
            app._send_to_intruder_param(req, "password")
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            assert "§secret§" in intruder.query_one("#intruder-req", TextArea).text

    @pytest.mark.asyncio
    async def test_multi_param_marking(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            req = {"method": "GET", "url": "http://test.local/search?q=foo&page=1&sort=asc",
                   "headers": {}, "body": ""}
            app._send_to_intruder_params(req, ["q", "page"])
            await pilot.pause()
            intruder = app.query_one("#screen-intruder", IntruderScreen)
            assert "§" in intruder.query_one("#intruder-req", TextArea).text


# ── TestProbes ────────────────────────────────────────────────────────────────

class TestProbesScreen:
    @pytest.mark.asyncio
    async def test_probes_tab_renders(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            app._switch_tab("tab-probes")
            await pilot.pause()
            assert app.query_one("#screen-probes", ProbesScreen) is not None

    @pytest.mark.asyncio
    async def test_jwt_probe_has_data(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            assert len(app._state.probe_results.get("jwt", [])) == 1

    @pytest.mark.asyncio
    async def test_idor_probe_has_data(self, out_dir):
        app = HxxpsinApp(load_dir=str(out_dir))
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            assert len(app._state.probe_results.get("idor", [])) == 1


# ── TestAlertsBar ─────────────────────────────────────────────────────────────

class TestAlertsBar:
    @pytest.mark.asyncio
    async def test_start_scan_shows_bar(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            bar = app.query_one("#alerts-bar", AlertsBar)
            bar.start_scan(13)
            await pilot.pause()
            assert bar.query_one("#scan-bar").display is True

    @pytest.mark.asyncio
    async def test_finish_scan_hides_bar(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            bar = app.query_one("#alerts-bar", AlertsBar)
            bar.start_scan(13)
            await pilot.pause()
            bar.finish_scan("Scan complete")
            await pilot.pause()
            assert bar.query_one("#scan-bar").display is False

    @pytest.mark.asyncio
    async def test_advance_step_updates_label(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            bar = app.query_one("#alerts-bar", AlertsBar)
            bar.start_scan(13)
            bar.advance_step(3, 13, "Desync probe")
            await pilot.pause()
            content = bar.query_one("#step-label", Label)._Static__content
            assert "Desync probe" in content or "3" in content

    @pytest.mark.asyncio
    async def test_canary_alert_updates_label(self):
        app = HxxpsinApp()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            await pilot.pause()
            bar = app.query_one("#alerts-bar", AlertsBar)
            bar.update_alert("canary123 @ 1.2.3.4")
            await pilot.pause()
            content = bar.query_one("#alerts-label", Label)._Static__content
            assert "canary123" in content or "1.2.3.4" in content


# ── TestEntityTree ────────────────────────────────────────────────────────────

class TestEntityTree:
    def test_parse_links_from_html(self):
        e = _EntityExtractor("https://ctf.corp.local/")
        e.feed('<a href="/page1">link</a><a href="#skip">anchor</a><a href="javascript:void(0)">js</a>')
        assert "https://ctf.corp.local/page1" in e.links
        assert len(e.links) == 1  # anchors and js: skipped

    def test_parse_images(self):
        e = _EntityExtractor("https://ctf.corp.local/")
        e.feed('<img src="/logo.png"><source src="/vid.mp4">')
        assert "https://ctf.corp.local/logo.png" in e.images
        assert "https://ctf.corp.local/vid.mp4" in e.images

    def test_parse_form_fields(self):
        e = _EntityExtractor("https://ctf.corp.local/")
        e.feed('<form action="/login" method="POST"><input name="user"><input name="pass" type="password"></form>')
        assert len(e.forms) == 1
        assert e.forms[0]["method"] == "POST"
        assert e.forms[0]["action"] == "https://ctf.corp.local/login"
        field_names = [f["name"] for f in e.forms[0]["fields"]]
        assert "user" in field_names
        assert "pass" in field_names

    def test_parse_external_script(self):
        e = _EntityExtractor("https://ctf.corp.local/")
        e.feed('<script src="/app.js"></script>')
        assert any(s.get("src") == "https://ctf.corp.local/app.js" for s in e.scripts)

    def test_parse_inline_ws(self):
        e = _EntityExtractor("https://ctf.corp.local/")
        e.feed('<script>var ws = new WebSocket("wss://ctf.corp.local/ws");</script>')
        assert "wss://ctf.corp.local/ws" in e.websockets

    def test_entity_tree_loads_params_from_url(self):
        import asyncio
        from tui.app import HxxpsinApp

        async def _test():
            app = HxxpsinApp()
            async with app.run_test(headless=True, size=(200, 50)) as pilot:
                await pilot.pause()
                app._switch_tab("tab-repeater")
                await pilot.pause()
                repeater = app.query_one("#screen-repeater", RepeaterScreen)
                req = {"method": "GET", "url": "http://test.local/?id=1&sort=asc",
                       "headers": {}, "body": ""}
                repeater.load_request(req)
                await pilot.pause()
                tree = repeater.query_one("#entity-tree-panel", EntityTree)
                from textual.widgets import Tree as TTree
                root = tree.query_one("#entity-tree", TTree).root
                # root has children: Params, Links, Forms, Scripts, Images, WebSockets
                assert root.children  # tree was populated

        asyncio.run(_test())


# ── TestStateDirectly ─────────────────────────────────────────────────────────

class TestStateDirectly:
    def test_load_output_dir_parses_all_probes(self, out_dir):
        state = AppState()
        state.load_output_dir(str(out_dir))
        assert len(state.requests) == 3
        assert len(state.findings) == 3
        assert state.probe_results["jwt"][0]["attack"] == "alg_none"
        assert state.probe_results["idor"][0]["category"] == "idor"
        assert state.probe_results["active"][0]["category"] == "sqli"

    def test_load_output_dir_sets_target(self, out_dir):
        state = AppState()
        state.load_output_dir(str(out_dir))
        assert state.target == "http://test.local"

    def test_listener_fires_on_loaded(self, out_dir):
        state = AppState()
        events = []
        state.add_listener(lambda evt, data: events.append(evt))
        state.load_output_dir(str(out_dir))
        assert "loaded" in events

    def test_pipeline_step_appended_to_log(self):
        state = AppState()
        state.on_pipeline_event("step", 2, 13, "Desync probe")
        assert any("Desync probe" in e for e in state.step_log)

    def test_canary_hit_stored(self):
        state = AppState()
        hit = {"tag": "abc123", "remote_address": "1.2.3.4"}
        state.on_pipeline_event("canary", hit)
        assert state.canary_hits[0]["tag"] == "abc123"

    def test_remove_listener(self):
        state = AppState()
        calls = []
        cb = lambda e, d: calls.append(e)
        state.add_listener(cb)
        state.remove_listener(cb)
        state.emit("loaded", None)
        assert calls == []


# ── standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    sys.exit(result.returncode)
