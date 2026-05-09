"""Spider tab — sitemap tree + flat list with tree/list toggle."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Select, Static, Tree
from textual.widgets.tree import TreeNode

from ..state import AppState
from ..widgets.context_panel import ContextPanel
from ..widgets.request_viewer import RequestViewer

# reuse the message class from requests (avoids circular import)
class SendToRepeater(Message):
    def __init__(self, req: dict, source: str = "") -> None:
        super().__init__()
        self.req = req
        self.source = source


# ── entity helpers (ported from target.py) ───────────────────────────────────

_ENTITY_TAG: dict[str, str] = {
    "document":   "[HTML]",
    "script":     "[JS]",
    "stylesheet": "[CSS]",
    "xhr":        "[API]",
    "fetch":      "[API]",
    "image":      "[IMG]",
    "font":       "[FONT]",
    "media":      "[MEDIA]",
    "websocket":  "[WS]",
    "other":      "[?]",
}

_PROBE_BADGES = {
    "idor": "IDR",
    "jwt": "JWT",
    "active": "ACT",
    "nosql": "NSQ",
    "crlf": "CRL",
    "upload": "UPL",
    "dom_xss": "XSS",
    "desync": "DSY",
    "report": "RPT",
}


def _entity_tag(types: set[str]) -> str:
    clean = {t for t in types if t}
    if not clean or clean == {"document"}:
        return "[HTML]"
    if clean <= {"xhr", "fetch"}:
        return "[API]"
    if len(clean) == 1:
        t = next(iter(clean))
        return _ENTITY_TAG.get(t, f"[{t.upper()}]")
    priority = ["websocket", "script", "xhr", "fetch", "stylesheet", "image", "font", "media"]
    for p in priority:
        if p in clean:
            return _ENTITY_TAG.get(p, "[?]") + "…"
    return "[mixed]"


def _normalize_path(path: str) -> str:
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}",
        path,
        flags=re.IGNORECASE,
    )
    return path


def _param_hint(reqs: list[dict]) -> str:
    names: set[str] = set()
    for r in reqs[:3]:
        url = r.get("url", "")
        try:
            qs = urlparse(url).query
            if qs:
                names.update(list(parse_qs(qs, keep_blank_values=True))[:5])
        except Exception:
            pass
        body = r.get("body") or ""
        ct = next(
            (v for k, v in (r.get("headers") or {}).items() if k.lower() == "content-type"),
            "",
        )
        if body and "json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    names.update(list(obj)[:5])
            except Exception:
                pass
        elif body:
            try:
                names.update(list(parse_qs(body, keep_blank_values=True))[:5])
            except Exception:
                pass
    if not names:
        return ""
    return "  [" + ",".join(sorted(names)[:5]) + "]"


# ── severity coloring ────────────────────────────────────────────────────────

# Higher = worse. Used to compare/escalate severities up the tree.
_SEV_RANK = {"none": 0, "info": 1, "likely": 2, "confirmed": 3}

# Verdict / heuristic strings → severity bucket.
_VERDICT_TO_SEV = {
    "confirmed": "confirmed",
    "exploitable": "confirmed",
    "high": "confirmed",
    "critical": "confirmed",
    "likely": "likely",
    "medium": "likely",
    "potential": "likely",
    "low": "info",
    "info": "info",
    "informational": "info",
}

_SEV_COLOR = {
    "confirmed": "red",
    "likely": "yellow",
    "info": "cyan",
}


def _normalize_url(url: str) -> str:
    """Strip query / fragment so finding URLs match site-map URLs even when
    only one carries query params."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        return url


def _build_severity_index(state: AppState) -> dict[str, tuple[str, set[str]]]:
    """Walk state.findings + canary hits and build {url → (worst_sev, {probe_tags})}.

    URLs are normalized (no query/fragment) so e.g.
    `/api/users?id=1` and `/api/users` map to the same key.
    """
    idx: dict[str, tuple[str, set[str]]] = {}

    def _bump(url: str, sev: str, tag: str) -> None:
        if not url:
            return
        key = _normalize_url(url)
        cur_sev, cur_tags = idx.get(key, ("none", set()))
        if _SEV_RANK[sev] > _SEV_RANK[cur_sev]:
            cur_sev = sev
        cur_tags.add(tag)
        idx[key] = (cur_sev, cur_tags)

    for f in state.findings:
        if not isinstance(f, dict):
            continue
        url = f.get("url") or f.get("endpoint") or f.get("probe_url") or ""
        verdict = (f.get("verdict") or f.get("severity") or "").lower()
        sev = _VERDICT_TO_SEV.get(verdict)
        if not sev:
            # No explicit verdict — treat the presence of a probe finding as info
            sev = "info"
        probe = (f.get("_probe") or f.get("probe") or "?").upper()[:6]
        _bump(url, sev, probe)

    # DNS canary hits — high signal, attach to whatever URL triggered them
    for hit in state.canary_hits or []:
        if not isinstance(hit, dict):
            continue
        url = hit.get("url") or ""
        _bump(url, "confirmed", "DNS")

    return idx


def _worst_severity(reqs: list[dict],
                    sev_index: dict[str, tuple[str, set[str]]]
                    ) -> tuple[str, set[str]]:
    """Worst severity across all of a node's descendant requests."""
    worst = "none"
    tags: set[str] = set()
    for r in reqs:
        url = _normalize_url(r.get("url", ""))
        entry = sev_index.get(url)
        if not entry:
            continue
        sev, t = entry
        if _SEV_RANK[sev] > _SEV_RANK[worst]:
            worst = sev
        tags |= t
    return worst, tags


def _build_site_map(requests: list[dict]) -> dict:
    tree: dict = {}
    for req in requests:
        url = req.get("url", "")
        resource_type = req.get("resource_type", "document")
        try:
            p = urlparse(url)
            host = p.netloc or "unknown"
            path = p.path or "/"
            segments = [s for s in path.split("/") if s]
        except Exception:
            continue
        node = tree.setdefault(host, {})
        for seg in segments:
            node = node.setdefault(seg, {})
        node.setdefault("__requests__", []).append(req)
        node.setdefault("__types__", set()).add(resource_type)
    return tree


def _aggregate_subtree(node: dict) -> tuple[list[dict], set[str]]:
    """Walk a site-map subtree and collect every descendant's __requests__/__types__.
    Lets branch nodes show a representative request when clicked."""
    reqs = list(node.get("__requests__", []))
    types: set[str] = set(node.get("__types__", set()))
    for k, v in node.items():
        if k.startswith("__") or not isinstance(v, dict):
            continue
        sub_reqs, sub_types = _aggregate_subtree(v)
        reqs.extend(sub_reqs)
        types |= sub_types
    return reqs, types


def _populate_tree(
    tree_widget: Tree,
    data: dict,
    parent: TreeNode | None = None,
    path_prefix: str = "",
    sev_index: dict[str, tuple[str, set[str]]] | None = None,
) -> None:
    root = parent if parent else tree_widget.root
    sev_index = sev_index or {}
    for key, value in sorted(data.items()):
        if key.startswith("__"):
            continue
        seg = f"/{key}" if path_prefix else key
        full_path = path_prefix + "/" + key if path_prefix else key
        own_reqs: list[dict] = value.get("__requests__", [])
        own_types: set[str] = value.get("__types__", set())

        # Aggregate descendant requests so branch nodes are selectable.
        all_reqs, all_types = _aggregate_subtree(value)

        if own_reqs:
            # Leaf-ish: this URL was hit directly. Show its own counts.
            methods = sorted(set(r.get("method", "?") for r in own_reqs))
            params = _param_hint(own_reqs)
            tag = _entity_tag(own_types)
            base = f"{seg}  {tag}  [{','.join(methods)}]({len(own_reqs)}){params}"
        elif all_reqs:
            # Pure branch: roll up descendant count for visibility.
            base = f"{seg}  ({len(all_reqs)})"
        else:
            base = seg

        # Severity = worst across all descendants (so a folder lights up red
        # if any URL inside it has a confirmed finding).
        sev, probe_tags = _worst_severity(all_reqs, sev_index)
        if sev != "none":
            color = _SEV_COLOR[sev]
            marker = "⚠" if sev == "confirmed" else ("△" if sev == "likely" else "·")
            badge = f" {marker} {','.join(sorted(probe_tags))}" if probe_tags else f" {marker}"
            # Escape '[' in `base` so Textual markup doesn't try to parse the
            # method tags ([GET], [POST]) as markup.
            safe = base.replace("[", "\\[")
            label: str = f"[{color}]{safe}{badge}[/{color}]"
        else:
            label = base

        # Carry the aggregated request list as data so clicking a branch always
        # populates the right-hand panel with the first descendant's request.
        child = root.add(
            label,
            data={"path": full_path, "reqs": all_reqs, "types": all_types,
                  "severity": sev, "probe_tags": probe_tags},
        )
        sub = {k: v for k, v in value.items() if not k.startswith("__")}
        if sub:
            _populate_tree(tree_widget, sub, child, full_path, sev_index)


# ── main screen ───────────────────────────────────────────────────────────────

class SpiderScreen(Vertical):
    """Sitemap viewer: tree (default) and flat list toggle."""

    BINDINGS = [
        Binding("r", "send_to_repeater", "→ Repeater"),
        Binding("t", "toggle_view", "Toggle Tree/List"),
        Binding("/", "focus_filter", "Filter"),
        Binding("e", "enrich", "Enrich"),
    ]

    DEFAULT_CSS = """
    SpiderScreen {
        height: 1fr;
    }
    SpiderScreen #filter-bar {
        height: 3;
        background: $surface-darken-1;
        border-bottom: solid $primary-darken-2;
        padding: 0 1;
    }
    SpiderScreen #filter-bar Label {
        width: auto;
        content-align: left middle;
        padding-right: 1;
    }
    SpiderScreen #spider-filter {
        width: 1fr;
    }
    SpiderScreen #btn-tree {
        min-width: 8;
        margin-left: 1;
    }
    SpiderScreen #btn-list {
        min-width: 8;
    }
    SpiderScreen #spider-count {
        width: auto;
        content-align: right middle;
        color: $text-muted;
        padding: 0 1;
    }
    SpiderScreen #spider-body {
        height: 1fr;
    }
    SpiderScreen #left-panel {
        width: 55%;
        border-right: solid $primary;
    }
    SpiderScreen Tree {
        height: 1fr;
    }
    SpiderScreen DataTable {
        height: 1fr;
    }
    SpiderScreen #right-panel {
        width: 45%;
    }
    SpiderScreen #right-panel .panel-title {
        background: $primary-darken-2;
        padding: 0 1;
        height: 1;
    }
    SpiderScreen RequestViewer {
        height: 1fr;
    }
    SpiderScreen ContextPanel {
        height: 14;
        border-top: solid $primary;
    }
    SpiderScreen #action-bar {
        height: 3;
        background: $surface-darken-1;
        border-top: solid $primary;
        padding: 0 1;
    }
    SpiderScreen #action-bar Button {
        min-width: 12;
        margin-right: 1;
    }
    SpiderScreen #action-bar #probe-select {
        width: 16;
    }
    """

    _PROBE_KEYS = [
        "crlf", "jwt", "idor", "desync", "nosql",
        "upload", "dom_xss", "active", "js", "fingerprint",
    ]

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._view_mode = "tree"
        self._filter_text = ""
        self._current_req: dict | None = None
        self._req_list: list[dict] = []  # current flat list (filtered)
        # register for live updates
        self._state.add_listener(self._on_state_event)

    def compose(self) -> ComposeResult:
        with Horizontal(id="filter-bar"):
            yield Label("Filter:")
            yield Input(placeholder="url / method / status / type", id="spider-filter")
            yield Button("Tree", id="btn-tree", variant="primary")
            yield Button("List", id="btn-list", variant="default")
            yield Label("", id="spider-count")

        with Horizontal(id="spider-body"):
            with Vertical(id="left-panel"):
                yield Tree("Sitemap", id="spider-tree")
                yield DataTable(id="spider-table", cursor_type="row", zebra_stripes=True)

            with Vertical(id="right-panel"):
                yield Static("Request / Response", classes="panel-title")
                yield RequestViewer(id="spider-req-viewer")
                yield Static("Context", classes="panel-title")
                yield ContextPanel(self._state, id="spider-context")

        with Horizontal(id="action-bar"):
            yield Button("Spider Now", id="act-spider", variant="success")
            yield Button("→ Repeater", id="act-repeater", variant="primary")
            yield Select(
                [(p.upper(), p) for p in self._PROBE_KEYS],
                id="probe-select",
                prompt="Run Probe",
            )
            yield Button("Enrich", id="act-enrich", variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#spider-table", DataTable)
        table.add_columns("#", "Method", "URL", "St", "Type", "Badges")
        # hide list view initially
        self.query_one("#spider-table").display = False
        self.refresh_data()

    # ── filter ────────────────────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "spider-filter":
            self._filter_text = event.value.strip().lower()
            self.refresh_data()

    def _matches(self, req: dict) -> bool:
        ft = self._filter_text
        if not ft:
            return True
        resp = req.get("response") or {}
        return (
            ft in req.get("url", "").lower()
            or ft in req.get("method", "").lower()
            or ft in str(resp.get("status", ""))
            or ft in req.get("resource_type", "").lower()
        )

    # ── toggle view ──────────────────────────────────────────────────────────

    def action_toggle_view(self) -> None:
        self._view_mode = "list" if self._view_mode == "tree" else "tree"
        self._apply_view_mode()
        self.refresh_data()

    def _apply_view_mode(self) -> None:
        is_tree = self._view_mode == "tree"
        self.query_one("#spider-tree").display = is_tree
        self.query_one("#spider-table").display = not is_tree
        self.query_one("#btn-tree", Button).variant = "primary" if is_tree else "default"
        self.query_one("#btn-list", Button).variant = "default" if is_tree else "primary"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn-tree":
            self._view_mode = "tree"
            self._apply_view_mode()
            self.refresh_data()
            return
        if btn == "btn-list":
            self._view_mode = "list"
            self._apply_view_mode()
            self.refresh_data()
            return

        if btn == "act-spider":
            self._kick_off_spider()
            return

        req = self._resolve_current_req()
        if btn == "act-repeater":
            if req:
                self.post_message(SendToRepeater(req, source="Spider"))
            else:
                self.app.notify("Select a request first", severity="warning")
        elif btn == "act-enrich":
            self.app._switch_tab("tab-enrichment")

    def _kick_off_spider(self) -> None:
        """Start a crawl-only run. Used by manual sessions to populate the
        sitemap without auto-running probes."""
        cfg = dict(self._state.session_config or {})
        target = cfg.get("target") or self._state.target
        if not target:
            self.app.notify(
                "No target — start a session from Dashboard first",
                severity="warning",
            )
            return
        if self._state.scan_status == "running":
            self.app.notify("A scan is already running", severity="warning")
            return

        # Force discovery-only — no active probes — even if Manual mode left
        # active_scan/auto_fuzz toggled on. The user can run probes one-by-one
        # afterwards via the Probe dropdown / Repeater.
        cfg["target"] = target
        cfg["passive"] = True
        cfg["active_scan"] = False
        cfg["auto_fuzz"] = False
        cfg["mode"] = "spider_only"
        if not cfg.get("out"):
            from datetime import datetime
            cfg["out"] = f"output/{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self._state.scan_status = "running"
        self._state.session_config = cfg
        self.app.notify(f"Spidering {target} …", timeout=4)
        self.app._run_scan(cfg)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "probe-select":
            return
        val = event.value
        if not val or not isinstance(val, str) or val not in self._PROBE_KEYS:
            return
        req = self._resolve_current_req()
        if req:
            self.app._run_probe_on_request(val, req)
            self.app.notify(f"Running {val.upper()} on {req.get('url', '')[:50]}", timeout=4)
        else:
            self.app.notify("Select a request first", severity="warning")

    # ── tree mode ─────────────────────────────────────────────────────────────

    def _build_tree(self) -> None:
        tree = self.query_one("#spider-tree", Tree)
        tree.clear()
        reqs = [r for r in self._state.requests if self._matches(r)]

        # Also add JS-discovered routes (as ghost nodes)
        js_routes = self._state.js_discovered_routes or []

        if not reqs and not js_routes:
            tree.root.set_label("Sitemap  (no requests yet — run a scan or import)")
            self._update_count(0)
            return

        # Build severity index once per render so every node gets colored
        # in a single pass. Cheap: just a dict lookup per request.
        sev_index = _build_severity_index(self._state)

        # Top-level summary: how many findings touch the current request set.
        n_confirmed = sum(1 for url, (s, _) in sev_index.items()
                          if s == "confirmed")
        n_likely = sum(1 for url, (s, _) in sev_index.items()
                       if s == "likely")
        sev_summary = ""
        if n_confirmed or n_likely:
            sev_summary = f"  [red]{n_confirmed}⚠[/red] [yellow]{n_likely}△[/yellow]"
        tree.root.set_label(f"Sitemap  ({len(reqs)} requests){sev_summary}")

        site_map = _build_site_map(reqs)
        _populate_tree(tree, site_map, sev_index=sev_index)

        # Add JS-discovered routes under a dedicated branch
        if js_routes:
            js_branch = tree.root.add(f"[JS routes]  ({len(js_routes)} discovered)", data=None)
            for route in js_routes:
                path = route if isinstance(route, str) else str(route)
                js_branch.add_leaf(path, data={"path": path, "reqs": [], "types": {"script"}})
            js_branch.expand()

        tree.root.expand()
        self._update_count(len(reqs))

    def _resolve_current_req(self) -> dict | None:
        """Return _current_req, falling back to the cursor in tree/list mode.
        This guards against the case where the user navigated with arrow keys
        but the selection event never fired before they pressed an action."""
        if self._current_req:
            return self._current_req
        if self._view_mode == "tree":
            try:
                tree = self.query_one("#spider-tree", Tree)
                node = tree.cursor_node
                if node and node.data:
                    reqs = node.data.get("reqs") or []
                    if reqs:
                        return reqs[0]
            except Exception:
                pass
        else:
            try:
                table = self.query_one("#spider-table", DataTable)
                idx = table.cursor_row
                if 0 <= idx < len(self._req_list):
                    return self._req_list[idx]
            except Exception:
                pass
        return None

    def _select_tree_node(self, node) -> None:
        data = node.data
        if not data:
            return
        reqs: list[dict] = data.get("reqs", [])
        if reqs:
            req = reqs[0]
            self._current_req = req
            try:
                self.query_one("#spider-req-viewer", RequestViewer).show_request(req)
                self.query_one("#spider-context", ContextPanel).update_entity(req)
            except Exception:
                pass

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        self._select_tree_node(event.node)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        # Arrow-key navigation should also update _current_req so pressing 'r'
        # or clicking → Repeater immediately works on the highlighted node.
        self._select_tree_node(event.node)

    # ── list mode ─────────────────────────────────────────────────────────────

    def _build_list(self) -> None:
        table = self.query_one("#spider-table", DataTable)
        table.clear()
        self._req_list = [r for r in self._state.requests if self._matches(r)]

        if not self._req_list:
            table.add_row("—", "No requests match", "", "", "", "")
            self._update_count(0)
            return

        for i, req in enumerate(self._req_list):
            resp = req.get("response") or {}
            status = req.get("response_status") or resp.get("status", "")
            url = req.get("url", "")
            display_url = ("…" + url[-87:]) if len(url) > 90 else url
            badge = self._badge_for_req(req)
            table.add_row(
                str(i + 1),
                req.get("method", ""),
                display_url,
                str(status),
                req.get("resource_type", ""),
                badge,
            )
        self._update_count(len(self._req_list))

    def _badge_for_req(self, req: dict) -> str:
        url = req.get("url", "")
        badges = []
        for probe, tag in _PROBE_BADGES.items():
            results = self._state.probe_results.get(probe, [])
            if any(r.get("url", "") == url or r.get("endpoint", "") == url for r in results):
                badges.append(tag)
        return " ".join(badges)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._req_list):
            req = self._req_list[idx]
            self._current_req = req
            self.query_one("#spider-req-viewer", RequestViewer).show_request(req)
            self.query_one("#spider-context", ContextPanel).update_entity(req)

    # ── live updates ─────────────────────────────────────────────────────────

    def _on_state_event(self, event: str, data=None) -> None:
        if event in ("loaded", "requests_updated", "findings_updated"):
            self.app.call_from_thread(self.refresh_data)
        elif event == "request_added" and isinstance(data, dict):
            self.app.call_from_thread(self._add_live_request, data)

    def _add_live_request(self, req: dict) -> None:
        if not self._matches(req):
            return
        if self._view_mode == "list":
            self._req_list.append(req)
            resp = req.get("response") or {}
            status = req.get("response_status") or resp.get("status", "")
            url = req.get("url", "")
            display_url = ("…" + url[-87:]) if len(url) > 90 else url
            table = self.query_one("#spider-table", DataTable)
            table.add_row(
                str(len(self._req_list)),
                req.get("method", ""),
                display_url,
                str(status),
                req.get("resource_type", ""),
                "",
            )
        else:
            # for tree mode, just rebuild (it's fast enough for incremental adds)
            self._build_tree()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _update_count(self, n: int) -> None:
        total = len(self._state.requests)
        try:
            label = self.query_one("#spider-count", Label)
            if self._filter_text:
                label.update(f"{n}/{total}")
            else:
                label.update(str(total))
        except Exception:
            pass

    # ── actions ───────────────────────────────────────────────────────────────

    def action_send_to_repeater(self) -> None:
        req = self._resolve_current_req()
        if req:
            self.post_message(SendToRepeater(req, source="Spider"))
        else:
            self.app.notify("Select a request first", severity="warning")

    def action_focus_filter(self) -> None:
        self.query_one("#spider-filter", Input).focus()

    def action_enrich(self) -> None:
        self.app._switch_tab("tab-enrichment")

    # ── public ───────────────────────────────────────────────────────────────

    def refresh_data(self) -> None:
        if self._view_mode == "tree":
            self._build_tree()
        else:
            self._build_list()
