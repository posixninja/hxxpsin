"""Target tab — site map tree, scope, fingerprint, and crawl controls."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.message import Message
from textual.widgets import (
    Button, Checkbox, Input, Label, ListItem, ListView, Static,
    TabbedContent, TabPane, TextArea, Tree,
)
from textual.widgets.tree import TreeNode

from ..state import AppState
from ..widgets.context_panel import ContextPanel


class LaunchNewTarget(Message):
    """Posted when the user confirms a new-target form submission."""
    def __init__(self, config: dict) -> None:
        super().__init__()
        self.config = config


class ScanTarget(Message):
    """Posted when the user clicks a scan-action button in the Target tab."""
    def __init__(self, action: str, url: str) -> None:
        super().__init__()
        self.action = action   # "fingerprint" | "spider"
        self.url = url


# Entity type tags — shown on every tree node and in the Selection panel
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

# Available actions per entity type — shown in the tree node label
_ENTITY_ACTIONS: dict[str, str] = {
    "document":   "Repeater · probe suggestions",
    "script":     "JS Analysis",
    "stylesheet": "—",
    "xhr":        "Repeater · Intruder · probes",
    "fetch":      "Repeater · Intruder · probes",
    "image":      "Fingerprint",
    "font":       "—",
    "media":      "—",
    "websocket":  "WebSocket probe",
    "other":      "Repeater",
}

# Human-readable entity type label for the Selection panel header
_TYPE_LABEL: dict[str, str] = {
    "document":   "HTML page",
    "script":     "JavaScript file",
    "stylesheet": "CSS stylesheet",
    "xhr":        "API endpoint",
    "fetch":      "API endpoint",
    "image":      "Image asset",
    "font":       "Font asset",
    "media":      "Media file",
    "websocket":  "WebSocket endpoint",
    "other":      "Resource",
}


def _entity_tag(types: set[str]) -> str:
    """Return the entity type tag for a node, always including document types."""
    clean = {t for t in types if t}
    if not clean or clean == {"document"}:
        return "[HTML]"
    if clean <= {"xhr", "fetch"}:
        return "[API]"
    if len(clean) == 1:
        t = next(iter(clean))
        return _ENTITY_TAG.get(t, f"[{t.upper()}]")
    # mixed — pick the most interesting non-document type
    priority = ["websocket", "script", "xhr", "fetch", "stylesheet", "image", "font", "media"]
    for p in priority:
        if p in clean:
            return _ENTITY_TAG.get(p, "[?]") + "…"
    return "[mixed]"


def _actions_hint(types: set[str], has_params: bool) -> str:
    """Return a compact actions hint for tree node labels."""
    clean = {t for t in types if t}
    if not clean or clean == {"document"}:
        return "Repeater" + (" · Intruder" if has_params else "")
    if clean <= {"xhr", "fetch"}:
        return "Repeater" + (" · Intruder" if has_params else "")
    if "websocket" in clean:
        return "WS probe"
    if "script" in clean:
        return "JS analysis"
    if clean <= {"image", "media"}:
        return "Repeater · IDOR?"
    if "stylesheet" in clean:
        return "Repeater (sourcemap)"
    if "font" in clean:
        return "Repeater"
    if clean <= {"image", "font", "media", "stylesheet"}:
        return "Repeater"
    return "Repeater"


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


def _normalize_path(path: str) -> str:
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}", path,
    )
    return path


def _build_normalized_endpoints(requests: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group requests by (host, normalized_path) pattern."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for req in requests:
        url = req.get("url", "")
        try:
            p = urlparse(url)
            host = p.netloc or "unknown"
            pattern = _normalize_path(p.path or "/")
            groups[(host, pattern)].append(req)
        except Exception:
            pass
    return dict(groups)


def _param_hint(reqs: list[dict]) -> str:
    """Return a short hint like '  [q,id]' listing GET/POST param names found."""
    names: set[str] = set()
    for r in reqs[:3]:
        url = r.get("url", "")
        try:
            qs = urlparse(url).query
            if qs:
                from urllib.parse import parse_qs as _pqs
                names.update(list(_pqs(qs, keep_blank_values=True))[:5])
        except Exception:
            pass
        body = r.get("body") or ""
        ct = next((v for k, v in (r.get("headers") or {}).items() if k.lower() == "content-type"), "")
        if body and "json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    names.update(list(obj)[:5])
            except Exception:
                pass
        elif body:
            try:
                from urllib.parse import parse_qs as _pqs2
                names.update(list(_pqs2(body, keep_blank_values=True))[:5])
            except Exception:
                pass
    if not names:
        return ""
    return "  [" + ",".join(sorted(names)[:5]) + "]"


def _populate_tree(
    tree_widget: Tree,
    data: dict,
    parent: TreeNode | None = None,
    path_prefix: str = "",
) -> None:
    root = parent if parent else tree_widget.root
    for key, value in sorted(data.items()):
        if key.startswith("__"):
            continue
        seg = f"/{key}"
        full_path = path_prefix + seg
        reqs = value.get("__requests__", [])
        types: set[str] = value.get("__types__", set())
        if reqs:
            methods  = sorted(set(r.get("method", "?") for r in reqs))
            params   = _param_hint(reqs)
            tag      = _entity_tag(types)
            actions  = _actions_hint(types, bool(params))
            label    = f"{seg}  {tag}  [{','.join(methods)}]({len(reqs)}){params}  ·  {actions}"
        else:
            label = seg
        child = root.add(label, expand=False, data=full_path)
        sub = {k: v for k, v in value.items() if not k.startswith("__")}
        if sub:
            _populate_tree(tree_widget, sub, child, full_path)


class TargetScreen(Vertical):
    """Target tab: site map, scope editor, fingerprint, new-target launcher."""

    DEFAULT_CSS = """
    TargetScreen {
        layout: horizontal;
        height: 1fr;
    }
    TargetScreen #sitemap-panel {
        width: 40%;
        border-right: solid $primary;
    }
    TargetScreen #detail-panel {
        width: 60%;
    }
    TargetScreen .panel-title {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
    }
    TargetScreen #target-list {
        height: auto;
        max-height: 8;
        border-bottom: solid $primary;
    }
    TargetScreen #scan-action-bar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
        border-bottom: solid $primary-darken-2;
    }
    TargetScreen #scan-action-bar Button {
        min-width: 14;
        margin-right: 1;
    }
    TargetScreen #fp-strip {
        height: 1;
        padding: 0 1;
        color: $text-muted;
        background: $surface-darken-1;
    }
    TargetScreen Tree {
        height: 1fr;
    }
    TargetScreen TextArea {
        height: 1fr;
        border: none;
    }
    TargetScreen .scope-label {
        color: $text-muted;
        margin: 0 0 1 0;
    }
    TargetScreen Button {
        margin-top: 1;
    }
    TargetScreen #sel-summary {
        height: auto;
        padding: 1;
        background: $surface-darken-1;
        border-bottom: solid $primary;
    }
    TargetScreen #sel-type {
        color: $warning;
        height: 1;
    }
    TargetScreen #sel-url {
        color: $text-muted;
        height: 1;
    }
    TargetScreen #sel-status {
        color: $text-muted;
        height: 1;
    }
    TargetScreen #sel-context {
        height: 1fr;
    }
    TargetScreen #sel-js {
        height: auto;
        max-height: 20;
        border-top: solid $primary;
        background: $surface-darken-1;
        padding: 0 1 1 1;
        overflow-y: auto;
    }
    TargetScreen .js-section-header {
        color: $warning;
        margin-top: 1;
        height: 1;
    }
    TargetScreen .js-item {
        color: $text-muted;
        height: 1;
        padding-left: 2;
    }
    TargetScreen .js-secret { color: $error; }
    TargetScreen .js-xss    { color: $error; }
    TargetScreen .js-auth   { color: $warning; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._tree_node_map:  dict[str, TreeNode]   = {}
        self._tree_methods:   dict[str, set[str]]   = {}
        self._tree_counts:    dict[str, int]         = {}
        self._tree_types:     dict[str, set[str]]   = {}
        self._tree_reqs:      dict[str, list[dict]] = {}  # sample reqs per node for param hints

    def compose(self) -> ComposeResult:
        with Vertical(id="sitemap-panel"):
            yield Static("Targets", classes="panel-title")
            yield ListView(id="target-list")
            with Horizontal(id="scan-action-bar"):
                yield Button("Fingerprint", id="btn-scan-fingerprint", variant="primary")
                yield Button("Spider", id="btn-scan-spider", variant="default")
            yield Static("Site Map", classes="panel-title")
            yield Static("", id="fp-strip")
            yield Tree("Target", id="sitemap-tree")

        with Vertical(id="detail-panel"):
            with TabbedContent(id="detail-tabs"):
                with TabPane("Selection", id="tab-selection"):
                    with Vertical(id="sel-summary"):
                        yield Static("Select any node in the site map", id="sel-type")
                        yield Static("", id="sel-url")
                        yield Static("", id="sel-status")
                    yield ContextPanel(self._state, id="sel-context")
                    yield ScrollableContainer(id="sel-js")

                with TabPane("Scope", id="tab-scope"):
                    yield Static(
                        "In-scope hosts (one per line):",
                        classes="scope-label",
                    )
                    yield TextArea(
                        "\n".join(self._state.allowed_hosts),
                        id="allowed-hosts-input",
                    )
                    yield Static(
                        "Excluded URL patterns (regex, one per line):",
                        classes="scope-label",
                    )
                    yield TextArea(
                        "\n".join(self._state.excluded_patterns),
                        id="excluded-patterns-input",
                    )
                    yield Button("Apply Scope", id="btn-apply-scope", variant="primary")

                with TabPane("Fingerprint", id="tab-fp"):
                    yield TextArea("", id="fp-text", read_only=True)

                with TabPane("Load / Crawl", id="tab-crawl"):
                    with ScrollableContainer(id="crawl-scroll"):
                        yield Static("Load existing output dir:", classes="scope-label")
                        yield Input(
                            value=self._state.out_dir or "",
                            placeholder="output/my-scan-dir",
                            id="load-dir-input",
                        )
                        yield Button("Load Output Dir", id="btn-load-dir", variant="default")
                        yield Static("── New target ──", classes="panel-title")
                        yield Static("Target URL", classes="scope-label")
                        yield Input(
                            value=self._state.target or "",
                            placeholder="https://target.com",
                            id="new-target-url",
                        )
                        yield Static("In-scope hosts (comma-separated)", classes="scope-label")
                        yield Input(
                            value=", ".join(self._state.allowed_hosts),
                            placeholder="api.target.com, cdn.target.com",
                            id="new-allowed-hosts",
                        )
                        yield Static("Excluded patterns (regex, comma-separated)", classes="scope-label")
                        yield Input(
                            value=", ".join(self._state.excluded_patterns),
                            placeholder=r"/logout, /static/, \.png$",
                            id="new-excluded-pats",
                        )
                        yield Static("Output directory (blank = auto)", classes="scope-label")
                        yield Input(
                            placeholder="output/my-scan",
                            id="new-out-dir",
                        )
                        yield Static("Auth state file (blank = auto)", classes="scope-label")
                        yield Input(placeholder="auth.json", id="new-auth")
                        yield Checkbox("Active scan", id="chk-new-active", value=False)
                        yield Checkbox("Auto-fuzz", id="chk-new-autofuzz", value=False)
                        yield Checkbox("Quick mode (no browser crawl)", id="chk-new-quick", value=False)
                        yield Checkbox("Allow writes (PUT/DELETE)", id="chk-new-writes", value=False)
                        with Horizontal(id="crawl-btns"):
                            yield Button("Add to List", id="btn-add-target", variant="primary")
                            yield Button("Add + Fingerprint", id="btn-launch-target", variant="success")
                    yield Static("", id="crawl-status")

    def on_mount(self) -> None:
        self._refresh_target_list()
        self._refresh_tree()
        self._refresh_fingerprint()

    # ── target list ───────────────────────────────────────────────────────

    def _refresh_target_list(self) -> None:
        lv = self.query_one("#target-list", ListView)
        lv.clear()
        for t in self._state.targets:
            url = t.get("target", "")
            extra = f"  +{len(t.get('allowed_hosts', []))} hosts" if t.get("allowed_hosts") else ""
            lv.append(ListItem(Label(f"{url}{extra}")))
        if not self._state.targets:
            lv.append(ListItem(Label("(no targets — press Ctrl+N to add one)")))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._state.targets):
            config = self._state.targets[idx]
            self._state.target = config["target"]
            self._state.allowed_hosts = config.get("allowed_hosts", [])
            self._state.excluded_patterns = config.get("excluded_patterns", [])
            out = config.get("out", "")
            if out and Path(out).is_dir():
                self._state.load_output_dir(out)
                self.app._refresh_all()
                self.app.notify(f"Switched to: {config['target']}")
            else:
                self.app.notify(f"Selected: {config['target']} (no scan output yet)")

    # ── site map tree ─────────────────────────────────────────────────────

    def _tech_strip(self) -> str:
        fp = self._state.stackprint
        if not fp:
            return ""
        detected = fp.get("detected", {})
        parts: list[str] = []
        for cat in ("server", "framework", "language", "database"):
            vals = detected.get(cat, [])
            if vals:
                parts.extend(str(v) for v in vals[:2])
        return "  ·  ".join(parts[:6]) if parts else ""

    def _reset_tree_state(self) -> None:
        self._tree_node_map.clear()
        self._tree_methods.clear()
        self._tree_counts.clear()
        self._tree_types.clear()
        self._tree_reqs.clear()

    def _refresh_tree(self) -> None:
        tree = self.query_one("#sitemap-tree", Tree)
        tree.clear()
        self._reset_tree_state()
        try:
            self.query_one("#fp-strip", Static).update(self._tech_strip())
        except Exception:
            pass
        if not self._state.requests:
            tree.root.add_leaf("(no requests — load an output dir or run Spider)")
            return

        site_map = _build_site_map(self._state.requests)
        _populate_tree(tree, site_map)

        # JS-discovered routes not already crawled
        discovered = self._state.js_discovered_routes
        if discovered:
            crawled_paths = {urlparse(r.get("url", "")).path for r in self._state.requests}
            uncrawled = [r for r in discovered if r not in crawled_paths]
            if uncrawled:
                disc_node = tree.root.add(
                    f"[JS Discovered]  ({len(uncrawled)} routes)", expand=False
                )
                for route in sorted(uncrawled)[:100]:
                    disc_node.add_leaf(route, data=route)

        # Normalized endpoint patterns section
        endpoints = _build_normalized_endpoints(self._state.requests)
        if endpoints:
            ep_root = tree.root.add(
                f"─── Endpoints  ({len(endpoints)} patterns) ───",
                expand=False,
                data={"_type": "ep_root"},
            )
            by_host: dict[str, list[tuple[str, list[dict]]]] = defaultdict(list)
            for (host, pattern), reqs in sorted(endpoints.items()):
                by_host[host].append((pattern, reqs))
            for host, patterns in sorted(by_host.items()):
                host_node = ep_root.add(host, expand=False, data={"_type": "ep_host", "host": host})
                for pattern, reqs in sorted(patterns):
                    methods = sorted(set(r.get("method", "?") for r in reqs))
                    types   = {r.get("resource_type", "document") for r in reqs}
                    params  = _param_hint(reqs)
                    tag     = _entity_tag(types)
                    actions = _actions_hint(types, bool(params))
                    label   = f"{pattern}  {tag}  [{','.join(methods)}]({len(reqs)}){params}  ·  {actions}"
                    host_node.add_leaf(
                        label,
                        data={"_type": "endpoint", "host": host, "pattern": pattern},
                    )

        tree.root.expand()

    def reset_for_crawl(self) -> None:
        tree = self.query_one("#sitemap-tree", Tree)
        tree.clear()
        self._reset_tree_state()
        tree.root.expand()

    def add_request_to_tree(self, req: dict) -> None:
        """Incrementally add one request to the site map without a full rebuild."""
        url = req.get("url", "")
        method = req.get("method", "GET")
        resource_type = req.get("resource_type", "document")
        try:
            p = urlparse(url)
            host = p.netloc or "unknown"
            segments = [s for s in p.path.split("/") if s]
        except Exception:
            return

        tree = self.query_one("#sitemap-tree", Tree)

        host_key = host
        if host_key not in self._tree_node_map:
            node = tree.root.add(host, expand=True, data=f"//{host}")
            self._tree_node_map[host_key] = node
            self._tree_methods[host_key] = set()
            self._tree_counts[host_key] = 0
            self._tree_types[host_key] = set()
            self._tree_reqs[host_key] = []
        host_node = self._tree_node_map[host_key]

        current_key = host_key
        current_node = host_node
        path_acc = ""
        for seg in segments:
            path_acc = path_acc + "/" + seg
            child_key = host_key + path_acc
            if child_key not in self._tree_node_map:
                child_node = current_node.add(f"/{seg}", expand=False, data=path_acc)
                self._tree_node_map[child_key] = child_node
                self._tree_methods[child_key] = set()
                self._tree_counts[child_key] = 0
                self._tree_types[child_key] = set()
                self._tree_reqs[child_key] = []
            current_key = child_key
            current_node = self._tree_node_map[child_key]

        self._tree_counts[current_key] = self._tree_counts.get(current_key, 0) + 1
        self._tree_methods.setdefault(current_key, set()).add(method)
        self._tree_types.setdefault(current_key, set()).add(resource_type)
        reqs_list = self._tree_reqs.setdefault(current_key, [])
        if len(reqs_list) < 3:
            reqs_list.append(req)

        count    = self._tree_counts[current_key]
        methods  = sorted(self._tree_methods[current_key])
        types    = self._tree_types[current_key]
        params   = _param_hint(reqs_list)
        tag      = _entity_tag(types)
        actions  = _actions_hint(types, bool(params))
        leaf_seg = segments[-1] if segments else host
        current_node.set_label(
            f"/{leaf_seg}  {tag}  [{','.join(methods)}]({count}){params}  ·  {actions}"
        )

    # ── tree selection → Selection panel ─────────────────────────────────

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data

        # Normalized endpoint node
        if isinstance(data, dict):
            node_type = data.get("_type", "")
            if node_type == "endpoint":
                host = data["host"]
                pattern = data["pattern"]
                # Find the best representative request for this pattern
                reqs = [
                    r for r in self._state.requests
                    if urlparse(r.get("url", "")).netloc == host
                    and _normalize_path(urlparse(r.get("url", "")).path or "/") == pattern
                ]
                req = reqs[0] if reqs else None
                params = _param_hint(reqs) if reqs else ""
                self._update_selection(
                    type_label=f"Endpoint  —  {len(reqs)} request(s)",
                    url=f"{host}{pattern}{params}",
                    req=req,
                )
            # ep_root / ep_host nodes — ignore clicks on headers
            return

        path: str = data or ""
        if not path:
            return

        # Strip scheme from host nodes
        if path.startswith("//"):
            host = path[2:]
            reqs = [r for r in self._state.requests
                    if urlparse(r.get("url", "")).netloc == host]
            target_url = self._state.target or f"https://{host}"
            synthetic = {"_host_node": True, "url": target_url, "method": "GET", "headers": {}}
            self._update_selection(
                type_label=f"Host  —  {len(reqs)} requests",
                url=path,
                req=synthetic,
            )
            return

        # Find the best matching request for this path
        req = self._find_request_for_path(path)
        resource_type = req.get("resource_type", "document") if req else "document"
        type_label = _TYPE_LABEL.get(resource_type, "Resource")

        self._update_selection(type_label=type_label, url=path, req=req)

        # For JS files: also load JS analysis data for this specific file
        if resource_type == "script" or path.endswith(".js"):
            self._populate_js_analysis(path, req)
        else:
            try:
                self.query_one("#sel-js", ScrollableContainer).remove_children()
            except Exception:
                pass

    def _find_request_for_path(self, path: str) -> dict | None:
        """Return the most recent request whose URL path matches."""
        for req in reversed(self._state.requests):
            try:
                if urlparse(req.get("url", "")).path == path:
                    return req
            except Exception:
                continue
        return None

    def _update_selection(self, type_label: str, url: str, req: dict | None) -> None:
        """Populate the Selection tab with context for the clicked node."""
        try:
            self.query_one("#detail-tabs", TabbedContent).active = "tab-selection"

            self.query_one("#sel-type", Static).update(type_label)
            self.query_one("#sel-url", Static).update(url)
            status = ""
            if req:
                resp = req.get("response") or {}
                code = req.get("response_status") or resp.get("status", "")
                size = len(resp.get("body") or "") if resp.get("body") else 0
                status = f"HTTP {code}  ·  {size:,} bytes" if code else ""
            self.query_one("#sel-status", Static).update(status)

            # If no real request matched, synthesise a minimal one from path/target
            # so the advisor still has something to score.
            ctx_req = req
            if ctx_req is None and url:
                base = self._state.target or ""
                full_url = (base.rstrip("/") + url) if url.startswith("/") else url
                ctx_req = {"method": "GET", "url": full_url, "headers": {}, "body": ""}

            self.query_one("#sel-context", ContextPanel).update_entity(ctx_req)
        except Exception:
            pass

    def _populate_js_analysis(self, path: str, req: dict | None) -> None:
        """Fill the JS analysis section for the selected JS file."""
        js_section = self.query_one("#sel-js", ScrollableContainer)
        js_section.remove_children()

        if not self._state.out_dir:
            js_section.mount(Static("No output dir loaded — run a scan to get JS analysis", classes="js-item"))
            return

        js_path = Path(self._state.out_dir) / "js_analysis.json"
        if not js_path.exists():
            js_section.mount(Static("No js_analysis.json — run a full scan to analyze JS bundles", classes="js-item"))
            return

        try:
            data = json.loads(js_path.read_text())
        except Exception:
            js_section.mount(Static("Could not read JS analysis", classes="js-item"))
            return

        # Reconstruct full URL to match source_file fields
        full_url = ""
        if req:
            full_url = req.get("url", "")
        if not full_url and self._state.target:
            full_url = urljoin(self._state.target, path)
        # Also check js_bundle_urls for a match
        if not full_url:
            full_url = next((u for u in self._state.js_bundle_urls if u.endswith(path)), "")

        def _matches(item: dict) -> bool:
            sf = item.get("source_file", "")
            return sf == full_url or (path and sf.endswith(path))

        endpoints  = [e for e in data.get("endpoints", [])    if _matches(e)]
        secrets    = [s for s in data.get("secrets", [])      if _matches(s) and not s.get("public_by_design")]
        dom_xss    = [x for x in data.get("dom_xss", [])      if _matches(x)]
        auth_smells= [a for a in data.get("auth_smells", [])  if _matches(a)]
        gql_ops    = [g for g in data.get("graphql_ops", [])  if _matches(g)]
        configs    = [c for c in data.get("configs", [])      if _matches(c)]

        any_findings = any([endpoints, secrets, dom_xss, auth_smells, gql_ops, configs])
        if not any_findings:
            js_section.mount(Static("No specific findings for this file in JS analysis", classes="js-item"))
            return

        if endpoints:
            js_section.mount(Static(f"Endpoints ({len(endpoints)})", classes="js-section-header"))
            for ep in endpoints[:20]:
                method = ep.get("method_hint", "?")
                ep_path = ep.get("path", "")
                risks = ", ".join(ep.get("risks", [])[:2])
                label = f"{method} {ep_path}" + (f"  · {risks}" if risks else "")
                js_section.mount(Static(label, classes="js-item"))

        if secrets:
            js_section.mount(Static(f"Secrets ({len(secrets)})", classes="js-section-header"))
            for s in secrets[:10]:
                preview = s.get("value_preview", "")[:40]
                stype = s.get("type", "unknown")
                js_section.mount(Static(f"[{stype}]  {preview}", classes="js-item js-secret"))

        if dom_xss:
            js_section.mount(Static(f"DOM XSS ({len(dom_xss)})", classes="js-section-header"))
            for x in dom_xss[:10]:
                js_section.mount(Static(
                    f"{x.get('source', '?')} → {x.get('sink', '?')}  (priority {x.get('priority', '?')})",
                    classes="js-item js-xss",
                ))

        if auth_smells:
            js_section.mount(Static(f"Auth patterns ({len(auth_smells)})", classes="js-section-header"))
            for a in auth_smells[:10]:
                js_section.mount(Static(a.get("pattern", ""), classes="js-item js-auth"))

        if gql_ops:
            js_section.mount(Static(f"GraphQL ops ({len(gql_ops)})", classes="js-section-header"))
            for g in gql_ops[:10]:
                js_section.mount(Static(
                    f"{g.get('op_type','?')} {g.get('name','')}",
                    classes="js-item",
                ))

        if configs:
            js_section.mount(Static(f"Config / feature flags ({len(configs)})", classes="js-section-header"))
            for c in configs[:10]:
                vals = ", ".join(str(v) for v in c.get("values", [])[:3])
                js_section.mount(Static(f"[{c.get('kind','')}]  {vals}", classes="js-item"))

    # ── fingerprint tab ───────────────────────────────────────────────────

    def _refresh_fingerprint(self) -> None:
        fp = self._state.stackprint
        if not fp:
            text = "(no stackprint data — run a scan or load an output directory)"
        else:
            lines = []
            detected = fp.get("detected", {})
            for category, values in detected.items():
                if values:
                    lines.append(f"{category}: {', '.join(str(v) for v in values)}")
            interesting = fp.get("interesting_paths", [])
            if interesting:
                lines.append(f"\nInteresting paths ({len(interesting)}):")
                lines.extend(f"  {p}" for p in interesting[:20])
            bundles = self._state.js_bundle_urls
            if bundles:
                lines.append(f"\nJS bundles ({len(bundles)}):")
                lines.extend(f"  {b}" for b in bundles[:10])
            routes = self._state.js_discovered_routes
            if routes:
                lines.append(f"\nJS-discovered routes ({len(routes)}):")
                lines.extend(f"  {r}" for r in sorted(routes)[:30])
            text = "\n".join(lines) if lines else "(no detections)"
        self.query_one("#fp-text", TextArea).load_text(text)

    # ── button handlers ───────────────────────────────────────────────────

    def show_new_target_form(self) -> None:
        """Navigate to Load/Crawl tab and pre-fill target URL from state."""
        try:
            self.query_one("#detail-tabs", TabbedContent).active = "tab-crawl"
            inp = self.query_one("#new-target-url", Input)
            if self._state.target and not inp.value:
                inp.value = self._state.target
        except Exception:
            pass

    def _build_new_target_config(self) -> dict | None:
        url = self.query_one("#new-target-url", Input).value.strip()
        if not url:
            self.app.notify("Target URL is required", severity="error")
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        allowed_raw = self.query_one("#new-allowed-hosts", Input).value.strip()
        excluded_raw = self.query_one("#new-excluded-pats", Input).value.strip()
        out_dir = self.query_one("#new-out-dir", Input).value.strip()
        auth = self.query_one("#new-auth", Input).value.strip()

        if not out_dir:
            host = (urlparse(url).hostname or "target").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_dir = str(Path(__file__).resolve().parents[3] / "output" / f"{host}-{ts}")

        return {
            "target": url,
            "allowed_hosts": [h.strip() for h in allowed_raw.split(",") if h.strip()],
            "excluded_patterns": [p.strip() for p in excluded_raw.split(",") if p.strip()],
            "out": out_dir,
            "auth": auth or None,
            "active_scan": self.query_one("#chk-new-active", Checkbox).value,
            "auto_fuzz": self.query_one("#chk-new-autofuzz", Checkbox).value,
            "quick": self.query_one("#chk-new-quick", Checkbox).value,
            "allow_writes": self.query_one("#chk-new-writes", Checkbox).value,
        }

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in ("btn-scan-fingerprint", "btn-scan-spider"):
            url = self._state.target or ""
            if not url:
                self.app.notify("No target set — add one first", severity="warning")
                return
            action = "fingerprint" if event.button.id == "btn-scan-fingerprint" else "spider"
            self.post_message(ScanTarget(action=action, url=url))
            return

        if event.button.id == "btn-apply-scope":
            self._apply_scope()

        elif event.button.id == "btn-load-dir":
            path = self.query_one("#load-dir-input", Input).value.strip()
            if path and Path(path).is_dir():
                self._state.load_output_dir(path)
                self.refresh_data()
                self.app._refresh_all()
                self.app.notify(f"Loaded: {path}")
            else:
                self.app.notify("Enter a valid output directory path", severity="warning")

        elif event.button.id in ("btn-add-target", "btn-launch-target"):
            config = self._build_new_target_config()
            if config:
                config["launch"] = (event.button.id == "btn-launch-target")
                self.post_message(LaunchNewTarget(config))

    def _apply_scope(self) -> None:
        hosts_text = self.query_one("#allowed-hosts-input", TextArea).text
        excl_text = self.query_one("#excluded-patterns-input", TextArea).text
        self._state.allowed_hosts = [
            line.strip() for line in hosts_text.splitlines() if line.strip()
        ]
        self._state.excluded_patterns = [
            line.strip() for line in excl_text.splitlines() if line.strip()
        ]
        self.app.notify(
            f"Scope: {len(self._state.allowed_hosts)} extra host(s), "
            f"{len(self._state.excluded_patterns)} exclude pattern(s)"
        )

    def refresh_data(self) -> None:
        self._refresh_target_list()
        self._refresh_tree()
        self._refresh_fingerprint()
        try:
            self.query_one("#allowed-hosts-input", TextArea).load_text(
                "\n".join(self._state.allowed_hosts)
            )
            self.query_one("#excluded-patterns-input", TextArea).load_text(
                "\n".join(self._state.excluded_patterns)
            )
        except Exception:
            pass
        # Sync the new-target form fields with current state
        try:
            if self._state.target:
                self.query_one("#new-target-url", Input).value = self._state.target
            self.query_one("#new-allowed-hosts", Input).value = ", ".join(self._state.allowed_hosts)
            self.query_one("#new-excluded-pats", Input).value = ", ".join(self._state.excluded_patterns)
        except Exception:
            pass
