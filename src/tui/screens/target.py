"""Target tab — site map tree, scope, fingerprint, and crawl controls."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import (
    Button, Input, Label, ListItem, ListView, Static,
    TabbedContent, TabPane, TextArea, Tree,
)
from textual.widgets.tree import TreeNode

from ..state import AppState


class LaunchNewTarget(Message):
    """Posted when the user confirms a new-target scan."""
    def __init__(self, config: dict) -> None:
        super().__init__()
        self.config = config   # keys: target, scan_type, out_dir, options…


def _build_site_map(requests: list[dict]) -> dict:
    tree: dict = {}
    for req in requests:
        url = req.get("url", "")
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
    return tree


def _populate_tree(tree_widget: Tree, data: dict, parent: TreeNode | None = None) -> None:
    root = parent if parent else tree_widget.root
    for key, value in sorted(data.items()):
        if key == "__requests__":
            continue
        label = f"/{key}" if isinstance(key, str) else str(key)
        reqs = value.get("__requests__", [])
        if reqs:
            methods = set(r.get("method", "?") for r in reqs)
            label = f"{label}  [{','.join(sorted(methods))}] ({len(reqs)})"
        child = root.add(label, expand=False)
        sub = {k: v for k, v in value.items() if k != "__requests__"}
        if sub:
            _populate_tree(tree_widget, sub, child)


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
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        with Vertical(id="sitemap-panel"):
            yield Static("Targets", classes="panel-title")
            yield ListView(id="target-list")
            yield Static("Site Map", classes="panel-title")
            yield Tree("Target", id="sitemap-tree")

        with Vertical(id="detail-panel"):
            with TabbedContent():
                with TabPane("Scope", id="tab-scope"):
                    yield Static(
                        "In-scope hosts (one per line — the primary target host is always included):",
                        classes="scope-label",
                    )
                    yield TextArea(
                        "\n".join(self._state.allowed_hosts),
                        id="allowed-hosts-input",
                    )
                    yield Static(
                        "Excluded URL patterns (regex, one per line — matched against full URL):",
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
                    yield Static("Load existing output directory:", classes="panel-title")
                    yield Input(
                        value=self._state.out_dir or "",
                        placeholder="output/my-scan-dir",
                        id="load-dir-input",
                    )
                    yield Button("Load Output Dir", id="btn-load-dir", variant="default")
                    yield Static("── or start a new scan ──", classes="panel-title")
                    yield Button("New Target…", id="btn-new-target", variant="success")
                    yield Static("", id="crawl-status")

    def on_mount(self) -> None:
        self._refresh_target_list()
        self._refresh_tree()
        self._refresh_fingerprint()

    def _refresh_target_list(self) -> None:
        lv = self.query_one("#target-list", ListView)
        lv.clear()
        for t in self._state.targets:
            url = t.get("target", "")
            extra = f"  +{len(t.get('allowed_hosts', []))} hosts" if t.get("allowed_hosts") else ""
            lv.append(ListItem(Label(f"{url}{extra}")))
        if not self._state.targets:
            lv.append(ListItem(Label("(no targets — press N to add one)")))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._state.targets):
            config = self._state.targets[idx]
            self._state.target = config["target"]
            self._state.allowed_hosts = config.get("allowed_hosts", [])
            self._state.excluded_patterns = config.get("excluded_patterns", [])
            # Load scan output if it exists
            out = config.get("out", "")
            if out and __import__("pathlib").Path(out).is_dir():
                self._state.load_output_dir(out)
                self.app._refresh_all()
                self.app.notify(f"Switched to: {config['target']}")
            else:
                self.app.notify(f"Selected: {config['target']} (no scan output yet)")

    def _refresh_tree(self) -> None:
        tree = self.query_one("#sitemap-tree", Tree)
        tree.clear()
        if not self._state.requests:
            tree.root.add_leaf("(no requests loaded — load an output dir or start a scan)")
            return
        site_map = _build_site_map(self._state.requests)
        _populate_tree(tree, site_map)
        tree.root.expand()

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
            text = "\n".join(lines) if lines else "(no detections)"
        self.query_one("#fp-text", TextArea).load_text(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
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

        elif event.button.id == "btn-new-target":
            self._apply_scope()
            self.app.action_new_target()

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
        # Sync scope widgets with state (in case state was reset)
        try:
            self.query_one("#allowed-hosts-input", TextArea).load_text(
                "\n".join(self._state.allowed_hosts)
            )
            self.query_one("#excluded-patterns-input", TextArea).load_text(
                "\n".join(self._state.excluded_patterns)
            )
        except Exception:
            pass
