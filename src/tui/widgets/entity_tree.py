"""entity_tree.py — HTML entity parser + Textual Tree widget."""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Tree

_WS_RE = re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']')


class _EntityExtractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.images: list[str] = []
        self.scripts: list[dict] = []
        self.forms: list[dict] = []
        self.websockets: list[str] = []
        self._in_script = False
        self._script_buf: list[str] = []
        self._current_form: dict | None = None

    def _abs(self, url: str) -> str:
        return urljoin(self.base_url, url)

    def _skip(self, href: str) -> bool:
        if not href:
            return True
        lh = href.strip().lower()
        return lh.startswith(("#", "javascript:", "mailto:", "data:"))

    def _attr(self, attrs: list, name: str) -> str:
        for k, v in attrs:
            if k == name:
                return v or ""
        return ""

    def handle_starttag(self, tag: str, attrs: list) -> None:
        tag = tag.lower()
        if tag == "a":
            href = self._attr(attrs, "href")
            if not self._skip(href):
                self.links.append(self._abs(href))
        elif tag == "link":
            href = self._attr(attrs, "href")
            rel = self._attr(attrs, "rel").lower()
            if not self._skip(href) and "stylesheet" not in rel:
                self.links.append(self._abs(href))
        elif tag in ("img", "source"):
            src = self._attr(attrs, "src")
            if src:
                self.images.append(self._abs(src))
        elif tag == "script":
            src = self._attr(attrs, "src")
            if src:
                self.scripts.append({"src": self._abs(src)})
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "form":
            action = self._attr(attrs, "action") or self.base_url
            method = (self._attr(attrs, "method") or "GET").upper()
            self._current_form = {"action": self._abs(action), "method": method, "fields": []}
            self.forms.append(self._current_form)
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            name = self._attr(attrs, "name")
            if name:
                self._current_form["fields"].append({
                    "name": name,
                    "type": self._attr(attrs, "type") or tag,
                    "value": self._attr(attrs, "value"),
                })

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script" and self._in_script:
            body = "".join(self._script_buf)
            if body.strip():
                self.scripts.append({"inline": body})
            for m in _WS_RE.finditer(body):
                self.websockets.append(m.group(1))
            self._in_script = False
            self._script_buf = []
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)


class EntityTree(Widget):
    """Parsed entity breakdown for a single HTTP request/response."""

    DEFAULT_CSS = """
    EntityTree {
        height: 1fr;
    }
    EntityTree Tree {
        height: 1fr;
    }
    """

    class Action(Message):
        def __init__(self, kind: str, value: str, meta: dict | None = None) -> None:
            super().__init__()
            self.kind = kind
            self.value = value
            self.meta: dict = meta or {}

    def compose(self) -> ComposeResult:
        yield Tree("(no request loaded)", id="entity-tree")

    def load(self, req: dict, resp_body: str = "") -> None:
        tree: Tree = self.query_one("#entity-tree", Tree)
        tree.clear()

        url: str = req.get("url", "")
        method: str = (req.get("method") or "GET").upper()
        headers: dict = req.get("headers") or {}
        body: str = req.get("body") or ""

        label = (url[:67] + "…") if len(url) > 70 else url
        tree.root.set_label(label)
        tree.root.data = None

        # --- params ----------------------------------------------------------
        params: dict[str, list[str]] = {}
        parsed = urlparse(url)
        if parsed.query:
            params.update(parse_qs(parsed.query, keep_blank_values=True))

        ct = next((v.lower() for k, v in headers.items() if k.lower() == "content-type"), "")
        if method in ("POST", "PUT", "PATCH") and body:
            if "application/x-www-form-urlencoded" in ct:
                params.update(parse_qs(body, keep_blank_values=True))
            elif "application/json" in ct:
                try:
                    jdata = json.loads(body)
                    if isinstance(jdata, dict):
                        for k, v in jdata.items():
                            params[k] = [str(v)]
                except Exception:
                    pass

        self._add_section(tree, f"Params ({len(params)})", [
            {
                "label": f"{name} = {vals[0]!r}" if vals else name,
                "data": {
                    "kind": "fuzz_param",
                    "value": name,
                    "meta": {"req": req, "param_value": vals[0] if vals else ""},
                },
            }
            for name, vals in params.items()
        ])

        # --- HTML entities ---------------------------------------------------
        extractor = _EntityExtractor(url)
        if resp_body:
            try:
                extractor.feed(resp_body)
            except Exception:
                pass

        unique_links = list(dict.fromkeys(extractor.links))
        self._add_section(tree, f"Links ({len(unique_links)})", [
            {"label": lnk, "data": {"kind": "repeater", "value": lnk}}
            for lnk in unique_links
        ])

        # forms — nested
        forms_branch = tree.root.add(f"Forms ({len(extractor.forms)})", data=None)
        if extractor.forms:
            for form in extractor.forms:
                form_node = forms_branch.add(
                    f"{form['method']} {form['action']}",
                    data={"kind": "fuzz_form", "value": form["action"],
                          "meta": {"fields": form["fields"], "method": form["method"], "req": req}},
                )
                for field in form["fields"]:
                    fname = field.get("name") or "(unnamed)"
                    ftype = field.get("type", "")
                    fval = field.get("value", "")
                    form_node.add_leaf(
                        f"{fname} [{ftype}]" + (f" = {fval!r}" if fval else ""),
                        data={"kind": "fuzz_param", "value": fname,
                              "meta": {"req": req, "param_value": fval, "form": form}},
                    )
                form_node.expand()
        else:
            forms_branch.add_leaf("(none)", data=None)
        forms_branch.expand()

        self._add_section(tree, f"Scripts ({len(extractor.scripts)})", [
            {
                "label": s.get("src") or "(inline) " + s.get("inline", "")[:40].replace("\n", " "),
                "data": (
                    {"kind": "js_probe", "value": s["src"]}
                    if "src" in s
                    else {"kind": "js_probe", "value": "(inline)",
                          "meta": {"snippet": s.get("inline", "")[:80]}}
                ),
            }
            for s in extractor.scripts
        ])

        self._add_section(tree, f"Images ({len(extractor.images)})", [
            {"label": img, "data": {"kind": "fingerprint", "value": img}}
            for img in extractor.images
        ])

        self._add_section(tree, f"WebSockets ({len(extractor.websockets)})", [
            {"label": ws, "data": {"kind": "ws_probe", "value": ws}}
            for ws in extractor.websockets
        ])

        tree.root.expand()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        data = node.data
        if data is None or node.children:
            return
        self.post_message(EntityTree.Action(
            kind=data["kind"],
            value=data["value"],
            meta=data.get("meta", {}),
        ))

    def _add_section(self, tree: Tree, label: str, items: list[dict]) -> None:
        branch = tree.root.add(label, data=None)
        if items:
            for item in items:
                branch.add_leaf(item["label"], data=item["data"])
        else:
            branch.add_leaf("(none)", data=None)
        branch.expand()
