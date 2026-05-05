"""Reusable split-panel widget: raw request (top) + response (bottom)."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static, TextArea
from textual.containers import Vertical, Horizontal


def _format_request(req: dict) -> str:
    method = req.get("method", "GET")
    url = req.get("url", "")
    headers = req.get("headers", {})
    body = req.get("body") or ""
    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body if len(body) < 4096 else body[:4096] + "\n[truncated]")
    return "\n".join(lines)


def _format_response(req: dict) -> str:
    resp = req.get("response", {})
    if not resp:
        status = req.get("response_status")
        headers = req.get("response_headers", {})
        body = req.get("response_body") or ""
    else:
        status = resp.get("status")
        headers = resp.get("headers", {})
        body = resp.get("body") or ""

    lines = [f"HTTP {status or '?'}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body if len(body) < 8192 else body[:8192] + "\n[truncated]")
    return "\n".join(lines)


class RequestViewer(Vertical):
    """Displays request + response in a vertical split."""

    DEFAULT_CSS = """
    RequestViewer {
        height: 1fr;
    }
    RequestViewer .req-label {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
    }
    RequestViewer TextArea {
        height: 1fr;
        border: none;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Request", classes="req-label")
        yield TextArea("", id="req-text", read_only=True)
        yield Static("Response", classes="req-label")
        yield TextArea("", id="resp-text", read_only=True)

    def show_request(self, req: dict) -> None:
        self.query_one("#req-text", TextArea).load_text(_format_request(req))
        self.query_one("#resp-text", TextArea).load_text(_format_response(req))

    def set_raw(self, raw_request: str, raw_response: str = "") -> None:
        self.query_one("#req-text", TextArea).load_text(raw_request)
        self.query_one("#resp-text", TextArea).load_text(raw_response)

    def get_raw_request(self) -> str:
        return self.query_one("#req-text", TextArea).text
