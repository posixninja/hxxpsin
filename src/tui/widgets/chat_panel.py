"""Dashboard chat panel — fixed-height LLM chat that drives MCP tools.

Lives in the dashboard side column as a fixed-height block (no
Collapsible) so it composes predictably alongside the Status / Alerts
/ Log blocks. Heavy work (MCP boot, LLM ReAct loop) runs in a worker
thread; the panel itself is just transcript + input + status line.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, Static, TextArea

if TYPE_CHECKING:
    from ..mcp_chat.controller import ChatController, ChatTurn


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class ChatPanel(Vertical):
    """Fixed-height chat box for the Dashboard side column."""

    DEFAULT_CSS = """
    ChatPanel {
        border: solid $primary-darken-2;
    }
    ChatPanel #chat-header {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        height: 1;
    }
    ChatPanel #chat-transcript {
        height: 1fr;
        background: $surface-darken-1;
    }
    ChatPanel #chat-status {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }
    ChatPanel #chat-input-row {
        height: 3;
        padding: 0 1;
    }
    ChatPanel #chat-input-row Input {
        width: 1fr;
    }
    ChatPanel #chat-input-row Button {
        min-width: 8;
        margin-left: 1;
    }
    """

    def __init__(self, controller: "ChatController", **kwargs):
        super().__init__(**kwargs)
        self._controller = controller
        self._busy = False
        self._lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static("LLM Chat (MCP)", id="chat-header", markup=False)
        yield TextArea(
            "Ask the assistant — it can call MCP tools (stackprint, "
            "decode, jwt_inspect, scan_findings, …).",
            id="chat-transcript",
            read_only=True,
        )
        yield Label("idle — MCP boots on first send", id="chat-status")
        with Horizontal(id="chat-input-row"):
            yield Input(placeholder="Type a message and press Enter", id="chat-input")
            yield Button("Send", variant="primary", id="btn-chat-send")
            yield Button("Clear", id="btn-chat-clear")

    # -- ui actions -------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-chat-send":
            self._submit()
        elif event.button.id == "btn-chat-clear":
            self._controller.clear()
            self._lines.clear()
            self._redraw()
            self._set_status("cleared")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            self._submit()

    def _submit(self) -> None:
        if self._busy:
            self.app.notify("chat busy — wait for the current turn", severity="warning")
            return
        inp = self.query_one("#chat-input", Input)
        msg = (inp.value or "").strip()
        if not msg:
            return
        inp.value = ""
        self._lines.append(f"[{_ts()}] you: {msg}")
        self._redraw()
        self._set_status("running…")
        self._busy = True
        self.app.run_worker(
            lambda m=msg: self._run_turn(m),
            thread=True,
            exclusive=False,
            name="chat-turn",
        )

    # -- worker thread ----------------------------------------------------

    def _run_turn(self, user_msg: str) -> None:
        def _step_cb(kind: str, payload: dict) -> None:
            self.app.call_from_thread(self._on_react_step, kind, payload)

        try:
            turn = self._controller.send(user_msg, on_step=_step_cb)
        except Exception as exc:
            self.app.call_from_thread(self._on_error, str(exc))
            return
        self.app.call_from_thread(self._on_final, turn)

    # -- render helpers ---------------------------------------------------

    def _on_react_step(self, kind: str, payload: dict) -> None:
        if kind == "status":
            text = payload.get("text", "")
            if text:
                self._set_status(text)
            return
        if kind == "tool_call":
            name = payload.get("name", "?")
            self._lines.append(f"  → calling {name}")
            self._set_status(f"tool: {name}")
        elif kind == "tool_result":
            name = payload.get("name", "?")
            ok = payload.get("ok", False)
            tag = "✓" if ok else "✗"
            text = (payload.get("text") or "").splitlines()[0] if payload.get("text") else ""
            self._lines.append(f"  {tag} {name}: {text[:90]}")
        self._redraw()

    def _on_final(self, turn: "ChatTurn") -> None:
        self._busy = False
        if turn.error and not turn.assistant:
            self._lines.append(f"[{_ts()}] error: {turn.error}")
        else:
            self._lines.append(f"[{_ts()}] assistant: {turn.assistant}")
        snap = self._controller.snapshot()
        provider = snap.provider or "?"
        model = snap.model or "?"
        tools = len(snap.tools)
        self._set_status(f"idle — {provider}/{model} • {tools} MCP tools")
        self._redraw()

    def _on_error(self, msg: str) -> None:
        self._busy = False
        self._lines.append(f"[{_ts()}] error: {msg}")
        self._set_status("error")
        self._redraw()

    def _redraw(self) -> None:
        try:
            ta = self.query_one("#chat-transcript", TextArea)
        except Exception:
            return
        max_lines = 200
        if len(self._lines) > max_lines:
            self._lines = self._lines[-max_lines:]
        ta.load_text("\n".join(self._lines))
        try:
            ta.cursor_location = ta.document.end
        except Exception:
            pass

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#chat-status", Label).update(text)
        except Exception:
            pass
