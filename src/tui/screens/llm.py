"""LLM tab — solver status, decision log, operator override input."""
from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static, TabbedContent, TabPane, TextArea

from ..state import AppState


_DEC_COLS = ["time", "stage", "finding", "verdict", "model", "reason"]


def _short(s, n: int = 80) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


class LLMScreen(Vertical):
    """LLM solver console: status + decision log + override chat."""

    DEFAULT_CSS = """
    LLMScreen { height: 1fr; }
    LLMScreen #llm-status { height: 7; padding: 0 1; background: $surface-darken-1; }
    LLMScreen DataTable { height: 1fr; }
    LLMScreen #llm-decision-detail { height: 12; border-top: solid $primary; padding: 0 1; }
    LLMScreen #llm-override-row { height: 3; padding: 0 1; background: $surface-darken-1; }
    LLMScreen #llm-override-row Input { width: 1fr; }
    LLMScreen #llm-override-row Button { min-width: 12; margin-left: 1; }
    LLMScreen #llm-override-history { height: 6; border-top: solid $primary-darken-2; padding: 0 1; color: $text-muted; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._override_history: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static("", id="llm-status")
        with TabbedContent():
            with TabPane("Decision log", id="llm-decisions"):
                yield DataTable(id="llm-dec-table", cursor_type="row", zebra_stripes=True)
                yield TextArea("", id="llm-decision-detail", read_only=True)
            with TabPane("Override / chat", id="llm-override"):
                with Horizontal(id="llm-override-row"):
                    yield Input(
                        placeholder=(
                            "Type a note for the next LLM briefing call "
                            "(e.g. 'skip the captcha flow') and press Send"
                        ),
                        id="llm-override-input",
                    )
                    yield Button("Send", variant="primary", id="btn-llm-send")
                yield TextArea("", id="llm-override-history", read_only=True)
                yield Static(
                    "Notes are consumed by the next call to "
                    "briefing_generator.generate_briefing(). One note per call; "
                    "queue more by sending again.",
                    id="llm-override-help",
                )

    def on_mount(self) -> None:
        self.query_one("#llm-dec-table", DataTable).add_columns(*_DEC_COLS)
        self.refresh_data()

    def refresh_data(self) -> None:
        decisions = self._state.llm_decisions or []
        last_model = ""
        last_provider = ""
        for d in reversed(decisions):
            if isinstance(d, dict):
                last_model = d.get("model") or last_model
                last_provider = d.get("provider") or last_provider
                if last_model and last_provider:
                    break

        confirmed = sum(
            1 for d in decisions
            if isinstance(d, dict) and d.get("stage") == "verdict" and d.get("verdict") == "confirmed"
        )
        refuted = sum(
            1 for d in decisions
            if isinstance(d, dict) and d.get("stage") == "verdict" and d.get("verdict") == "refuted"
        )
        inconclusive = sum(
            1 for d in decisions
            if isinstance(d, dict) and d.get("stage") == "verdict" and d.get("verdict") == "inconclusive"
        )
        starts = sum(1 for d in decisions if isinstance(d, dict) and d.get("stage") == "start")

        status = (
            f"provider: {last_provider or '—'}    model:    {last_model or '—'}\n"
            f"findings started:  {starts}\n"
            f"verdicts:          {confirmed} confirmed  /  {refuted} refuted  /  "
            f"{inconclusive} inconclusive\n"
            f"pending overrides: {len(self._override_history)} queued"
        )
        self.query_one("#llm-status", Static).update(status)

        table = self.query_one("#llm-dec-table", DataTable)
        table.clear()
        for d in decisions:
            if not isinstance(d, dict):
                continue
            ts = d.get("received_at") or d.get("ts") or ""
            if isinstance(ts, (int, float)) and ts:
                ts = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            elif not ts:
                ts = ""
            table.add_row(
                _short(ts, 12),
                _short(d.get("stage"), 10),
                _short(d.get("finding_index"), 6),
                _short(d.get("verdict"), 14),
                _short(d.get("model"), 22),
                _short(d.get("reason") or d.get("url"), 60),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        decisions = self._state.llm_decisions or []
        if 0 <= idx < len(decisions):
            d = decisions[idx]
            if isinstance(d, dict):
                lines = [f"{k}: {v}" for k, v in d.items()]
                self.query_one("#llm-decision-detail", TextArea).load_text("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-llm-send":
            self._send_override()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "llm-override-input":
            self._send_override()

    def _send_override(self) -> None:
        inp = self.query_one("#llm-override-input", Input)
        msg = (inp.value or "").strip()
        if not msg:
            return
        try:
            import sys as _sys
            from pathlib import Path as _Path
            src = str(_Path(__file__).resolve().parents[2])
            if src not in _sys.path:
                _sys.path.insert(0, src)
            from briefing_generator import push_override
            push_override(msg)
        except Exception as exc:
            self.app.notify(f"Override push failed: {exc}", severity="error", timeout=6)
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        self._override_history.insert(0, f"[{stamp}] {msg}")
        history_text = "\n".join(self._override_history[:20])
        self.query_one("#llm-override-history", TextArea).load_text(history_text)
        inp.value = ""
        self.app.notify("Override queued — applied to the next briefing call.", timeout=4)
        self.refresh_data()
