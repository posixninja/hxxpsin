"""Report tab — scrollable markdown report viewer."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Button, Markdown, Static
from textual.containers import Horizontal

from ..state import AppState


class ReportScreen(Vertical):
    """Renders report.md as a scrollable Markdown widget."""

    BINDINGS = [
        Binding("e", "open_editor", "Open in $EDITOR"),
    ]

    DEFAULT_CSS = """
    ReportScreen {
        height: 1fr;
    }
    ReportScreen #report-toolbar {
        height: 3;
        padding: 0 1;
        background: $surface-darken-1;
    }
    ReportScreen #report-toolbar Button {
        min-width: 18;
        margin-right: 1;
    }
    ReportScreen Markdown {
        height: 1fr;
    }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        with Horizontal(id="report-toolbar"):
            yield Button("Open in $EDITOR (e)", id="btn-editor", variant="default")
            yield Button("Reload", id="btn-reload", variant="default")
            yield Static("", id="report-path-label")
        yield Markdown("*(no report loaded)*", id="report-md")

    def on_mount(self) -> None:
        self._load_report()

    def _get_report_path(self) -> Path | None:
        if self._state.out_dir:
            p = Path(self._state.out_dir) / "report.md"
            if p.exists():
                return p
        return None

    def _load_report(self) -> None:
        path = self._get_report_path()
        if path:
            try:
                content = path.read_text()
                self.query_one("#report-md", Markdown).update(content)
                self.query_one("#report-path-label", Static).update(str(path))
            except Exception as exc:
                self.query_one("#report-md", Markdown).update(f"Error reading report: {exc}")
        else:
            out_dir = self._state.out_dir or "(no output dir set)"
            self.query_one("#report-md", Markdown).update(
                f"No report.md found in `{out_dir}`.\n\nRun a scan first or load an output directory."
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-editor":
            self.action_open_editor()
        elif event.button.id == "btn-reload":
            self._load_report()

    def action_open_editor(self) -> None:
        path = self._get_report_path()
        if not path:
            self.app.notify("No report.md found", severity="warning")
            return
        editor = os.environ.get("EDITOR", "vi")
        try:
            self.app.suspend()
            subprocess.run([editor, str(path)])
        finally:
            self.app.resume()

    def refresh_data(self) -> None:
        self._load_report()
