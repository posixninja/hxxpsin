"""wizard.py — New Session wizard modal."""
from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, RadioButton, RadioSet


class WizardScreen(Screen[dict | None]):
    """New Session wizard: mode → target/options → start."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    WizardScreen {
        align: center middle;
    }
    #wizard-dialog {
        width: 70;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 1 2;
    }
    #wizard-dialog .field-row {
        height: 3;
        margin-bottom: 1;
    }
    #wizard-dialog .field-row Label {
        width: 20;
        content-align: left middle;
    }
    #wizard-dialog .field-row Input {
        width: 1fr;
    }
    #wizard-dialog .section-header {
        color: $text-muted;
        height: 1;
        margin-top: 1;
        margin-bottom: 1;
    }
    #wizard-dialog #mode-row {
        height: auto;
        margin-bottom: 1;
    }
    #wizard-dialog #short-row {
        height: 3;
        margin-bottom: 1;
    }
    #wizard-dialog #short-row Label {
        width: 14;
        content-align: left middle;
    }
    #wizard-dialog #short-row Input {
        width: 10;
    }
    #wizard-dialog .check-row {
        height: 3;
    }
    #wizard-dialog #btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    #wizard-dialog #btn-row Button {
        min-width: 12;
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        default_out = f"output/{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        with Vertical(id="wizard-dialog"):
            yield Label("New Session", markup=False)

            with Horizontal(id="mode-row"):
                yield Label("Mode: ", markup=False)
                with RadioSet(id="mode-radio"):
                    yield RadioButton("Automatic", value=True, id="rb-auto")
                    yield RadioButton("Manual", id="rb-manual")

            with Horizontal(classes="field-row"):
                yield Label("Target:", markup=False)
                yield Input(placeholder="https://", id="inp-target")

            with Horizontal(classes="field-row"):
                yield Label("Output dir:", markup=False)
                yield Input(value=default_out, id="inp-output")

            # Automatic options
            with Vertical(id="auto-opts"):
                yield Label("── Automatic ─────────────────────────────", classes="section-header", markup=False)
                with Horizontal(classes="field-row"):
                    yield Label("Auth file:", markup=False)
                    yield Input(placeholder="(optional)", id="inp-auth-auto")

            # Manual options
            with Vertical(id="manual-opts"):
                yield Label("── Manual ─────────────────────────────────", classes="section-header", markup=False)
                with Horizontal(classes="field-row"):
                    yield Label("Auth file:", markup=False)
                    yield Input(placeholder="(optional)", id="inp-auth-manual")
                with Horizontal(classes="field-row"):
                    yield Label("Allowed hosts:", markup=False)
                    yield Input(placeholder="space-separated", id="inp-allowed")
                with Horizontal(classes="field-row"):
                    yield Label("Exclude patterns:", markup=False)
                    yield Input(placeholder="space-separated", id="inp-excluded")
                with Horizontal(id="short-row"):
                    yield Label("Max pages:", markup=False)
                    yield Input(value="80", id="inp-max-pages", restrict=r"[0-9]*")
                    yield Label("  Depth:", markup=False)
                    yield Input(value="4", id="inp-depth", restrict=r"[0-9]*")
                with Horizontal(classes="check-row"):
                    yield Checkbox("Active scan", id="chk-active")
                    yield Checkbox("Auto-fuzz", id="chk-fuzz")
                with Horizontal(classes="check-row"):
                    yield Checkbox("Allow writes", id="chk-writes")
                    yield Checkbox("Headed browser", id="chk-headed")

            with Horizontal(id="btn-row"):
                yield Button("Start", variant="primary", id="btn-start")
                yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        self.query_one("#auto-opts").display = True
        self.query_one("#manual-opts").display = False

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        is_auto = event.index == 0
        self.query_one("#auto-opts").display = is_auto
        self.query_one("#manual-opts").display = not is_auto

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-start":
            self._do_start()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _do_start(self) -> None:
        target = self.query_one("#inp-target", Input).value.strip()
        if not target:
            self.query_one("#inp-target", Input).focus()
            return
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        out_dir = (
            self.query_one("#inp-output", Input).value.strip()
            or f"output/{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )

        mode_radio: RadioSet = self.query_one("#mode-radio", RadioSet)
        is_auto = mode_radio.pressed_index == 0

        if is_auto:
            auth = self.query_one("#inp-auth-auto", Input).value.strip()
            config: dict = {
                "mode": "automatic",
                "target": target,
                "out": out_dir,
                "auth": auth or None,
                "active_scan": False,
                "auto_fuzz": False,
                "allow_writes": False,
                "quick": False,
                "passive": True,   # Automatic = discovery only; no active probes
                "allowed_hosts": [],
                "excluded_patterns": [],
            }
        else:
            auth = self.query_one("#inp-auth-manual", Input).value.strip()
            allowed_raw = self.query_one("#inp-allowed", Input).value
            excluded_raw = self.query_one("#inp-excluded", Input).value
            try:
                max_pages = int(self.query_one("#inp-max-pages", Input).value or "80")
            except ValueError:
                max_pages = 80
            config = {
                "mode": "manual",
                "target": target,
                "out": out_dir,
                "auth": auth or None,
                "active_scan": self.query_one("#chk-active", Checkbox).value,
                "auto_fuzz": self.query_one("#chk-fuzz", Checkbox).value,
                "allow_writes": self.query_one("#chk-writes", Checkbox).value,
                "quick": False,
                "passive": False,  # Manual = user toggles what to run
                "allowed_hosts": allowed_raw.split() if allowed_raw else [],
                "excluded_patterns": excluded_raw.split() if excluded_raw else [],
            }

        self.dismiss(config)
