"""MSF workspace pane — displays whatever msf_ingest pulled/pushed.

Reads AppState.msf_result (the MSFIngestResult.to_dict() persisted into
report.json) plus the live step-log emitted by msf_ingest_step events.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static, TextArea

from ..state import AppState


_PULL_ROWS = [
    ("Hosts",    "pulled_hosts"),
    ("Services", "pulled_services"),
    ("Vulns",    "pulled_vulns"),
    ("Creds",    "pulled_creds"),
    ("Loot",     "pulled_loot"),
    ("Notes",    "pulled_notes"),
    ("Sessions", "pulled_sessions"),
]


class MSFPane(Vertical):
    """MSF integration pane — backend, workspace, pull/push counts, log."""
    DEFAULT_CSS = """
    MSFPane { height: 1fr; }
    MSFPane #msf-header { height: 4; padding: 0 1; background: $surface-darken-1; }
    MSFPane Static.section { background: $surface-darken-1; padding: 0 1; height: 1; color: $text-muted; }
    MSFPane DataTable { height: 8; }
    MSFPane #msf-overlap { height: 6; padding: 0 1; }
    MSFPane #msf-sessions { height: 8; }
    MSFPane #msf-suggested { height: 8; padding: 0 1; }
    MSFPane #msf-log { height: 1fr; border-top: solid $primary; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        yield Static("", id="msf-header")
        yield Static("Pulled / pushed counts", classes="section")
        yield DataTable(id="msf-counts", cursor_type="row", zebra_stripes=True)
        yield Static("Workspace overlap with this scan", classes="section")
        yield Static("", id="msf-overlap")
        yield Static("Live MSF sessions on this target", classes="section")
        yield DataTable(id="msf-sessions", cursor_type="row", zebra_stripes=True)
        yield Static("Suggested MSF modules per finding", classes="section")
        yield Static("", id="msf-suggested")
        yield Static("Ingest step log", classes="section")
        yield TextArea("", id="msf-log", read_only=True)

    def on_mount(self) -> None:
        self.query_one("#msf-counts", DataTable).add_columns("Source", "Count")
        sessions_tbl = self.query_one("#msf-sessions", DataTable)
        sessions_tbl.add_columns("ID", "Type", "Target", "Via", "Opened")
        self.refresh_data()

    def refresh_data(self) -> None:
        backend = self._state.msf_backend or "—"
        workspace = self._state.msf_workspace or "—"
        result = self._state.msf_result or {}

        header_lines = [
            f"backend:   {backend}",
            f"workspace: {workspace}",
        ]
        pushed = result.get("pushed_vulns") or []
        if pushed:
            header_lines.append(f"pushed:    {len(pushed)} finding(s) → MSF")
        self.query_one("#msf-header", Static).update("\n".join(header_lines))

        counts = self.query_one("#msf-counts", DataTable)
        counts.clear()
        for label, key in _PULL_ROWS:
            counts.add_row(label, str(int(result.get(key, 0) or 0)))
        if pushed:
            counts.add_row("Pushed vulns", str(len(pushed)))

        overlap = result.get("overlapped_hosts") or []
        if overlap:
            preview = ", ".join(str(h) for h in overlap[:8])
            more = f"  …+{len(overlap) - 8} more" if len(overlap) > 8 else ""
            self.query_one("#msf-overlap", Static).update(
                f"{len(overlap)} host(s) overlap:\n  {preview}{more}"
            )
        else:
            self.query_one("#msf-overlap", Static).update(
                "No host overlap detected (MSF workspace and current scan target are disjoint)."
            )

        sessions_tbl = self.query_one("#msf-sessions", DataTable)
        sessions_tbl.clear()
        sessions = self._state.msf_sessions_on_target or []
        if sessions:
            for s in sessions[:20]:
                sessions_tbl.add_row(
                    str(s.get("id", "-")),
                    str(s.get("session_type", "-")),
                    str(s.get("target_host", "-")),
                    str(s.get("via_exploit", "-")),
                    str(s.get("opened_at", "-")),
                )
        else:
            sessions_tbl.add_row("—", "—", "—", "—", "no live sessions on target")

        suggested = self._state.msf_suggested_modules or {}
        if suggested:
            preview_lines = []
            for url, hints in list(suggested.items())[:6]:
                short = url if len(url) <= 60 else url[:55] + "…"
                preview_lines.append(f"{short}\n  → {', '.join(hints)}")
            if len(suggested) > 6:
                preview_lines.append(f"…+{len(suggested) - 6} more finding(s)")
            self.query_one("#msf-suggested", Static).update("\n".join(preview_lines))
        else:
            self.query_one("#msf-suggested", Static).update(
                "No module suggestions yet (suggest_modules disabled or no "
                "high-signal findings)."
            )

        # Live step log — emitted by msf_ingest_step events; falls back to
        # any notes the result carries on a finished scan.
        log_lines: list[str] = list(self._state.msf_step_log)
        notes = result.get("notes") or []
        if notes:
            log_lines.append("--- notes ---")
            log_lines.extend(str(n) for n in notes)
        if not log_lines:
            log_lines = [
                "MSF integration not active — enable [msf] in your operator "
                "config (see hxxpsin.toml.example) or pass --msf on the CLI.",
            ]
        self.query_one("#msf-log", TextArea).load_text("\n".join(log_lines))
