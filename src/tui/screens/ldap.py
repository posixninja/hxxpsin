"""AD/LDAP tab — directory dump viewer."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static, TabbedContent, TabPane, TextArea

from ..state import AppState


_FP_COLS = ["vendor", "confidence", "evidence", "source_finding"]
_INJ_COLS = ["endpoint", "param", "baseline_len", "true_len", "false_len", "wildcard_len"]
_ACCT_COLS = ["identifier", "dn", "tags", "source_endpoint", "source_param"]
_HV_COLS = ["identifier", "tag", "evidence"]


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:6])
    if v is None:
        return ""
    return str(v)


class LDAPScreen(Vertical):
    """LDAP/AD dump viewer: fingerprints, confirmed injections, accounts, high-value."""

    DEFAULT_CSS = """
    LDAPScreen { height: 1fr; }
    LDAPScreen #ldap-summary { height: 5; padding: 0 1; background: $surface-darken-1; }
    LDAPScreen DataTable { height: 1fr; }
    LDAPScreen #ldap-detail { height: 12; border-top: solid $primary; padding: 0 1; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        yield Static("", id="ldap-summary")
        with TabbedContent():
            with TabPane("Fingerprints", id="ldap-fp"):
                yield DataTable(id="ldap-fp-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Confirmed Injections", id="ldap-inj"):
                yield DataTable(id="ldap-inj-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Accounts", id="ldap-acct"):
                yield DataTable(id="ldap-acct-table", cursor_type="row", zebra_stripes=True)
            with TabPane("High Value", id="ldap-hv"):
                yield DataTable(id="ldap-hv-table", cursor_type="row", zebra_stripes=True)
        yield TextArea("", id="ldap-detail", read_only=True)

    def on_mount(self) -> None:
        self.query_one("#ldap-fp-table", DataTable).add_columns(*_FP_COLS)
        self.query_one("#ldap-inj-table", DataTable).add_columns(*_INJ_COLS)
        self.query_one("#ldap-acct-table", DataTable).add_columns(*_ACCT_COLS)
        self.query_one("#ldap-hv-table", DataTable).add_columns(*_HV_COLS)
        self.refresh_data()

    def refresh_data(self) -> None:
        dump = self._state.ldap_dump or {}
        fingerprints = dump.get("fingerprints", []) or []
        injections = dump.get("confirmed_injections", []) or []
        accounts = self._state.ldap_accounts or dump.get("accounts", []) or []
        high_value = dump.get("high_value", []) or []
        notes = dump.get("notes", []) or []
        attempts = dump.get("extraction_attempts", 0)
        successes = dump.get("successful_extractions", 0)

        if not dump and not accounts:
            summary = "LDAP/AD dump has not run — triggered when ActiveScanner flags LDAP injection."
        else:
            summary = (
                f"fingerprints: {len(fingerprints)}    injections: {len(injections)}    "
                f"accounts: {len(accounts)}    high-value: {len(high_value)}\n"
                f"extraction:   {successes}/{attempts} successful"
            )
            if notes:
                summary += "\n" + "; ".join(str(n) for n in notes[:3])
        self.query_one("#ldap-summary", Static).update(summary)

        fp_t = self.query_one("#ldap-fp-table", DataTable)
        fp_t.clear()
        for fp in fingerprints:
            if not isinstance(fp, dict):
                continue
            fp_t.add_row(
                _join(fp.get("vendor")),
                _join(fp.get("confidence")),
                _join(fp.get("evidence"))[:80],
                _join(fp.get("source_finding"))[:60],
            )

        inj_t = self.query_one("#ldap-inj-table", DataTable)
        inj_t.clear()
        for inj in injections:
            if not isinstance(inj, dict):
                continue
            inj_t.add_row(
                _join(inj.get("endpoint"))[:60],
                _join(inj.get("param")),
                _join(inj.get("baseline_len")),
                _join(inj.get("true_len")),
                _join(inj.get("false_len")),
                _join(inj.get("wildcard_len")),
            )

        acct_t = self.query_one("#ldap-acct-table", DataTable)
        acct_t.clear()
        for a in accounts:
            if not isinstance(a, dict):
                continue
            acct_t.add_row(
                _join(a.get("identifier")),
                _join(a.get("dn"))[:60],
                _join(a.get("tags")),
                _join(a.get("source_endpoint"))[:50],
                _join(a.get("source_param")),
            )

        hv_t = self.query_one("#ldap-hv-table", DataTable)
        hv_t.clear()
        for hv in high_value:
            if not isinstance(hv, dict):
                continue
            hv_t.add_row(
                _join(hv.get("identifier")),
                _join(hv.get("tag")),
                _join(hv.get("evidence"))[:90],
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id or ""
        idx = event.cursor_row
        rows: list = []
        if table_id == "ldap-fp-table":
            rows = self._state.ldap_dump.get("fingerprints", []) if self._state.ldap_dump else []
        elif table_id == "ldap-inj-table":
            rows = self._state.ldap_dump.get("confirmed_injections", []) if self._state.ldap_dump else []
        elif table_id == "ldap-acct-table":
            rows = self._state.ldap_accounts or (
                self._state.ldap_dump.get("accounts", []) if self._state.ldap_dump else []
            )
        elif table_id == "ldap-hv-table":
            rows = self._state.ldap_dump.get("high_value", []) if self._state.ldap_dump else []
        if 0 <= idx < len(rows) and isinstance(rows[idx], dict):
            row = rows[idx]
            lines = []
            for k, v in row.items():
                if isinstance(v, dict):
                    lines.append(f"{k}:")
                    for ak, av in v.items():
                        lines.append(f"  {ak}: {av}")
                else:
                    lines.append(f"{k}: {v}")
            self.query_one("#ldap-detail", TextArea).load_text("\n".join(lines))
