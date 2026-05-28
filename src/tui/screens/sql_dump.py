"""DB Dump tab — SQL dump viewer (fingerprints, schema, extracted rows)."""
from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static, TabbedContent, TabPane, TextArea

from ..state import AppState


_FP_COLS = ["dialect", "confidence", "evidence", "source_finding"]
_SCHEMA_COLS = ["table", "columns"]
_TABLES_COLS = ["table", "rows"]


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:6])
    if v is None:
        return ""
    return str(v)


class SQLDumpScreen(Vertical):
    """SQL dump viewer: dialect fingerprints, schema, dumped rows."""

    DEFAULT_CSS = """
    SQLDumpScreen { height: 1fr; }
    SQLDumpScreen #sqldump-summary { height: 5; padding: 0 1; background: $surface-darken-1; }
    SQLDumpScreen DataTable { height: 1fr; }
    SQLDumpScreen #sqldump-detail { height: 12; border-top: solid $primary; padding: 0 1; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._selected_table: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("", id="sqldump-summary")
        with TabbedContent():
            with TabPane("Fingerprints", id="sqldump-fp"):
                yield DataTable(id="sqldump-fp-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Schema", id="sqldump-schema"):
                yield DataTable(id="sqldump-schema-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Data", id="sqldump-data"):
                yield DataTable(id="sqldump-tables-table", cursor_type="row", zebra_stripes=True)
        yield TextArea("", id="sqldump-detail", read_only=True)

    def on_mount(self) -> None:
        self.query_one("#sqldump-fp-table", DataTable).add_columns(*_FP_COLS)
        self.query_one("#sqldump-schema-table", DataTable).add_columns(*_SCHEMA_COLS)
        self.query_one("#sqldump-tables-table", DataTable).add_columns(*_TABLES_COLS)
        self.refresh_data()

    def refresh_data(self) -> None:
        dump = self._state.sql_dump or {}
        fingerprints = dump.get("fingerprints", []) or []
        schema = dump.get("schema", []) or []
        notes = dump.get("notes", []) or []
        rows_dumped = dump.get("rows_dumped", 0)
        tables_dumped = dump.get("tables_dumped", 0)
        out_dir = dump.get("out_dir", "")
        rows_by_table = self._state.sql_dump_rows or {}

        if not dump and not rows_by_table:
            summary = (
                "SQL dump has not run — triggered when ActiveScanner confirms a "
                "SQLi finding with output extraction."
            )
        else:
            dialects = ", ".join(
                f"{fp.get('dialect','?')} ({fp.get('confidence',0):.2f})"
                for fp in fingerprints if isinstance(fp, dict)
            ) or "—"
            summary = (
                f"dialects:  {dialects}\n"
                f"schema:    {len(schema)} tables discovered\n"
                f"dumped:    {tables_dumped} tables, {rows_dumped} rows  →  {out_dir}"
            )
            if notes:
                summary += "\n" + "; ".join(str(n) for n in notes[:3])
        self.query_one("#sqldump-summary", Static).update(summary)

        fp_t = self.query_one("#sqldump-fp-table", DataTable)
        fp_t.clear()
        for fp in fingerprints:
            if not isinstance(fp, dict):
                continue
            fp_t.add_row(
                _join(fp.get("dialect")),
                f"{fp.get('confidence', 0):.2f}",
                _join(fp.get("evidence"))[:80],
                _join(fp.get("source_finding"))[:60],
            )

        schema_t = self.query_one("#sqldump-schema-table", DataTable)
        schema_t.clear()
        for t in schema:
            if not isinstance(t, dict):
                continue
            cols = t.get("columns") or []
            schema_t.add_row(
                _join(t.get("name")),
                _join(cols)[:120] if cols else "—",
            )

        tables_t = self.query_one("#sqldump-tables-table", DataTable)
        tables_t.clear()
        for table_name, rows in sorted(rows_by_table.items()):
            tables_t.add_row(table_name, str(len(rows)))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id or ""
        idx = event.cursor_row
        detail = self.query_one("#sqldump-detail", TextArea)
        dump = self._state.sql_dump or {}

        if table_id == "sqldump-fp-table":
            rows = dump.get("fingerprints", []) or []
            if 0 <= idx < len(rows) and isinstance(rows[idx], dict):
                detail.load_text(_pretty(rows[idx]))
        elif table_id == "sqldump-schema-table":
            rows = dump.get("schema", []) or []
            if 0 <= idx < len(rows) and isinstance(rows[idx], dict):
                detail.load_text(_pretty(rows[idx]))
        elif table_id == "sqldump-tables-table":
            names = sorted((self._state.sql_dump_rows or {}).keys())
            if 0 <= idx < len(names):
                table = names[idx]
                rows = self._state.sql_dump_rows.get(table, [])
                payload = [r.get("row", r) if isinstance(r, dict) else r for r in rows]
                detail.load_text(
                    f"# {table} ({len(payload)} rows)\n\n"
                    + json.dumps(payload, indent=2, default=str)
                )


def _pretty(row: dict) -> str:
    lines = []
    for k, v in row.items():
        if isinstance(v, (dict, list)):
            lines.append(f"{k}:")
            lines.append("  " + json.dumps(v, indent=2, default=str).replace("\n", "\n  "))
        else:
            lines.append(f"{k}: {v}")
    return "\n".join(lines)
