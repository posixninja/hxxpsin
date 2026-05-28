"""Disk-backed task ledger for long-running scans launched over MCP.

A scan can run 5–30 minutes; we don't want the MCP process to hold all
its state in memory (the host may restart it, or another caller may
list/poll mid-flight). Each scan gets a directory under ``output/`` and
a ``state.json`` we treat as the source of truth.

Layout::

    output/
      <scan_id>/
        state.json          ← this module's ledger (status, started_at, …)
        scan.log            ← stderr/stdout of the scan subprocess
        report.md           ← written by reporter.py once the scan completes
        report.json
        …other hxxpsin artifacts…

``scan_id`` shape: ``<host-safe>-<YYYYMMDD-HHMMSS>-<rand4>`` so multiple
scans against the same host can co-exist.
"""

from __future__ import annotations

import json
import os
import os as _os_for_rand
import binascii as _binascii_for_rand
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")


@dataclass
class ScanRecord:
    scan_id: str
    target: str
    mode: str  # "scan" | "quick"
    out_dir: str
    pid: int | None
    status: str  # one of SCAN_STATUSES
    started_at: float
    finished_at: float | None
    exit_code: int | None
    options: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["started_at_iso"] = datetime.fromtimestamp(self.started_at).isoformat()
        if self.finished_at:
            d["finished_at_iso"] = datetime.fromtimestamp(self.finished_at).isoformat()
        return d


class TaskStore:
    """All operations are file-locked-by-rename — single process, multi-thread safe.

    For multi-process safety (e.g. an MCP server restart while a scan
    subprocess still owns ``state.json``), the subprocess only writes
    its OWN state.json on completion, and never racing with us because
    we only mutate ``status`` from this object.
    """

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root) if root else _default_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- new scans --------------------------------------------------------

    def new_scan(self, *, target: str, mode: str, options: dict[str, Any] | None = None) -> ScanRecord:
        scan_id = _mint_scan_id(target)
        out_dir = self.root / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        rec = ScanRecord(
            scan_id=scan_id,
            target=target,
            mode=mode,
            out_dir=str(out_dir),
            pid=None,
            status="queued",
            started_at=time.time(),
            finished_at=None,
            exit_code=None,
            options=dict(options or {}),
        )
        self._write(rec)
        return rec

    # -- mutations --------------------------------------------------------

    def mark_running(self, scan_id: str, pid: int) -> ScanRecord:
        return self._mutate(scan_id, status="running", pid=pid)

    def mark_finished(self, scan_id: str, *, exit_code: int, error: str | None = None) -> ScanRecord:
        status = "completed" if exit_code == 0 else "failed"
        return self._mutate(
            scan_id,
            status=status,
            finished_at=time.time(),
            exit_code=exit_code,
            error=error,
        )

    def mark_cancelled(self, scan_id: str) -> ScanRecord:
        return self._mutate(scan_id, status="cancelled", finished_at=time.time())

    # -- reads ------------------------------------------------------------

    def get(self, scan_id: str) -> ScanRecord:
        path = self._state_path(scan_id)
        if not path.exists():
            raise KeyError(f"no such scan: {scan_id}")
        return _record_from_file(path)

    def list(self, *, limit: int = 50) -> list[ScanRecord]:
        rows: list[ScanRecord] = []
        for entry in sorted(self.root.iterdir(), key=lambda p: p.name, reverse=True):
            sp = entry / "state.json"
            if not sp.exists():
                continue
            try:
                rows.append(_record_from_file(sp))
            except Exception:
                continue
            if len(rows) >= limit:
                break
        return rows

    # -- internals --------------------------------------------------------

    def _state_path(self, scan_id: str) -> Path:
        return self.root / scan_id / "state.json"

    def _write(self, rec: ScanRecord) -> None:
        path = self._state_path(rec.scan_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(rec.to_dict(), indent=2))
        os.replace(tmp, path)

    def _mutate(self, scan_id: str, **changes: Any) -> ScanRecord:
        with self._lock:
            rec = self.get(scan_id)
            for k, v in changes.items():
                setattr(rec, k, v)
            self._write(rec)
            return rec


def _default_root() -> Path:
    """Project-level output directory. Mirrors what ``hxxpsin.py`` uses."""
    here = Path(__file__).resolve()
    project_root = here.parents[2]  # src/mcp_agent/task_store.py → project root
    return project_root / "output"


def _mint_scan_id(target: str) -> str:
    host = (urlparse(target).hostname or "target").replace(":", "_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    # hxxpsin has a local module `src/secrets.py` that shadows the stdlib
    # `secrets` module when src/ is on sys.path. Use os.urandom + binascii
    # to mint the token-hex equivalent without touching that namespace.
    rand = _binascii_for_rand.hexlify(_os_for_rand.urandom(2)).decode()
    return f"{host}-{ts}-{rand}"


def _record_from_file(path: Path) -> ScanRecord:
    data = json.loads(path.read_text())
    # Strip derived fields before instantiating the dataclass
    data.pop("started_at_iso", None)
    data.pop("finished_at_iso", None)
    return ScanRecord(**data)
