"""Launch ``hxxpsin.py {scan,quick}`` as a subprocess and track it.

Why a subprocess and not an in-process call: the scan pipeline holds
significant state (playwright, httpx clients, file grabbers) and we
want a single MCP server to be able to drive multiple concurrent scans
without those instances colliding. Process isolation also means a
crashed scan cannot kill the MCP server itself.

The MCP server keeps a dict of ``scan_id → Popen`` so it can cancel
in-flight work via SIGTERM. State persists to ``output/<scan_id>/state.json``
through [task_store.py](task_store.py).
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from .task_store import ScanRecord, TaskStore

log = logging.getLogger(__name__)


class ScanRunner:
    """Owns subprocesses for in-flight scans. Thread-safe."""

    def __init__(self, store: TaskStore | None = None, *, hxxpsin_bin: str | None = None) -> None:
        self.store = store or TaskStore()
        self.hxxpsin_bin = hxxpsin_bin or _default_hxxpsin_bin()
        self._procs: dict[str, subprocess.Popen[bytes]] = {}
        self._lock = threading.Lock()

    # -- public API -------------------------------------------------------

    def start(
        self,
        *,
        target: str,
        mode: str = "scan",
        auth: str | None = None,
        active_scan: bool = False,
        solve: bool = False,
        extra_args: list[str] | None = None,
    ) -> ScanRecord:
        if mode not in ("scan", "quick"):
            raise ValueError(f"mode must be 'scan' or 'quick', got {mode!r}")

        rec = self.store.new_scan(
            target=target,
            mode=mode,
            options={
                "auth": auth,
                "active_scan": active_scan,
                "solve": solve,
                "extra_args": list(extra_args or []),
            },
        )

        argv = [self.hxxpsin_bin, mode, target, "--out", rec.out_dir]
        if auth:
            argv += ["--auth", auth]
        if active_scan and mode == "scan":
            argv += ["--active-scan"]
        if solve and mode == "scan":
            argv += ["--solve"]
        argv += list(extra_args or [])

        log_path = Path(rec.out_dir) / "scan.log"
        log_fh = open(log_path, "wb")
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # so SIGTERM cleanly stops the tree
            )
        except FileNotFoundError as e:
            log_fh.close()
            self.store.mark_finished(rec.scan_id, exit_code=127, error=str(e))
            raise

        with self._lock:
            self._procs[rec.scan_id] = proc
        rec = self.store.mark_running(rec.scan_id, pid=proc.pid)

        watcher = threading.Thread(
            target=self._wait_and_finalize,
            args=(rec.scan_id, proc, log_fh),
            daemon=True,
            name=f"scan-watch-{rec.scan_id}",
        )
        watcher.start()
        return rec

    def cancel(self, scan_id: str) -> ScanRecord:
        with self._lock:
            proc = self._procs.get(scan_id)
        if proc is None:
            # Already finished or never owned by this process — fall back to PID kill.
            rec = self.store.get(scan_id)
            if rec.status in ("running", "queued") and rec.pid:
                try:
                    os.killpg(rec.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            return self.store.mark_cancelled(scan_id)

        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        return self.store.mark_cancelled(scan_id)

    # -- internals --------------------------------------------------------

    def _wait_and_finalize(
        self,
        scan_id: str,
        proc: subprocess.Popen[bytes],
        log_fh: Any,
    ) -> None:
        try:
            code = proc.wait()
        except Exception as e:  # pragma: no cover
            log.exception("scan_runner: wait failed for %s: %s", scan_id, e)
            code = -1
        finally:
            try:
                log_fh.close()
            except Exception:
                pass
        with self._lock:
            self._procs.pop(scan_id, None)
        # If the user cancelled, the store status is already 'cancelled' —
        # don't overwrite it with 'failed'.
        try:
            current = self.store.get(scan_id)
        except KeyError:
            return
        if current.status == "cancelled":
            return
        self.store.mark_finished(scan_id, exit_code=code)


def _default_hxxpsin_bin() -> str:
    here = Path(__file__).resolve()
    project_root = here.parents[2]
    candidate = project_root / "hxxpsin.py"
    if candidate.exists():
        return str(candidate)
    # Fallback — invoke main.py via the current interpreter
    return sys.executable
