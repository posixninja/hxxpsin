"""Optional supervisor for the servus assistant daemon.

hxxpsin can't call an LLM without servus (`secretarius.server.
assistant_http_app`), so when the operator hits the chat panel and
servus isn't listening, we spawn it instead of bouncing them back with
a 401. We only own the subprocess if WE started it — if servus was
already up, we leave it alone on TUI exit.

Resolution order for the launcher:

1. ``$SERVUS_LAUNCH_CMD`` — operator-provided shell command (highest trust).
2. ``$SERVUS_REPO/securisnexus/run-assistant.sh`` if executable.
3. ``$SERVUS_REPO`` + ``python -m secretarius.server.assistant_http_app``.
4. ``~/Desktop/Projects/servus/securisnexus/run-assistant.sh`` (this box's
   default install path).
5. ``~/Desktop/Projects/servus`` + ``python -m secretarius.server.…``.

Probe target is ``$SERVUS_ASSISTANT_URL/health`` (default
``http://127.0.0.1:9847/health``) — the same URL ServusLLMClient reads.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


log = logging.getLogger(__name__)


_DEFAULT_URL = "http://127.0.0.1:9847"
_DEFAULT_SERVUS_REPO = Path.home() / "Desktop" / "Projects" / "servus"
_HEALTH_TIMEOUT_S = 2.0


@dataclass
class ServusStatus:
    running: bool
    owned: bool          # True if WE spawned it this session
    url: str
    pid: int | None = None
    message: str = ""


def base_url() -> str:
    return (os.environ.get("SERVUS_ASSISTANT_URL") or _DEFAULT_URL).rstrip("/")


def is_running(url: str | None = None, *, timeout: float = _HEALTH_TIMEOUT_S) -> bool:
    """GET <url>/health and return True on a 2xx response."""
    target = (url or base_url()).rstrip("/") + "/health"
    req = urllib.request.Request(target, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return False


def _resolve_launch() -> tuple[list[str], Path] | None:
    """Return (argv, cwd) for the best launcher we can find, or None."""
    cmd = os.environ.get("SERVUS_LAUNCH_CMD")
    if cmd:
        return shlex.split(cmd), Path.cwd()

    repo_env = os.environ.get("SERVUS_REPO")
    candidate_repos = [Path(repo_env)] if repo_env else []
    candidate_repos.append(_DEFAULT_SERVUS_REPO)

    for repo in candidate_repos:
        if not repo.is_dir():
            continue
        sh = repo / "securisnexus" / "run-assistant.sh"
        if sh.is_file() and os.access(sh, os.X_OK):
            return [str(sh)], repo
        # Fallback to direct module invocation
        py = repo / ".venv" / "bin" / "python3"
        python = str(py) if py.exists() else sys.executable
        return (
            [python, "-m", "secretarius.server.assistant_http_app",
             "--host", "127.0.0.1", "--port", _port_from(base_url())],
            repo,
        )
    return None


def _port_from(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return str(p.port or 9847)
    except Exception:
        return "9847"


class ServusSupervisor:
    """Stateful: remembers whether we spawned the daemon so we know if
    we should stop it on shutdown."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._url = base_url()
        self._log_path: Path | None = None

    # -- queries ----------------------------------------------------------

    def status(self) -> ServusStatus:
        return ServusStatus(
            running=is_running(self._url),
            owned=self._proc is not None and self._proc.poll() is None,
            url=self._url,
            pid=self._proc.pid if self._proc and self._proc.poll() is None else None,
        )

    # -- lifecycle --------------------------------------------------------

    def ensure_running(self, *, wait_s: float = 12.0) -> ServusStatus:
        """If servus is up, no-op. Otherwise spawn the launcher and wait
        for /health to become 200. Returns a status snapshot."""
        if is_running(self._url):
            return ServusStatus(running=True, owned=False, url=self._url,
                                message="already running")

        launch = _resolve_launch()
        if launch is None:
            return ServusStatus(
                running=False, owned=False, url=self._url,
                message=(
                    "no servus launcher found. Set $SERVUS_LAUNCH_CMD, "
                    "$SERVUS_REPO, or install servus at "
                    f"{_DEFAULT_SERVUS_REPO}."
                ),
            )

        argv, cwd = launch
        # Capture stderr to a file the operator can tail if startup hangs.
        log_dir = Path.home() / ".cache" / "hxxpsin"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = log_dir / "servus.log"
            log_fh = open(self._log_path, "ab", buffering=0)
        except Exception:
            self._log_path = None
            log_fh = subprocess.DEVNULL

        try:
            self._proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=log_fh,
                start_new_session=True,
                env=dict(os.environ),
            )
        except Exception as e:
            return ServusStatus(
                running=False, owned=False, url=self._url,
                message=f"failed to spawn servus: {type(e).__name__}: {e}",
            )

        # Poll /health until ready or timed out.
        deadline = time.monotonic() + wait_s
        last_err = "no response"
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                tail = self._read_log_tail()
                return ServusStatus(
                    running=False, owned=False, url=self._url,
                    message=f"servus exited during startup (rc={self._proc.returncode}). {tail}",
                )
            if is_running(self._url, timeout=1.0):
                return ServusStatus(
                    running=True, owned=True, url=self._url,
                    pid=self._proc.pid,
                    message=f"spawned (pid={self._proc.pid})"
                            + (f", log: {self._log_path}" if self._log_path else ""),
                )
            time.sleep(0.4)
            last_err = "still not responding"

        # Timed out — leave the subprocess running so the operator can
        # debug it manually, but report failure.
        return ServusStatus(
            running=False, owned=True, url=self._url,
            pid=self._proc.pid,
            message=(
                f"servus pid={self._proc.pid} did not respond at {self._url}/health "
                f"within {wait_s:.0f}s ({last_err}). "
                + (f"Check {self._log_path}." if self._log_path else "")
            ),
        )

    def stop(self) -> None:
        """Stop ONLY if we spawned it. Pre-existing servus stays up."""
        if self._proc is None:
            return
        if self._proc.poll() is None:
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except Exception:
                pass
        self._proc = None

    # -- helpers ----------------------------------------------------------

    def _read_log_tail(self, max_bytes: int = 1024) -> str:
        if not self._log_path or not self._log_path.exists():
            return ""
        try:
            data = self._log_path.read_bytes()
            return f"log tail: {data[-max_bytes:].decode(errors='replace')}"
        except Exception:
            return ""


__all__ = ["ServusStatus", "ServusSupervisor", "base_url", "is_running"]
