"""
canary.py — Out-of-band callback tracker (Burp Collaborator equivalent).

Wraps the interactsh-client binary when available. Falls back gracefully:
  Canary.available == False  →  generate() returns ""  →  callers skip OOB probes.

Usage:
    async with await Canary.create() as c:
        if c.available:
            url = c.generate("ssrf-probe")      # http://abc123-ssrf.oast.live
            # ... send probe containing url ...
            hits = await c.poll(timeout=8.0)    # [CanaryHit(...), ...]
"""

import asyncio
import json
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CanaryHit:
    tag: str                    # tag passed to generate()
    domain: str                 # subdomain that received the callback
    protocol: str               # "dns" | "http" | "smtp"
    remote_address: str         # source IP of the callback
    timestamp: float            # epoch seconds
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tag": self.tag,
            "domain": self.domain,
            "protocol": self.protocol,
            "remote_address": self.remote_address,
            "timestamp": self.timestamp,
        }


@dataclass
class CanarySession:
    server_url: str
    correlation_id: str
    secret_key: str


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _interactsh_available() -> bool:
    return shutil.which("interactsh-client") is not None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class Canary:
    """
    OOB callback tracker.

    When interactsh-client is not in PATH, the instance is created with
    available=False and all operations are no-ops.
    """

    def __init__(self) -> None:
        self.available: bool = False
        self._session: Optional[CanarySession] = None
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._tag_map: dict[str, str] = {}   # subdomain_prefix → tag
        self._hit_buffer: list[CanaryHit] = []
        self._reader_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    async def create(cls, mode: str = "interactsh", oob_domain: str = "") -> "Canary":
        """
        Start an interactsh session or mark unavailable.
        mode: "interactsh" | "domain" | "disabled"
        """
        c = cls()
        if mode == "disabled":
            return c

        if mode == "domain" and oob_domain:
            # Static domain mode — generate subdomains, no polling
            c._session = CanarySession(
                server_url=oob_domain,
                correlation_id="",
                secret_key="",
            )
            c.available = True
            return c

        # interactsh mode
        if not _interactsh_available():
            return c

        try:
            proc = await asyncio.create_subprocess_exec(
                "interactsh-client",
                "-json",
                "-o", "/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            c._proc = proc

            # Read the first JSON line — interactsh prints its session info on start
            session_line = await asyncio.wait_for(proc.stdout.readline(), timeout=10.0)
            session_data = json.loads(session_line.decode())

            c._session = CanarySession(
                server_url=session_data.get("server", "oast.live"),
                correlation_id=session_data.get("correlation-id", ""),
                secret_key=session_data.get("secret-key", ""),
            )
            c.available = True
            c._reader_task = asyncio.create_task(c._read_loop())
        except Exception:
            # Any failure → degrade silently
            if c._proc:
                try:
                    c._proc.kill()
                except Exception:
                    pass
                c._proc = None

        return c

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def generate(self, tag: str) -> str:
        """
        Return a unique OOB URL for the given tag.
        Returns "" when unavailable — callers must check: `if url := c.generate("x")`
        """
        if not self.available or not self._session:
            return ""
        prefix = uuid.uuid4().hex[:8]
        slug = re.sub(r"[^a-z0-9-]", "-", tag.lower())[:20]
        subdomain = f"{prefix}-{slug}"
        self._tag_map[prefix] = tag
        return f"http://{subdomain}.{self._session.server_url}"

    async def poll(self, timeout: float = 10.0) -> list[CanaryHit]:
        """
        Return any hits received since the last poll. Non-blocking if none.
        Waits up to `timeout` seconds for the first hit, then drains the buffer.
        """
        if not self.available:
            return []

        deadline = time.monotonic() + timeout
        while not self._hit_buffer and time.monotonic() < deadline:
            await asyncio.sleep(0.25)

        hits = list(self._hit_buffer)
        self._hit_buffer.clear()
        return hits

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Canary":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal reader loop
    # ------------------------------------------------------------------

    async def _read_loop(self) -> None:
        """Continuously read JSON lines from interactsh-client stdout."""
        if not self._proc or not self._proc.stdout:
            return
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    break
                try:
                    event = json.loads(line.decode())
                    hit = self._parse_event(event)
                    if hit:
                        self._hit_buffer.append(hit)
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass

    def _parse_event(self, event: dict) -> Optional[CanaryHit]:
        """Convert an interactsh JSON event into a CanaryHit."""
        domain = event.get("full-id", event.get("unique-id", ""))
        if not domain:
            return None

        # Resolve tag from subdomain prefix
        prefix = domain.split(".")[0].split("-")[0] if "-" in domain.split(".")[0] else domain.split(".")[0]
        tag = self._tag_map.get(prefix, "unknown")

        return CanaryHit(
            tag=tag,
            domain=domain,
            protocol=event.get("protocol", "dns"),
            remote_address=event.get("remote-address", ""),
            timestamp=time.time(),
            raw=event,
        )
