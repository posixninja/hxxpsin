"""
tunnel.py — Public tunnel backends for the payload server.

Exposes a local HTTP server (see payload_server.py) at a publicly reachable
URL so targets can call back into it during SSRF / XXE / upload-callback /
open-redirect testing.

Three backends, one interface:

  CloudflaredTunnel — wraps `cloudflared tunnel --url http://localhost:PORT`.
                      No auth required — uses TryCloudflare's random
                      *.trycloudflare.com subdomain. Recommended default.

  NgrokTunnel       — wraps `ngrok http PORT --log=stdout --log-format=json`.
                      Requires `auth_token`. Reads the public URL from ngrok's
                      local API at http://127.0.0.1:4040/api/tunnels.

  StaticTunnel      — no subprocess. Operator runs their own VPS-hosted
                      callback at a stable URL (declared in config). Most
                      reliable for serious engagements.

  NullTunnel        — disabled. Returns None for the public URL. Probes that
                      need callback URLs gracefully skip OOB tests.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# Status object
# ---------------------------------------------------------------------------


@dataclass
class TunnelStatus:
    """Current state of a tunnel — surfaced to the operator + reporter."""
    backend: str
    public_url: Optional[str]
    local_url: str
    started_at: float
    pid: Optional[int] = None
    note: str = ""


class TunnelError(Exception):
    """Raised when a tunnel can't be brought up. Probes should fall back."""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class Tunnel(ABC):
    """Base class — async context manager that yields a public URL."""

    backend_name: str = "abstract"

    def __init__(self, local_url: str):
        self.local_url = local_url.rstrip("/")
        self.public_url: Optional[str] = None
        self.started_at: float = 0.0

    async def __aenter__(self) -> "Tunnel":
        try:
            await self.start()
        except TunnelError:
            # Don't propagate — caller checks .public_url
            pass
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    @abstractmethod
    async def start(self) -> Optional[str]:
        """Bring the tunnel up. Returns the public URL, or None on failure."""

    @abstractmethod
    async def stop(self) -> None:
        """Tear the tunnel down cleanly."""

    def status(self) -> TunnelStatus:
        return TunnelStatus(
            backend=self.backend_name,
            public_url=self.public_url,
            local_url=self.local_url,
            started_at=self.started_at,
        )


# ---------------------------------------------------------------------------
# Cloudflare Tunnel (TryCloudflare) — zero-config default
# ---------------------------------------------------------------------------


_TRYCLOUDFLARE_URL_RE = re.compile(
    r"https://[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE,
)


class CloudflaredTunnel(Tunnel):
    """Spawns `cloudflared tunnel --url <local>`. Parses the random
    trycloudflare.com URL out of stderr within ~20s of startup."""

    backend_name = "cloudflared"

    def __init__(self, local_url: str, binary: str = "cloudflared",
                 startup_timeout: float = 25.0):
        super().__init__(local_url)
        self.binary = binary
        self.startup_timeout = startup_timeout
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._stderr_buf: list[str] = []

    async def start(self) -> Optional[str]:
        if not shutil.which(self.binary):
            raise TunnelError(
                f"cloudflared binary not found on PATH (looked for '{self.binary}'). "
                f"Install: https://developers.cloudflare.com/cloudflared/"
            )

        self._proc = await asyncio.create_subprocess_exec(
            self.binary, "tunnel", "--no-autoupdate", "--url", self.local_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.started_at = time.time()

        # cloudflared prints the trycloudflare URL on stderr
        self._stderr_task = asyncio.create_task(self._consume_stream(self._proc.stderr))
        _stdout_task = asyncio.create_task(self._consume_stream(self._proc.stdout))

        # Poll our buffer for the URL
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self._proc.returncode is not None:
                raise TunnelError(
                    f"cloudflared exited early (code={self._proc.returncode}): "
                    f"{''.join(self._stderr_buf)[-400:]}"
                )
            for line in self._stderr_buf:
                m = _TRYCLOUDFLARE_URL_RE.search(line)
                if m:
                    self.public_url = m.group(0)
                    return self.public_url
            await asyncio.sleep(0.4)

        # Timed out — kill the process and report
        await self.stop()
        raise TunnelError(
            f"cloudflared did not surface a trycloudflare URL within "
            f"{self.startup_timeout:.0f}s"
        )

    async def _consume_stream(self, stream) -> None:
        """Drain stdout/stderr into a rolling buffer so we can grep for the URL
        and surface diagnostics on error."""
        while True:
            try:
                line = await stream.readline()
            except (asyncio.CancelledError, ValueError):
                return
            if not line:
                return
            text = line.decode(errors="replace")
            self._stderr_buf.append(text)
            if len(self._stderr_buf) > 200:
                self._stderr_buf = self._stderr_buf[-100:]

    async def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.returncode is None:
            try:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
            except ProcessLookupError:
                pass
        if self._stderr_task:
            self._stderr_task.cancel()
        self._proc = None


# ---------------------------------------------------------------------------
# ngrok — paid/free with account
# ---------------------------------------------------------------------------


class NgrokTunnel(Tunnel):
    """Spawns `ngrok http PORT --log=stdout --log-format=json`, then reads the
    public URL from the ngrok agent's local API."""

    backend_name = "ngrok"
    AGENT_API = "http://127.0.0.1:4040/api/tunnels"

    def __init__(self, local_url: str, binary: str = "ngrok",
                 auth_token: Optional[str] = None,
                 region: Optional[str] = None,
                 startup_timeout: float = 20.0):
        super().__init__(local_url)
        self.binary = binary
        self.auth_token = auth_token
        self.region = region
        self.startup_timeout = startup_timeout
        self._proc: Optional[asyncio.subprocess.Process] = None

    @staticmethod
    def _parse_port(local_url: str) -> int:
        """Extract just the port — ngrok takes `ngrok http PORT`, not a URL."""
        from urllib.parse import urlparse
        p = urlparse(local_url)
        if p.port:
            return p.port
        return 80 if p.scheme == "http" else 443

    async def start(self) -> Optional[str]:
        if not shutil.which(self.binary):
            raise TunnelError(
                f"ngrok binary not found on PATH (looked for '{self.binary}'). "
                f"Install: https://ngrok.com/download"
            )
        if not self.auth_token:
            raise TunnelError(
                "ngrok requires auth_token — set [tunnel].auth_token in config "
                "or HXXPSIN_TUNNEL_AUTH_TOKEN env var"
            )

        port = self._parse_port(self.local_url)
        args = [self.binary, "http", str(port),
                "--authtoken", self.auth_token,
                "--log", "stdout", "--log-format", "json"]
        if self.region:
            args.extend(["--region", self.region])

        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.started_at = time.time()

        # Poll local agent API for the tunnel's public URL
        deadline = time.monotonic() + self.startup_timeout
        async with httpx.AsyncClient(timeout=2.0) as client:
            while time.monotonic() < deadline:
                if self._proc.returncode is not None:
                    raise TunnelError(f"ngrok exited (code={self._proc.returncode})")
                try:
                    r = await client.get(self.AGENT_API)
                    if r.status_code == 200:
                        data = r.json()
                        for t in data.get("tunnels", []):
                            url = t.get("public_url", "")
                            if url.startswith("https://"):
                                self.public_url = url
                                return url
                except (httpx.HTTPError, json.JSONDecodeError):
                    pass
                await asyncio.sleep(0.4)

        await self.stop()
        raise TunnelError(f"ngrok agent did not expose a tunnel within {self.startup_timeout:.0f}s")

    async def stop(self) -> None:
        if self._proc is None or self._proc.returncode is not None:
            self._proc = None
            return
        try:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        except ProcessLookupError:
            pass
        self._proc = None


# ---------------------------------------------------------------------------
# Static — operator runs their own callback host
# ---------------------------------------------------------------------------


class StaticTunnel(Tunnel):
    """No subprocess. Operator declares a stable public URL pointing at a
    callback they run themselves (VPS + nginx, Cloudflare Workers, etc.).

    NOTE: This tunnel does NOT forward to local_url. The operator is
    responsible for making sure their declared URL routes back to the same
    payload_server instance — typically via SSH reverse tunnel or wireguard."""

    backend_name = "static"

    def __init__(self, local_url: str, public_url: str):
        super().__init__(local_url)
        if not public_url:
            raise TunnelError("StaticTunnel requires a non-empty public_url")
        self._configured_url = public_url.rstrip("/")

    async def start(self) -> Optional[str]:
        self.public_url = self._configured_url
        self.started_at = time.time()
        return self.public_url

    async def stop(self) -> None:
        return


# ---------------------------------------------------------------------------
# Null / disabled
# ---------------------------------------------------------------------------


class NullTunnel(Tunnel):
    """No-op. Returns None for public_url. Used when operator has disabled
    OOB callbacks entirely via [tunnel].backend = 'none'."""

    backend_name = "none"

    async def start(self) -> Optional[str]:
        self.public_url = None
        return None

    async def stop(self) -> None:
        return


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def from_profile(profile, local_url: str) -> Tunnel:
    """Build a Tunnel from an auth_config.TunnelProfile + the local server's URL."""
    backend = (profile.backend or "cloudflared").lower()
    if backend == "none":
        return NullTunnel(local_url=local_url)
    if backend == "cloudflared":
        return CloudflaredTunnel(local_url=local_url, binary=profile.binary or "cloudflared")
    if backend == "ngrok":
        return NgrokTunnel(
            local_url=local_url, binary=profile.binary or "ngrok",
            auth_token=profile.auth_token, region=profile.region,
        )
    if backend == "static":
        return StaticTunnel(local_url=local_url, public_url=profile.public_url or "")
    raise TunnelError(f"unknown tunnel backend: {profile.backend!r}")
