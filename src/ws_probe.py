"""
WebSocket security probe for hxxpsin.

Active tests run against every discovered WebSocket URL:
  1. CSWSH  — connect with spoofed Origin (https://evil.example.com)
              while keeping auth cookies; 101 → server ignores Origin
  2. Unauth — connect without any auth token or session cookie;
              101 when auth_headers are known → endpoint is publicly accessible
  3. Null origin — Origin: null (sandboxed iframe / file:// context)
  4. Subscription IDOR — replay captured subscribe/join frames with a
              different channel/room ID than the one legitimately observed

All checks use raw asyncio TCP so no extra Python dependencies are needed.
WS URLs are gathered from the crawler's passively-captured connections,
JS bundle extraction, and stackprint's JS scan.
"""

import asyncio
import base64
import json
import os
import re
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WSProbeResult:
    urls_tested: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def confirmed(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") in ("high", "medium")]

    def to_dict(self) -> dict:
        return {
            "urls_tested": self.urls_tested,
            "findings": self.findings,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class WSProbe:
    def __init__(self, auth_headers: dict = None, timeout: float = 8.0):
        self._auth = auth_headers or {}
        self._timeout = min(timeout, 10.0)

    async def run(
        self,
        ws_urls: list[str],
        captured_websockets=None,
        http_origins: list[str] = None,
    ) -> WSProbeResult:
        """
        ws_urls: WS URLs gathered from crawler, JS analysis, stackprint.
        captured_websockets: list[CapturedWebSocket] from collector.
        http_origins: HTTP origins (e.g. http://localhost:3000) to probe for
                      Socket.io endpoints even if no WS URL was captured.
        """
        result = WSProbeResult()

        # Normalise and deduplicate input WS URLs
        seen: set[str] = set()
        unique: list[str] = []
        for raw in ws_urls:
            url = raw.strip()
            if not url:
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("ws", "wss"):
                continue
            # For Socket.io URLs with sid=, strip to canonical base so we
            # handle one canonical URL per Socket.io endpoint (we'll get a
            # fresh sid for each probe attempt).
            canonical = _socketio_canonical(url) if _is_socketio_url(url) else url
            if canonical not in seen:
                seen.add(canonical)
                unique.append(canonical)

        # Probe HTTP origins for Socket.io even if nothing was passively captured
        if http_origins:
            for origin in http_origins[:5]:
                sio_url = await self._discover_socketio(origin)
                if sio_url and sio_url not in seen:
                    seen.add(sio_url)
                    unique.append(sio_url)

        if not unique:
            return result

        captured = captured_websockets or []
        tasks = [
            self._probe_one(url, captured, result)
            for url in unique[:12]
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return result

    async def _discover_socketio(self, http_origin: str) -> Optional[str]:
        """GET /socket.io/?EIO=4&transport=polling to see if Socket.io is present.
        Returns the canonical WS URL (without sid) if detected, else None."""
        import httpx
        try:
            url = http_origin.rstrip("/") + "/socket.io/?EIO=4&transport=polling"
            async with httpx.AsyncClient(verify=False, timeout=4.0,
                                         follow_redirects=True) as client:
                resp = await client.get(url, headers=dict(self._auth))
            if resp.status_code != 200:
                return None
            # Socket.io responds with a JSON handshake: 0{...}
            text = resp.text
            if not text.startswith("0{") and "sid" not in text:
                return None
            ws_scheme = "wss" if http_origin.startswith("https") else "ws"
            parsed = urlparse(http_origin)
            return f"{ws_scheme}://{parsed.netloc}/socket.io/?EIO=4&transport=websocket"
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Per-URL orchestration
    # ------------------------------------------------------------------

    async def _probe_one(self, url: str, captured: list, result: WSProbeResult) -> None:
        result.urls_tested.append(url)

        # Socket.io endpoints need a session handshake before each WS upgrade.
        # Provide a factory function so each test can get its own fresh sid.
        is_sio = _is_socketio_url(url)
        if is_sio:
            # Pre-check: confirm Socket.io responds at all before running subtests
            sid = await self._get_socketio_sid(url, use_auth=True)
            if sid is None:
                result.errors.append({
                    "url": url, "test": "socketio_connect",
                    "note": "Socket.io session handshake failed — cannot probe this endpoint",
                })
                return

        # Gather frames the crawler passively observed for this URL
        sent_frames: list[dict] = []
        for ws in captured:
            if ws.url == url:
                sent_frames = ws.messages_sent
                break
            # Match Socket.io URLs loosely (sid will differ)
            if is_sio and _is_socketio_url(ws.url) and _sio_base(ws.url) == _sio_base(url):
                sent_frames = ws.messages_sent
                break

        tests = [
            self._test_cswsh(url, result),
            self._test_null_origin(url, result),
        ]
        if self._auth:
            tests.append(self._test_unauth(url, result))

        await asyncio.gather(*tests, return_exceptions=True)

        if sent_frames:
            await self._test_sub_idor(url, sent_frames, result)

    # ------------------------------------------------------------------
    # Individual tests
    # ------------------------------------------------------------------

    async def _test_cswsh(self, url: str, result: WSProbeResult) -> None:
        """Upgrade with attacker Origin but with any known auth cookies.
        If the server returns 101 it doesn't validate the Origin header —
        a page on evil.example.com could connect as the victim."""
        evil_origin = "https://evil.example.com"
        extra = {}
        if "Cookie" in self._auth:
            extra["Cookie"] = self._auth["Cookie"]
        elif "cookie" in self._auth:
            extra["Cookie"] = self._auth["cookie"]

        probe_url = url
        if _is_socketio_url(url):
            sid = await self._get_socketio_sid(url, use_auth=True)
            if sid is None:
                return
            probe_url = _inject_sid(url, sid)

        ok, status = await self._upgrade(probe_url, extra_headers=extra, origin=evil_origin)
        if ok:
            result.findings.append({
                "category": "cross_site_websocket_hijacking",
                "severity": "high",
                "url": url,
                "evidence": (
                    f"WebSocket upgrade accepted (101) with Origin: {evil_origin}. "
                    "Server does not validate the Origin header."
                ),
                "impact": (
                    "An attacker-controlled page can establish a WebSocket using "
                    "the victim's session cookies (no token exfiltration needed)."
                ),
                "cwe": "CWE-346",
            })
        elif status not in (-1, -2):
            # Server rejected — note it for coverage visibility
            result.errors.append({
                "url": url, "test": "cswsh",
                "note": f"upgrade rejected (HTTP {status}) — not vulnerable",
            })

    async def _test_null_origin(self, url: str, result: WSProbeResult) -> None:
        """Origin: null is produced by sandboxed iframes and file:// pages.
        Some servers allow it as a special-case; others forget to block it."""
        probe_url = url
        if _is_socketio_url(url):
            sid = await self._get_socketio_sid(url, use_auth=True)
            if sid is None:
                return
            probe_url = _inject_sid(url, sid)

        ok, status = await self._upgrade(probe_url, origin="null")
        if ok:
            result.findings.append({
                "category": "null_origin_websocket",
                "severity": "medium",
                "url": url,
                "evidence": (
                    "WebSocket upgrade accepted (101) with Origin: null. "
                    "Connections from sandboxed iframes or file:// contexts are allowed."
                ),
                "impact": (
                    "Sandboxed content (data-URI iframes, local HTML files) can "
                    "interact with this WebSocket endpoint."
                ),
                "cwe": "CWE-346",
            })

    async def _test_unauth(self, url: str, result: WSProbeResult) -> None:
        """Connect with no auth headers at all. If the server returns 101
        when the scan is running authenticated, the WS endpoint is publicly
        accessible and authentication is not enforced."""
        probe_url = url
        if _is_socketio_url(url):
            # Get a sid WITHOUT auth headers — if polling itself requires auth
            # we'll get None and skip, which is the correct behaviour.
            sid = await self._get_socketio_sid(url, use_auth=False)
            if sid is None:
                # Polling rejected unauthenticated — WS unauth test is moot
                return
            probe_url = _inject_sid(url, sid)

        ok, status = await self._upgrade(probe_url, extra_headers={}, origin=None)
        if ok:
            result.findings.append({
                "category": "unauthenticated_websocket",
                "severity": "high",
                "url": url,
                "evidence": (
                    "WebSocket upgrade accepted (101) without any auth token "
                    "or session cookie. Endpoint is accessible to anonymous users."
                ),
                "impact": (
                    "Any unauthenticated attacker can connect and send/receive "
                    "messages on this WebSocket channel."
                ),
                "cwe": "CWE-306",
            })

    async def _test_sub_idor(self, url: str, sent_frames: list[dict], result: WSProbeResult) -> None:
        """If the crawler captured subscribe/join frames that contain a channel
        or room ID, replay one with the ID mutated by ±1. A successful upgrade
        + first-frame echo (or no error frame within timeout) suggests the
        server may not validate channel membership."""
        candidate = _find_subscribe_frame(sent_frames)
        if candidate is None:
            return

        mutated, original_id, field_name = candidate
        if mutated is None:
            return

        # First, establish a normal auth'd connection to verify baseline works
        ok, _ = await self._upgrade(url, extra_headers=dict(self._auth), origin=None)
        if not ok:
            return

        # Now connect with mutated frame payload — track whether the server
        # accepts the subscribe action with the different ID
        accepted = await self._upgrade_and_send(url, mutated)
        if accepted:
            result.findings.append({
                "category": "websocket_subscription_idor",
                "severity": "medium",
                "url": url,
                "evidence": (
                    f"Subscribe/join frame replayed with mutated {field_name} "
                    f"(original: {original_id}, tried: {_mutate_id(original_id)}). "
                    "Server accepted the upgrade and did not immediately close the connection."
                ),
                "impact": (
                    "May be able to subscribe to another user's private channel "
                    "by guessing or enumerating the channel/room ID."
                ),
                "cwe": "CWE-639",
                "frame_sent": mutated[:200] if isinstance(mutated, str) else repr(mutated)[:200],
            })

    # ------------------------------------------------------------------
    # Low-level: raw TCP WebSocket upgrade
    # ------------------------------------------------------------------
    # Socket.io session negotiation
    # ------------------------------------------------------------------

    async def _get_socketio_sid(self, ws_url: str, use_auth: bool = True) -> Optional[str]:
        """Perform the Socket.io HTTP polling handshake and extract the session ID.
        Returns the sid string, or None if the handshake failed."""
        import httpx
        parsed = urlparse(ws_url)
        http_scheme = "https" if parsed.scheme == "wss" else "http"
        poll_url = (
            f"{http_scheme}://{parsed.netloc}{parsed.path}"
            f"?EIO=4&transport=polling"
        )
        hdrs = dict(self._auth) if use_auth else {}
        try:
            async with httpx.AsyncClient(verify=False, timeout=4.0,
                                         follow_redirects=True) as client:
                resp = await client.get(poll_url, headers=hdrs)
            if resp.status_code != 200:
                return None
            text = resp.text
            # Socket.io v4 responses look like: 0{"sid":"XXXX","upgrades":["websocket"],...}
            m = re.search(r'"sid"\s*:\s*"([^"]+)"', text)
            if m:
                return m.group(1)
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Low-level: raw TCP WebSocket upgrade
    # ------------------------------------------------------------------

    async def _upgrade(
        self,
        url: str,
        extra_headers: Optional[dict] = None,
        origin: Optional[str] = None,
    ) -> tuple[bool, int]:
        """Send an HTTP/1.1 WebSocket upgrade and return (accepted, status_code).
        accepted=True means the server returned 101 Switching Protocols.
        status_code=-1 means connection failed; -2 means parse error."""
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False, -1
        use_ssl = parsed.scheme == "wss"
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        ws_key = base64.b64encode(os.urandom(16)).decode()

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if origin is not None:
            lines.append(f"Origin: {origin}")
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")  # blank line ending headers
        lines.append("")
        request = "\r\n".join(lines).encode()

        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self._timeout,
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)

            first_line = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

            status_line = first_line.decode("utf-8", errors="replace").strip()
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                return False, -2
            try:
                code = int(parts[1])
                return code == 101, code
            except ValueError:
                return False, -2

        except asyncio.TimeoutError:
            return False, -1
        except ConnectionRefusedError:
            return False, -1
        except OSError:
            return False, -1
        except Exception:
            return False, -1

    async def _upgrade_and_send(self, url: str, frame_text: str) -> bool:
        """Upgrade with auth headers and send one text frame, return True if
        the connection stayed open (server didn't immediately close it)."""
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        use_ssl = parsed.scheme == "wss"
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        ws_key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in self._auth.items():
            lines.append(f"{k}: {v}")
        lines.extend(["", ""])
        request = "\r\n".join(lines).encode()

        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self._timeout,
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)

            first_line = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            status_line = first_line.decode("utf-8", errors="replace").strip()
            if "101" not in status_line:
                writer.close()
                return False

            # Drain the rest of the HTTP headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                if not line or line == b"\r\n":
                    break

            # Send a masked WebSocket text frame with the payload
            payload = frame_text.encode("utf-8", errors="replace")
            mask = os.urandom(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            length = len(payload)
            if length <= 125:
                frame = bytes([0x81, 0x80 | length]) + mask + masked
            else:
                frame = bytes([0x81, 0xFE, length >> 8, length & 0xFF]) + mask + masked
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), timeout=3.0)

            # Wait briefly — if the server closes immediately it's rejecting us
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                writer.close()
                # Server sent a response (could be an error frame or a reply)
                # Either way, the upgrade was accepted and the frame was received
                return True
            except asyncio.TimeoutError:
                writer.close()
                # No response within timeout — server accepted but didn't reply
                # Treat as accepted (we didn't get an immediate close/error)
                return True

        except Exception:
            return False


# ---------------------------------------------------------------------------
# Socket.io URL helpers
# ---------------------------------------------------------------------------

_SIO_PATH_RE = re.compile(r"/socket\.io/", re.IGNORECASE)


def _is_socketio_url(url: str) -> bool:
    return bool(_SIO_PATH_RE.search(url))


def _sio_base(url: str) -> str:
    """Return the Socket.io URL without the sid query param for grouping."""
    parsed = urlparse(url)
    qs = {k: v for k, v in parse_qs(parsed.query).items() if k != "sid"}
    base_qs = urlencode({k: v[0] for k, v in qs.items()}, doseq=False)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{base_qs}".rstrip("?")


def _socketio_canonical(url: str) -> str:
    """Canonical Socket.io URL with transport=websocket, no sid."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?EIO=4&transport=websocket"


def _inject_sid(url: str, sid: str) -> str:
    """Add (or replace) the sid query parameter in a Socket.io URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs["sid"] = [sid]
    new_qs = urlencode({k: v[0] for k, v in qs.items()})
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

_CHANNEL_FIELDS = ("room_id", "roomId", "channel_id", "channelId",
                   "channel", "topic", "room", "sub")
_SUBSCRIBE_EVENTS = ("subscribe", "join", "SUBSCRIBE", "JOIN", "phx_join")


def _find_subscribe_frame(frames: list[dict]) -> Optional[tuple[str, str, str]]:
    """Search captured sent frames for a subscribe/join message with an
    enumerable channel/room ID. Returns (mutated_json, original_id, field_name)
    or None if no suitable frame is found."""
    for frame in frames:
        raw = frame.get("raw", "") if isinstance(frame, dict) else str(frame)
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue

        # Check if this looks like a subscribe/join event
        event_val = (
            str(data.get("event", ""))
            or str(data.get("type", ""))
            or str(data.get("action", ""))
            or str(data.get("msg_type", ""))
        ).lower()

        is_subscribe = any(ev in event_val for ev in ("subscribe", "join"))
        if not is_subscribe:
            # Check top-level keys for subscribe verbs
            is_subscribe = any(
                any(ev in str(k).lower() for ev in ("subscribe", "join"))
                for k in data.keys()
            )
        if not is_subscribe:
            continue

        # Look for a channel/room ID field we can mutate
        for field_name in _CHANNEL_FIELDS:
            original_id = data.get(field_name)
            if original_id is None:
                # Also check one level down (payload/data sub-objects)
                for sub_key in ("payload", "data", "body"):
                    sub = data.get(sub_key)
                    if isinstance(sub, dict):
                        original_id = sub.get(field_name)
                        if original_id is not None:
                            break
            if original_id is None:
                continue

            mutated_id = _mutate_id(original_id)
            if mutated_id == original_id:
                continue

            # Build the mutated frame JSON
            mutated_data = json.loads(raw)  # fresh copy
            if field_name in mutated_data:
                mutated_data[field_name] = mutated_id
            else:
                for sub_key in ("payload", "data", "body"):
                    sub = mutated_data.get(sub_key)
                    if isinstance(sub, dict) and field_name in sub:
                        sub[field_name] = mutated_id
                        break

            return json.dumps(mutated_data), str(original_id), field_name

    return None


def _mutate_id(val) -> str:
    """Increment integer IDs or append '-2' to string IDs."""
    try:
        return str(int(val) + 1)
    except (TypeError, ValueError):
        s = str(val)
        if s.endswith("-1"):
            return s[:-2] + "-2"
        return s + "-2"
