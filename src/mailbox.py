"""
mailbox.py — Pluggable mail-fetch backends for AutoAuth.

Three backends, one interface:

  MailhogBackend  — polls a local Mailhog/Mailpit HTTP API. Default for the
                    bundled vm/ test stack.
  IMAPBackend     — polls any IMAP server. Operator points at a real inbox they
                    control (Gmail app-password, ProtonMail bridge, FastMail,
                    self-hosted, etc.) — needed for real targets that send
                    click-link verification or email-OTP 2FA.
  MailTmBackend   — provisions a throwaway inbox per scan via mail.tm's free
                    HTTP API. Zero operator setup, but rate-limited and
                    detectable by hardened signup forms.

All backends return a normalized `Message`. `extract_verification(msg)` pulls
the OTP code and/or verification link out of the body the same way regardless
of source.
"""

from __future__ import annotations

import asyncio
import email
import email.policy
import imaplib
import json
import random
import re
import string
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx


# ---------------------------------------------------------------------------
# Normalized message + verification extraction
# ---------------------------------------------------------------------------


@dataclass
class Message:
    """Backend-neutral representation of one email."""
    msg_id: str
    received_at: float
    from_addr: str
    to_addrs: list[str]
    subject: str
    body_text: str
    body_html: str = ""

    @property
    def body(self) -> str:
        """Combined body for regex scanning — text first, then HTML."""
        return (self.body_text or "") + "\n" + (self.body_html or "")


@dataclass
class Verification:
    """Verification artifacts extracted from a message body."""
    otp: Optional[str] = None
    link: Optional[str] = None
    source_msg_id: Optional[str] = None


_OTP_RE = re.compile(r"(?:code|otp|pin|token)[^\d]{0,20}(\d{4,8})", re.IGNORECASE)
_OTP_FALLBACK_RE = re.compile(r"\b(\d{4,8})\b")
_VERIFY_LINK_RE = re.compile(
    r"https?://[^\s<>\"']+(?:verify|confirm|activate|otp|token|magic|"
    r"validate|finish-signup|complete-signup)[^\s<>\"']*",
    re.IGNORECASE,
)


def extract_verification(msg: Message) -> Verification:
    """Pull OTP code + verify link from a message. Same logic for every backend."""
    body = msg.body
    # Prefer OTP next to a label word ("code: 123456"), fall back to any 4-8 digits
    otp_match = _OTP_RE.search(body) or _OTP_FALLBACK_RE.search(body)
    link_match = _VERIFY_LINK_RE.search(body)
    return Verification(
        otp=otp_match.group(1) if otp_match else None,
        link=link_match.group(0) if link_match else None,
        source_msg_id=msg.msg_id,
    )


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------


class MailBackend(ABC):
    """Common contract for all mail backends."""

    # True for backends that own the inbox lifecycle (mail.tm).
    provisions_inbox: bool = False

    async def __aenter__(self) -> "MailBackend":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release any backend resources. Default no-op."""
        return

    async def create_inbox(self) -> tuple[str, str]:
        """For provisioning backends: create + return (email, password).
        Non-provisioning backends raise NotImplementedError."""
        raise NotImplementedError(
            f"{type(self).__name__} doesn't provision inboxes — "
            f"operator must supply the email address"
        )

    @abstractmethod
    async def fetch_for(self, address: str, since: float = 0.0) -> list[Message]:
        """Return messages addressed to `address` received after `since` (unix ts).
        Most-recent first. Empty list if nothing matches yet."""

    async def wait_for(
        self,
        address: str,
        since: float = 0.0,
        timeout: float = 30.0,
        interval: float = 2.0,
    ) -> Optional[Message]:
        """Poll fetch_for until a new message arrives or timeout expires.
        Returns the newest message, or None on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msgs = await self.fetch_for(address, since=since)
            if msgs:
                return msgs[0]
            remaining = deadline - time.monotonic()
            await asyncio.sleep(min(interval, max(remaining, 0.0)))
        return None


# ---------------------------------------------------------------------------
# Mailhog / Mailpit — local test-stack backend
# ---------------------------------------------------------------------------


_MAIL_API_PORTS = (8025, 1080, 8026, 8030)


class MailhogBackend(MailBackend):
    """Polls a Mailhog/Mailpit/Mailcatcher HTTP API. If `base_url` is unset,
    auto-probes common ports on `auto_host` (default 'localhost')."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        auto_host: str = "localhost",
        timeout: float = 3.0,
    ):
        self.base_url = base_url.rstrip("/") if base_url else None
        self.auto_host = auto_host
        self.timeout = timeout
        self._client = httpx.AsyncClient(verify=False, timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _candidate_urls(self) -> list[str]:
        if self.base_url:
            return [f"{self.base_url}/api/v2/messages"]
        return [f"http://{self.auto_host}:{port}/api/v2/messages" for port in _MAIL_API_PORTS]

    async def fetch_for(self, address: str, since: float = 0.0) -> list[Message]:
        addr_lower = address.lower()
        results: list[Message] = []
        for url in await self._candidate_urls():
            try:
                r = await self._client.get(url)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except (json.JSONDecodeError, ValueError):
                continue
            items = data.get("items", []) if isinstance(data, dict) else data
            for raw in items[:50]:
                msg = self._parse_mailhog(raw)
                if msg is None:
                    continue
                if msg.received_at < since:
                    continue
                # Match if any To: contains the address, or body mentions it
                if any(addr_lower in to.lower() for to in msg.to_addrs) \
                        or addr_lower in msg.body.lower():
                    results.append(msg)
            if results:
                break  # found a populated mail server, don't probe others
        results.sort(key=lambda m: m.received_at, reverse=True)
        return results

    @staticmethod
    def _parse_mailhog(raw: dict) -> Optional[Message]:
        if not isinstance(raw, dict):
            return None
        # Two formats: Mailhog (Content/To structured) vs Mailpit (flat)
        msg_id = raw.get("ID") or raw.get("id") or ""
        # Mailhog timestamp: nested in Created; Mailpit: Created at top
        ts_raw = raw.get("Created") or raw.get("created") or ""
        received_at = _parse_iso_ts(ts_raw)

        # To: list — Mailhog gives [{"Mailbox":"x","Domain":"y"}], Mailpit gives ["x@y"]
        to_addrs: list[str] = []
        for t in raw.get("To") or raw.get("to") or []:
            if isinstance(t, dict):
                mailbox = t.get("Mailbox") or t.get("mailbox") or ""
                domain = t.get("Domain") or t.get("domain") or ""
                if mailbox and domain:
                    to_addrs.append(f"{mailbox}@{domain}")
            elif isinstance(t, str):
                to_addrs.append(t)

        from_addr = ""
        f = raw.get("From") or raw.get("from") or {}
        if isinstance(f, dict):
            mb = f.get("Mailbox") or f.get("mailbox") or ""
            dm = f.get("Domain") or f.get("domain") or ""
            if mb and dm:
                from_addr = f"{mb}@{dm}"
        elif isinstance(f, str):
            from_addr = f

        # Subject + body
        subject = ""
        body_text = ""
        body_html = ""
        content = raw.get("Content") or raw.get("content")
        if isinstance(content, dict):
            headers = content.get("Headers") or {}
            if isinstance(headers, dict):
                subj_list = headers.get("Subject") or []
                if subj_list:
                    subject = subj_list[0] if isinstance(subj_list, list) else str(subj_list)
            body_text = content.get("Body", "") or ""
        # Mailpit shape
        subject = subject or raw.get("Subject") or ""
        body_text = body_text or raw.get("Text") or ""
        body_html = raw.get("HTML") or ""

        return Message(
            msg_id=str(msg_id),
            received_at=received_at,
            from_addr=from_addr,
            to_addrs=to_addrs,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )


# ---------------------------------------------------------------------------
# IMAP — real inbox the operator controls
# ---------------------------------------------------------------------------


class IMAPBackend(MailBackend):
    """Polls a real IMAP inbox. Wraps stdlib `imaplib` (sync) via
    `asyncio.to_thread` to keep the async API. Operator-controlled —
    expects an app-password / scoped credential, not a primary mailbox login."""

    def __init__(
        self,
        host: str,
        port: int = 993,
        user: str = "",
        password: str = "",
        folder: str = "INBOX",
        ssl: bool = True,
        timeout: float = 10.0,
    ):
        if not host or not user:
            raise ValueError("IMAPBackend requires host and user")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.folder = folder
        self.ssl = ssl
        self.timeout = timeout

    async def fetch_for(self, address: str, since: float = 0.0) -> list[Message]:
        return await asyncio.to_thread(self._fetch_blocking, address, since)

    def _fetch_blocking(self, address: str, since: float) -> list[Message]:
        """Synchronous IMAP fetch. Runs in a thread."""
        try:
            if self.ssl:
                conn = imaplib.IMAP4_SSL(self.host, self.port, timeout=self.timeout)
            else:
                conn = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        except (OSError, imaplib.IMAP4.error):
            return []

        try:
            conn.login(self.user, self.password)
        except imaplib.IMAP4.error:
            conn.logout()
            return []

        results: list[Message] = []
        try:
            conn.select(self.folder, readonly=True)
            # IMAP SEARCH: TO "<address>" + SINCE "<date>" if since>0
            # SINCE granularity is day-level — we re-filter by timestamp client-side
            criteria = [f'TO "{address}"']
            if since > 0:
                since_date = time.strftime("%d-%b-%Y", time.gmtime(since))
                criteria.append(f'SINCE "{since_date}"')
            search_str = " ".join(criteria)
            typ, data = conn.search(None, search_str)
            if typ != "OK" or not data or not data[0]:
                return []
            ids = data[0].split()
            # Fetch the most-recent 20 only — pentest mailbox doesn't need full sync
            for msg_id in reversed(ids[-20:]):
                typ, fetch_data = conn.fetch(msg_id, "(RFC822)")
                if typ != "OK" or not fetch_data:
                    continue
                raw_bytes = b""
                for part in fetch_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_bytes = part[1]
                        break
                if not raw_bytes:
                    continue
                parsed = self._parse_rfc822(msg_id.decode(), raw_bytes)
                if parsed is None:
                    continue
                if parsed.received_at < since:
                    continue
                results.append(parsed)
        finally:
            try:
                conn.close()
            except imaplib.IMAP4.error:
                pass
            conn.logout()

        results.sort(key=lambda m: m.received_at, reverse=True)
        return results

    @staticmethod
    def _parse_rfc822(msg_id: str, raw: bytes) -> Optional[Message]:
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except (ValueError, TypeError):
            return None

        # Date → unix ts
        received_at = 0.0
        date_hdr = msg.get("Date", "")
        if date_hdr:
            try:
                dt = email.utils.parsedate_to_datetime(date_hdr)
                received_at = dt.timestamp()
            except (TypeError, ValueError):
                pass

        to_addrs = [addr for _, addr in email.utils.getaddresses([msg.get("To", "")])]
        from_addr = ""
        from_list = email.utils.getaddresses([msg.get("From", "")])
        if from_list:
            from_addr = from_list[0][1]

        subject = msg.get("Subject", "")

        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain" and not body_text:
                    try:
                        body_text = part.get_content()
                    except (LookupError, ValueError):
                        body_text = part.get_payload(decode=True).decode(errors="replace")
                elif ct == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except (LookupError, ValueError):
                        body_html = part.get_payload(decode=True).decode(errors="replace")
        else:
            try:
                body_text = msg.get_content()
            except (LookupError, ValueError):
                body_text = msg.get_payload(decode=True).decode(errors="replace")

        return Message(
            msg_id=str(msg_id),
            received_at=received_at,
            from_addr=from_addr,
            to_addrs=to_addrs,
            subject=subject,
            body_text=body_text or "",
            body_html=body_html or "",
        )


# ---------------------------------------------------------------------------
# mail.tm — disposable inbox per scan
# ---------------------------------------------------------------------------


class MailTmBackend(MailBackend):
    """Provisions a throwaway inbox via mail.tm's free HTTP API. Use for
    one-shot scans where the operator doesn't want to wire up a real inbox.

    Caveats: mail.tm has aggressive rate limits and its domain pool is on most
    public disposable-email blocklists. Fine for CTFs and personal test apps,
    will trip anti-abuse on hardened signup flows."""

    provisions_inbox = True

    BASE = "https://api.mail.tm"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.BASE, timeout=timeout, verify=True,
            headers={"Accept": "application/ld+json", "User-Agent": "hxxpsin/1.0"},
        )
        self._address: Optional[str] = None
        self._password: Optional[str] = None
        self._token: Optional[str] = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def create_inbox(self) -> tuple[str, str]:
        """Provision a fresh disposable account. Returns (address, password)."""
        if self._address and self._password:
            return self._address, self._password

        domain = await self._pick_domain()
        local = "hxxpsin_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        address = f"{local}@{domain}"
        password = "Hxxp_" + "".join(random.choices(string.ascii_letters + string.digits, k=14)) + "!1"

        r = await self._client.post(
            "/accounts",
            json={"address": address, "password": password},
            headers={"Content-Type": "application/json"},
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"mail.tm account creation failed: {r.status_code} {r.text[:200]}")

        # Get auth token
        token_r = await self._client.post(
            "/token",
            json={"address": address, "password": password},
            headers={"Content-Type": "application/json"},
        )
        if token_r.status_code != 200:
            raise RuntimeError(f"mail.tm token failed: {token_r.status_code}")
        self._token = token_r.json().get("token")
        if not self._token:
            raise RuntimeError("mail.tm token response missing 'token'")

        self._address = address
        self._password = password
        return address, password

    async def _pick_domain(self) -> str:
        r = await self._client.get("/domains")
        if r.status_code != 200:
            raise RuntimeError(f"mail.tm /domains failed: {r.status_code}")
        data = r.json()
        items = data.get("hydra:member") or data.get("items") or []
        for d in items:
            if d.get("isActive", True) and not d.get("isPrivate", False):
                name = d.get("domain")
                if name:
                    return name
        raise RuntimeError("mail.tm: no active public domain available")

    async def fetch_for(self, address: str, since: float = 0.0) -> list[Message]:
        if not self._token:
            return []
        try:
            r = await self._client.get(
                "/messages",
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError:
            return []
        if r.status_code != 200:
            return []
        data = r.json()
        items = data.get("hydra:member") or data.get("items") or data or []

        results: list[Message] = []
        for stub in items[:20]:
            received_at = _parse_iso_ts(stub.get("createdAt", ""))
            if received_at < since:
                continue
            mid = stub.get("id")
            if not mid:
                continue
            # Fetch full message to get the body
            full_r = await self._client.get(
                f"/messages/{mid}",
                headers={"Authorization": f"Bearer {self._token}"},
            )
            if full_r.status_code != 200:
                continue
            full = full_r.json()
            results.append(Message(
                msg_id=str(mid),
                received_at=received_at,
                from_addr=(full.get("from") or {}).get("address", ""),
                to_addrs=[t.get("address", "") for t in (full.get("to") or [])],
                subject=full.get("subject", ""),
                body_text=full.get("text", "") or "",
                body_html="\n".join(full.get("html") or []),
            ))
        results.sort(key=lambda m: m.received_at, reverse=True)
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)


def _parse_iso_ts(s: str) -> float:
    if not s:
        return 0.0
    # Try strptime variants
    for fmt in _ISO_FORMATS:
        try:
            return time.mktime(time.strptime(s.replace("Z", "+0000"), fmt.replace("Z", "%z")))
        except ValueError:
            continue
    # Fallback: email-style RFC2822
    try:
        dt = email.utils.parsedate_to_datetime(s)
        return dt.timestamp()
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def from_profile(profile, target_url: Optional[str] = None) -> MailBackend:
    """Build a MailBackend from an auth_config.MailProfile.

    `target_url` is used only by MailhogBackend's auto-host fallback when no
    explicit mailhog_url is set."""
    backend = profile.backend.lower()
    if backend == "mailhog":
        if profile.mailhog_url:
            return MailhogBackend(base_url=profile.mailhog_url)
        host = "localhost"
        if target_url:
            host = urlparse(target_url).hostname or "localhost"
        return MailhogBackend(auto_host=host)
    if backend == "imap":
        return IMAPBackend(
            host=profile.imap_host or "",
            port=profile.imap_port,
            user=profile.imap_user or "",
            password=profile.imap_pass or "",
            folder=profile.imap_folder,
            ssl=profile.imap_ssl,
        )
    if backend == "mailtm":
        return MailTmBackend()
    raise ValueError(f"unknown mail backend: {profile.backend!r}")
