"""
captcha.py — Detect captchas and hand off to the human operator.

Detection runs on rendered HTML of candidate login/register pages. We tag
forms with the captcha kind we saw (reCAPTCHA v2/v3, hCaptcha, Cloudflare
Turnstile, FunCaptcha, or generic), and store the sitekey when present.

When a tagged form would otherwise be auto-submitted, AutoAuth invokes the
configured `CaptchaSolver`. The default (and currently only) solver is
`HumanSolver` — it launches a headed Playwright browser, lets the operator
log in by hand, and captures the resulting storage_state (cookies +
localStorage) plus any Authorization tokens seen on the network.

The captured snapshot is persisted to `output/manual-auth.json` so subsequent
scans can reuse it via `--auth` without re-opening the browser.

We deliberately do not ship algorithmic captcha-bypass code. Human-in-the-loop
is the right primitive for authorized pentest work — the operator solves
their own captcha on a target they're authorized to test. Service backends
(2Captcha etc.) are a separate, opt-in path that can be added later.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass
class CaptchaSignal:
    """One captcha detected on a page. Tagged onto _FormShape by AutoAuth."""
    kind: str  # "recaptcha-v2" | "recaptcha-v3" | "hcaptcha" | "turnstile" | "funcaptcha" | "math" | "generic"
    sitekey: Optional[str] = None
    evidence: str = ""  # short snippet that triggered detection


_DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    # reCAPTCHA v2 — visible checkbox or image grid challenge
    ("recaptcha-v2", re.compile(
        r'(?:class\s*=\s*["\'][^"\']*\bg-recaptcha\b|'
        r'data-sitekey\s*=\s*["\'][^"\']+["\'][^>]*g-recaptcha|'
        r'src\s*=\s*["\'][^"\']*recaptcha/api\.js[^"\']*["\'])',
        re.IGNORECASE,
    )),
    # reCAPTCHA v3 — invisible, score-based. Usually loaded via api.js with ?render=SITEKEY
    ("recaptcha-v3", re.compile(
        r'recaptcha/api\.js\?[^"\']*render=([^"\'&]+)',
        re.IGNORECASE,
    )),
    # hCaptcha
    ("hcaptcha", re.compile(
        r'(?:class\s*=\s*["\'][^"\']*\bh-captcha\b|'
        r'src\s*=\s*["\']https?://(?:hcaptcha\.com|js\.hcaptcha\.com)[^"\']*)',
        re.IGNORECASE,
    )),
    # Cloudflare Turnstile
    ("turnstile", re.compile(
        r'(?:class\s*=\s*["\'][^"\']*\bcf-turnstile\b|'
        r'src\s*=\s*["\']https?://challenges\.cloudflare\.com[^"\']*)',
        re.IGNORECASE,
    )),
    # FunCaptcha / Arkose Labs
    ("funcaptcha", re.compile(
        r'(?:funcaptcha|arkoselabs\.com|client-api\.arkoselabs)',
        re.IGNORECASE,
    )),
    # Generic math captcha — e.g. "What is 5 + 3?" near a small input
    ("math", re.compile(
        r'(?:captcha|verify\s+you[\'a-z\s]+human)[^<]{0,80}\d+\s*[\+\-\*x]\s*\d+',
        re.IGNORECASE,
    )),
]

_SITEKEY_RE = re.compile(r'data-sitekey\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def detect(html: str) -> Optional[CaptchaSignal]:
    """Inspect raw HTML for a known captcha. Returns the strongest hit or None."""
    if not html:
        return None
    for kind, pattern in _DETECTORS:
        m = pattern.search(html)
        if not m:
            continue
        sitekey: Optional[str] = None
        # v3 captures sitekey directly in its pattern
        if kind == "recaptcha-v3" and m.groups():
            sitekey = m.group(1)
        if not sitekey:
            sk = _SITEKEY_RE.search(html)
            if sk:
                sitekey = sk.group(1)
        evidence = html[max(0, m.start() - 20): m.end() + 40]
        return CaptchaSignal(kind=kind, sitekey=sitekey, evidence=evidence[:120])
    return None


# ---------------------------------------------------------------------------
# Solver interface + outputs
# ---------------------------------------------------------------------------


@dataclass
class SolvedAuth:
    """Result of a successful human-solved login."""
    storage_state: dict
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: Optional[str] = None
    final_url: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def has_auth(self) -> bool:
        return bool(self.bearer_token or self.cookies or self.storage_state.get("cookies"))


class CaptchaSolver:
    """Abstract solver — given a login page URL and a detected captcha signal,
    produce a SolvedAuth (or None on giving up)."""

    async def solve(
        self,
        page_url: str,
        signal: CaptchaSignal,
        success_indicator: Optional[str] = None,
    ) -> Optional[SolvedAuth]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Human-in-the-loop solver — headed Playwright
# ---------------------------------------------------------------------------


class HumanSolver(CaptchaSolver):
    """Opens a headed Chromium window, lets the operator log in manually,
    then captures storage_state + intercepted bearer tokens."""

    def __init__(
        self,
        snapshot_path: Optional[Path] = None,
        prompt_stream=sys.stderr,
        wait_timeout: float = 600.0,  # 10 min hard cap
        reuse_snapshot: bool = True,
    ):
        self.snapshot_path = snapshot_path
        self.prompt = prompt_stream
        self.wait_timeout = wait_timeout
        self.reuse_snapshot = reuse_snapshot

    def _print(self, msg: str) -> None:
        try:
            self.prompt.write(msg + "\n")
            self.prompt.flush()
        except (OSError, ValueError):
            pass

    def _load_existing_snapshot(self) -> Optional[SolvedAuth]:
        if not (self.reuse_snapshot and self.snapshot_path and self.snapshot_path.exists()):
            return None
        try:
            data = json.loads(self.snapshot_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        storage = data.get("storage_state") or {}
        cookies = {c.get("name"): c.get("value") for c in (storage.get("cookies") or []) if c.get("name")}
        return SolvedAuth(
            storage_state=storage,
            cookies=cookies,
            bearer_token=data.get("bearer_token"),
            final_url=data.get("final_url", ""),
            notes=["reused " + str(self.snapshot_path)],
        )

    async def solve(
        self,
        page_url: str,
        signal: CaptchaSignal,
        success_indicator: Optional[str] = None,
    ) -> Optional[SolvedAuth]:
        # Short-circuit if we already have a snapshot the operator made earlier
        cached = self._load_existing_snapshot()
        if cached and cached.has_auth:
            self._print(f"  [captcha] reusing {self.snapshot_path} (skip browser).")
            return cached

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self._print(
                "  [captcha] Playwright not installed — install with "
                "`pip install playwright && playwright install chromium`."
            )
            return None

        # Banner the operator sees in the terminal
        bar = "─" * 70
        self._print("")
        self._print(bar)
        self._print(f"  [captcha] Detected {signal.kind} on {page_url}")
        if signal.sitekey:
            self._print(f"  [captcha] sitekey = {signal.sitekey}")
        self._print(bar)
        self._print(
            "  A browser window is opening. Please complete the login manually:\n"
            "    1. Solve the captcha challenge.\n"
            "    2. Submit the form.\n"
            "    3. Wait until you're logged in (any post-login page).\n"
            "    4. Return to this terminal and press ENTER."
        )
        self._print(bar)
        self._print("")

        bearer: Optional[str] = None
        final_url = ""

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False)
            try:
                ctx = await browser.new_context(ignore_https_errors=True)
                page = await ctx.new_page()

                # Sniff outgoing Authorization: Bearer headers — many SPAs put the
                # token in localStorage and attach it manually, so we see it here.
                def on_request(req):
                    nonlocal bearer
                    if bearer:
                        return
                    auth_hdr = req.headers.get("authorization", "")
                    if auth_hdr.lower().startswith("bearer "):
                        bearer = auth_hdr.split(" ", 1)[1]

                page.on("request", on_request)

                await page.goto(page_url, wait_until="domcontentloaded")

                # Block here until the operator presses ENTER in the terminal.
                # Run input() in a thread so the asyncio loop keeps draining the
                # page's network events while we wait.
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(input, ""),
                        timeout=self.wait_timeout,
                    )
                except asyncio.TimeoutError:
                    self._print("  [captcha] timeout — no input within 10 min, giving up.")
                    return None

                final_url = page.url
                storage_state = await ctx.storage_state()
            finally:
                await browser.close()

        cookies = {c.get("name"): c.get("value") for c in storage_state.get("cookies", []) if c.get("name")}
        solved = SolvedAuth(
            storage_state=storage_state,
            cookies=cookies,
            bearer_token=bearer,
            final_url=final_url,
            notes=[f"manually solved {signal.kind}"],
        )

        if not solved.has_auth:
            self._print("  [captcha] no cookies/token captured — operator may not have completed login.")
            return None

        # Persist for re-runs
        if self.snapshot_path:
            try:
                self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                self.snapshot_path.write_text(json.dumps({
                    "captured_at": time.time(),
                    "page_url": page_url,
                    "final_url": final_url,
                    "captcha_kind": signal.kind,
                    "bearer_token": bearer,
                    "storage_state": storage_state,
                }, indent=2))
                solved.notes.append(f"saved → {self.snapshot_path}")
            except OSError as exc:
                solved.notes.append(f"snapshot save failed: {exc}")

        self._print(
            f"  [captcha] captured session: "
            f"{len(cookies)} cookie(s)"
            + (", bearer token" if bearer else "")
            + f" — final URL: {final_url}"
        )
        return solved


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def from_profile(profile, snapshot_path: Optional[Path] = None) -> Optional[CaptchaSolver]:
    """Build a solver from an auth_config.CaptchaProfile.
    Returns None for mode='none' so callers can `if solver:` cheaply."""
    if profile is None:
        return None
    mode = (profile.mode or "human").lower()
    if mode == "none":
        return None
    if mode == "human":
        return HumanSolver(snapshot_path=snapshot_path)
    if mode == "service":
        raise NotImplementedError(
            "captcha mode 'service' (2Captcha/AntiCaptcha) is not yet implemented — "
            "use mode = 'human' for now"
        )
    raise ValueError(f"unknown captcha mode: {profile.mode!r}")
