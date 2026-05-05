"""
browser_verifier.py — Playwright-backed execution verification.

Reusable utility that other probes hand a URL to and ask: "did this trigger
JavaScript execution / a redirect / a fetch to my canary?". Used by:
  - active_scanner._test_xss for reflected XSS execution proof
  - dom_xss probe for DOM source→sink verification
  - open_redirect probe for client-side meta/JS redirect detection
  - (future) SSRF probes that need browser-side fetch correlation

Why this exists: response-body grep produces both false positives (payload
echoed in JSON, never rendered) and false negatives (Angular `[innerHTML]`,
React `dangerouslySetInnerHTML`, jQuery `.html()`, late-bound DOM writes the
body never shows). A real browser sidesteps both.

Lifecycle:
  async with BrowserVerifier() as v:
      r = await v.verify_xss(url, ...)
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional


# Token the injected payload should mutate to prove execution. Constant
# rather than per-verification because we read it back immediately and the
# context is single-tenant (one browser, one verifier per scan).
XSS_OBSERVE_TOKEN = "__hxxpsin_xss_observed"

# Init script that runs before every page navigation. Sets up the canary
# slot and a defensive "did anything weird try to run?" hook.
_INIT_SCRIPT = f"""
(() => {{
  try {{
    window.{XSS_OBSERVE_TOKEN} = false;
    window.__hxxpsin_dialogs = 0;
    // Some payloads call console.log — track those too as a weak signal
    window.__hxxpsin_console_count = 0;
    const orig = console.log;
    console.log = function() {{
      window.__hxxpsin_console_count++;
      return orig.apply(console, arguments);
    }};
  }} catch (e) {{}}
}})();
"""


@dataclass
class XSSVerification:
    """Result of a browser-based XSS verification attempt."""
    verdict: str           # confirmed | likely | not_confirmed | skipped | error
    confidence: float
    evidence: str
    url: str = ""
    signal: str = ""       # which signal fired: canary | dialog | csp | none
    console_violations: list[str] = field(default_factory=list)
    final_url: str = ""    # where the page ended up (helps debug redirects)

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == "confirmed"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence, "url": self.url, "signal": self.signal,
            "console_violations": self.console_violations[:5],
            "final_url": self.final_url,
        }


@dataclass
class RedirectVerification:
    """Result of a browser-based open-redirect verification."""
    verdict: str
    confidence: float
    evidence: str
    final_url: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence, "final_url": self.final_url,
        }


class BrowserVerifier:
    """Owns a single Playwright Chromium instance for the duration of a scan.

    Cap on verifications keeps runtime predictable — each verify costs
    ~2-3s (navigation + settle wait). At default cap=50 that's ≤2.5 min.
    """

    def __init__(
        self,
        timeout_ms: int = 8000,
        max_verifications: int = 50,
        settle_ms: int = 600,
        headless: bool = True,
    ):
        self.timeout_ms = timeout_ms
        self.max_verifications = max_verifications
        self.settle_ms = settle_ms
        self.headless = headless
        self._pw_ctx = None
        self._browser = None
        self._verifications_done = 0
        self._available = False

    @property
    def available(self) -> bool:
        return self._available

    async def __aenter__(self) -> "BrowserVerifier":
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return self  # available stays False; callers will skip
        try:
            self._pw_ctx = await async_playwright().start()
            self._browser = await self._pw_ctx.chromium.launch(headless=self.headless)
            self._available = True
        except Exception:
            self._available = False
        return self

    async def __aexit__(self, *args) -> None:
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw_ctx:
                await self._pw_ctx.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # XSS verification
    # ------------------------------------------------------------------

    @staticmethod
    def xss_payloads(context: str = "html") -> list[str]:
        """Payloads that set window.__hxxpsin_xss_observed=true on execution.
        Caller is responsible for embedding in URL/body and URL-encoding as
        needed for the transport.

        context:
          html       → free-form body content (default)
          attribute  → inside an HTML attribute value (needs to break out)
          js_string  → inside a JS string literal (needs to break out of quotes)
          url        → href/src — javascript: URI variants
          json       → inside a JSON string value
          svg        → SVG body (XML-clean variants)
        """
        obs = f"window.{XSS_OBSERVE_TOKEN}=1"
        ctx = (context or "html").lower()

        if ctx == "attribute":
            return [
                f'" autofocus onfocus="{obs}" x="',
                f"' autofocus onfocus='{obs}' x='",
                f'" onmouseover="{obs}" x="',
            ]
        if ctx == "js_string":
            return [
                f"';{obs};'",
                f'";{obs};"',
                f"\\';{obs};\\'",
                f"'-{obs}-'",
            ]
        if ctx == "url":
            return [
                f"javascript:{obs}//",
                f"javascript:void({obs})",
                f"data:text/html,<script>{obs}</script>",
            ]
        if ctx == "json":
            # Break out of a quoted JSON value into HTML — relies on the
            # response Content-Type being text/html. JSON-only sinks need
            # a different strategy.
            return [
                f'"</script><svg/onload="{obs}">',
                f'\"></script><svg/onload=\"{obs}\">',
            ]
        if ctx == "svg":
            return [
                f'<svg xmlns="http://www.w3.org/2000/svg" onload="{obs}"/>',
                f'<svg/onload="{obs}"/>',
            ]
        # Default: html body
        return [
            f'<svg/onload="{obs}">',
            f'<img src=x onerror="{obs}">',
            f'<script>{obs}</script>',
            f'"><svg/onload="{obs}">',  # attribute breakout + html
            # OWASP polyglot — fires in many contexts at once
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk={obs} )//'
            f'%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>'
            f'\\x3csVg/<sVg/oNloAd={obs}//>\\x3e',
        ]

    async def verify_xss(
        self,
        url: str,
        auth_headers: Optional[dict] = None,
    ) -> XSSVerification:
        """Navigate `url` and check whether any of our XSS canaries fired.

        Returns 'skipped' if browser unavailable or cap reached. Returns
        'error' on navigation timeout. 'confirmed' / 'not_confirmed' / 'likely'
        otherwise."""
        if not self._available:
            return XSSVerification(
                verdict="skipped", confidence=0.0,
                evidence="browser unavailable", url=url,
            )
        if self._verifications_done >= self.max_verifications:
            return XSSVerification(
                verdict="skipped", confidence=0.0,
                evidence=f"verification cap reached ({self.max_verifications})",
                url=url,
            )
        self._verifications_done += 1

        ctx = await self._browser.new_context(
            extra_http_headers=auth_headers or {},
            ignore_https_errors=True,
            # Don't carry state between verifications
            storage_state=None,
        )
        try:
            page = await ctx.new_page()
            await page.add_init_script(_INIT_SCRIPT)

            # Track signals
            dialogs: list[dict] = []

            async def _on_dialog(dialog):
                dialogs.append({"type": dialog.type, "message": dialog.message})
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", lambda d: asyncio.create_task(_on_dialog(d)))

            console_msgs: list[str] = []
            page.on("console", lambda m: console_msgs.append(m.text or ""))

            # Navigate
            try:
                response = await page.goto(
                    url, timeout=self.timeout_ms,
                    wait_until="domcontentloaded",
                )
            except Exception as exc:
                return XSSVerification(
                    verdict="error", confidence=0.0,
                    evidence=f"nav_error: {type(exc).__name__}", url=url,
                )

            # Allow deferred JS to run (innerHTML→<svg> needs a tick)
            await page.wait_for_timeout(self.settle_ms)

            # Read canary
            canary_set = False
            try:
                canary_set = bool(await page.evaluate(f"window.{XSS_OBSERVE_TOKEN}"))
            except Exception:
                pass
            final_url = page.url

            csp_violations = [
                m for m in console_msgs
                if "csp" in m.lower() or "content security policy" in m.lower()
                or "refused to execute" in m.lower()
                or "unsafe-eval" in m.lower() or "unsafe-inline" in m.lower()
            ]

            if canary_set:
                return XSSVerification(
                    verdict="confirmed", confidence=0.98,
                    evidence=f"canary global set after navigation — JS execution proven",
                    url=url, signal="canary", final_url=final_url,
                    console_violations=csp_violations[:5],
                )
            if dialogs:
                d = dialogs[0]
                return XSSVerification(
                    verdict="confirmed", confidence=0.95,
                    evidence=f"{d['type']} dialog fired: {d['message'][:80]!r}",
                    url=url, signal="dialog", final_url=final_url,
                    console_violations=csp_violations[:5],
                )
            if csp_violations:
                # CSP blocked SOMETHING — payload was at least parsed as JS.
                # Useful signal but not proof of exploitability.
                return XSSVerification(
                    verdict="likely", confidence=0.55,
                    evidence=f"payload parsed as JS but blocked by CSP: {csp_violations[0][:100]}",
                    url=url, signal="csp", final_url=final_url,
                    console_violations=csp_violations[:5],
                )
            return XSSVerification(
                verdict="not_confirmed", confidence=0.0,
                evidence="no execution signal — payload likely escaped or not in active sink",
                url=url, signal="none", final_url=final_url,
            )
        finally:
            try:
                await ctx.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Open-redirect verification (bonus — body-grep can't see meta/JS redirects)
    # ------------------------------------------------------------------

    async def verify_redirect(
        self,
        url: str,
        target_origin: str,
        auth_headers: Optional[dict] = None,
    ) -> RedirectVerification:
        """Navigate `url` and check if the final page URL ended up on a
        different origin than `target_origin`. Catches meta-refresh and
        client-side JS redirects that response-body inspection misses."""
        if not self._available:
            return RedirectVerification(
                verdict="skipped", confidence=0.0,
                evidence="browser unavailable",
            )
        if self._verifications_done >= self.max_verifications:
            return RedirectVerification(
                verdict="skipped", confidence=0.0,
                evidence="cap reached",
            )
        self._verifications_done += 1

        ctx = await self._browser.new_context(
            extra_http_headers=auth_headers or {},
            ignore_https_errors=True,
        )
        try:
            page = await ctx.new_page()
            try:
                await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            except Exception as exc:
                return RedirectVerification(
                    verdict="error", confidence=0.0,
                    evidence=f"nav_error: {type(exc).__name__}",
                )
            await page.wait_for_timeout(self.settle_ms)
            final_url = page.url
            # Compare origins
            from urllib.parse import urlparse
            final_origin = urlparse(final_url).netloc
            expected_origin = urlparse(target_origin).netloc
            if final_origin and final_origin != expected_origin:
                return RedirectVerification(
                    verdict="confirmed", confidence=0.9,
                    evidence=f"browser landed on {final_origin} (expected {expected_origin})",
                    final_url=final_url,
                )
            return RedirectVerification(
                verdict="not_confirmed", confidence=0.0,
                evidence=f"browser stayed on {final_origin or 'unknown'}",
                final_url=final_url,
            )
        finally:
            try:
                await ctx.close()
            except Exception:
                pass
