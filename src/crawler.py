"""
Playwright-based crawler for hxxpsin.

Navigates a target app as an authenticated user, intercepts all network traffic,
captures WebSocket messages, harvests JS bundle URLs, and emits raw data to a
Collector instance. Does not exploit anything — maps only.

SPA-aware: extracts router config + hash routes via spa_router; mirrors
discovered paths to /#/path form when the target uses fragment routing.
Form-fill: delegates to auto_auth._map_field_value for realistic input values.
"""

import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    WebSocket,
    async_playwright,
)

from collector import Collector, CapturedRequest, CapturedWebSocket
from spa_router import extract_routes_from_page, extract_routes_from_text

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CLICK_BLACKLIST = re.compile(
    r"\b(delete|remove|destroy|purchase|pay|submit\s+payment|"
    r"send\s+invite|email\s+users?|unsubscribe|reset\s+all|wipe)\b",
    re.IGNORECASE,
)

# Forms that look like account creation or destructive actions — skip submission
FORM_SKIP_RE = re.compile(
    r"\b(register|sign[\s-]?up|create[\s-]?account|delete|destroy|"
    r"purchase|pay|unsubscribe|reset[\s-]?all|wipe)\b",
    re.IGNORECASE,
)

# Probe values keyed by keyword found in input name/placeholder
_PROBE_BY_HINT: list[tuple[str, str]] = [
    ("email",    "probe@test.invalid"),
    ("url",      "http://test.invalid"),
    ("webhook",  "http://test.invalid"),
    ("callback", "http://test.invalid"),
    ("redirect", "http://test.invalid"),
    ("phone",    "5551234567"),
    ("tel",      "5551234567"),
    ("date",     "2024-01-01"),
    ("zip",      "10001"),
    ("postal",   "10001"),
    ("number",   "1"),
    ("amount",   "1"),
    ("qty",      "1"),
    ("count",    "1"),
    ("id",       "1"),
]
_PROBE_BY_TYPE: dict[str, str] = {
    "email":  "probe@test.invalid",
    "url":    "http://test.invalid",
    "tel":    "5551234567",
    "number": "1",
    "date":   "2024-01-01",
}
_PROBE_DEFAULT = "testprobe"

JS_ENDPOINT_RE = re.compile(
    r"""(?:["'`])((?:/api/|/rest/|/graphql|/admin|/internal|/v\d+/|/debug|/auth/|/oauth|/oidc|/webhook)[^"'`\s]{0,200})(?:["'`])""",
    re.IGNORECASE,
)

JS_CONSTANT_RE = re.compile(
    r"""(?:api[_-]?key|secret|token|auth|password|flag|role|feature|plan)\s*[:=]\s*["'`]([^"'`\s]{4,120})["'`]""",
    re.IGNORECASE,
)

WS_SCHEMES = {"ws", "wss"}

SAFE_POST_WORDS = re.compile(
    r"\b(login|sign\s*in|search|filter|query|next|load\s*more|submit|go)\b",
    re.IGNORECASE,
)


@dataclass
class CrawlConfig:
    start_url: str
    auth_state: Optional[str] = None       # path to storage_state JSON
    max_pages: int = 80
    max_depth: int = 4
    click_timeout_ms: int = 800
    nav_timeout_ms: int = 12_000
    idle_wait_ms: int = 600
    headless: bool = True
    allow_writes: bool = False             # if True, allow PUT/PATCH/DELETE auto-clicks
    extra_headers: dict = field(default_factory=dict)
    hash_routing: bool = False             # mirror discovered paths to /#/path form
    parallel_pages: int = 4                # number of worker pages within one context
    auto_auth_retry: bool = True           # trigger AutoAuth + retry on auth-redirect
    # Two-phase crawl knobs. Defaults preserve legacy single-phase behaviour;
    # Phase A (pre-auth discovery) sets form_fill=False/auto_click=False so we
    # don't submit registration forms or trigger destructive actions before
    # AutoAuth has chosen credentials.
    form_fill: bool = True
    auto_click: bool = True
    seed_paths: list = field(default_factory=list)  # extra start_urls enqueued at depth 0
    # Scope control — empty means same-origin only (legacy default)
    allowed_hosts: list = field(default_factory=list)   # additional netlocs to follow
    excluded_patterns: list = field(default_factory=list)  # regex strings; matched against full URL


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    # Resource types whose response bodies we want to keep. XHR/fetch are the
    # API responses downstream probes need; document is useful for HTML grep.
    _BODY_CAPTURE_TYPES = frozenset({"xhr", "fetch", "document"})
    # Per-body cap (200 KB covers ~99% of API responses; truncate larger)
    _BODY_CAPTURE_MAX_BYTES = 200_000
    # Total per-scan budget — caps memory blow-up on chatty SPAs
    _BODY_CAPTURE_TOTAL_BUDGET = 50 * 1024 * 1024
    # Content-types that are NEVER worth body-capturing (binary-shaped)
    _BODY_SKIP_CT_PREFIXES = ("image/", "audio/", "video/", "font/",
                              "application/octet-stream", "application/pdf",
                              "application/zip", "application/x-")

    def __init__(self, config: CrawlConfig, collector: Collector):
        self.cfg = config
        self.col = collector
        self._origin = self._parse_origin(config.start_url)
        # Pre-compile excluded patterns once so _enqueue is cheap
        self._excluded_re = [re.compile(p) for p in (config.excluded_patterns or [])]
        self._visited: set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._skipped: list[dict] = []  # {url, reason, elapsed_ms}
        # Lazy-initialized AutoAuth instance for credential generation in form-fill
        # and for auto-retry on auth redirects. Built only when first needed.
        self._auto_auth = None
        self._auto_auth_attempted = False  # one retry per crawl, not per page
        self._auto_auth_lock = asyncio.Lock()  # guard against parallel-worker race
        # Async body-capture tracking — spawned by sync _on_response, joined by _visit
        self._pending_body_tasks: list[asyncio.Task] = []
        self._captured_body_bytes: int = 0
        self._bodies_captured: int = 0
        self._bodies_skipped_oversize: int = 0
        self._bodies_skipped_budget: int = 0

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    # Path prefixes/extensions that are NEVER SPA routes — skip the mirror
    # *and* skip browser visit (these belong to stackprint/httpx, not Playwright).
    _NON_SPA_PREFIXES = (
        "/.well-known/", "/sitemap", "/robots", "/.git/", "/.env",
        "/api/", "/rest/", "/graphql", "/_next/", "/__nuxt/",
        "/actuator/", "/openapi.", "/swagger", "/api-docs",
        "/metrics", "/health",
    )
    _NON_SPA_SUFFIXES = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".xml", ".json", ".txt",
    )

    @classmethod
    def _is_spa_route_candidate(cls, path: str) -> bool:
        """True if `path` could plausibly be a client-side SPA route (worth
        navigating with the browser and mirroring to /#/path)."""
        if not path or path == "/":
            return False
        path_l = path.lower()
        if any(path_l.startswith(p) for p in cls._NON_SPA_PREFIXES):
            return False
        if any(path_l.endswith(s) for s in cls._NON_SPA_SUFFIXES):
            return False
        return True

    async def _enqueue(self, url: str, depth: int) -> None:
        """Push URL onto BFS queue with dedup. If hash_routing is on and the
        path looks like a SPA route, also queue the /#/path mirror."""
        if not self._same_origin(url):
            return
        if self._is_excluded(url):
            return
        norm = self._normalize(url)
        if norm in self._visited:
            return
        await self._queue.put((url, depth))

        if self.cfg.hash_routing:
            parsed = urlparse(url)
            path = parsed.path or "/"
            # Skip mirroring for non-SPA paths (assets, well-known, API)
            if not self._is_spa_route_candidate(path):
                return
            # /foo → /#/foo (mirror direction); skip if URL already has a hash
            if parsed.fragment:
                return
            mirror_url = f"{parsed.scheme}://{parsed.netloc}/#{path}"
            mirror_norm = self._normalize(mirror_url)
            if mirror_norm not in self._visited:
                await self._queue.put((mirror_url, depth))

    def _record_skip(self, url: str, reason: str, elapsed_ms: int) -> None:
        """Loud failure tracking — written to crawl_skipped.json after run."""
        self._skipped.append({"url": url, "reason": reason, "elapsed_ms": elapsed_ms})
        print(f"  [skip] {url}  ({reason})", file=sys.stderr)

    def dump_skipped(self, out_dir: str) -> Optional[str]:
        """Write crawl_skipped.json next to collector.json. Returns the path written."""
        if not self._skipped:
            return None
        path = Path(out_dir) / "crawl_skipped.json"
        path.write_text(json.dumps({"skipped": self._skipped}, indent=2))
        return str(path)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=self.cfg.headless)
            ctx = await self._make_context(browser)

            await self._enqueue(self.cfg.start_url, 0)
            for seed in self.cfg.seed_paths:
                seed_url = seed if seed.startswith("http") else urljoin(self._origin + "/", seed.lstrip("/"))
                await self._enqueue(seed_url, 0)

            # Parallel worker pool — each worker has its own Page in the shared
            # context so they all see the same auth state.
            n_workers = max(1, self.cfg.parallel_pages)
            workers = [
                asyncio.create_task(self._worker(ctx, worker_id=i))
                for i in range(n_workers)
            ]
            try:
                # Drain the queue (Queue.join unblocks once every enqueued item
                # has had task_done() called for it). Workers loop forever and
                # are cancelled below.
                await self._queue.join()
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                # Final body-capture flush — catches any tasks spawned by
                # late-firing response events that the per-visit flush missed
                await self._flush_body_tasks()
                await browser.close()

    async def _worker(self, ctx: BrowserContext, worker_id: int) -> None:
        """Worker loop — pulls URLs off the queue, visits, marks task_done.
        Runs until cancelled by run() once the queue is fully drained."""
        page = await ctx.new_page()
        self._attach_listeners(page)
        try:
            while True:
                url, depth = await self._queue.get()
                try:
                    # max_pages=0 (or negative) means unlimited
                    if self.cfg.max_pages > 0 and len(self._visited) >= self.cfg.max_pages:
                        continue
                    norm = self._normalize(url)
                    if norm in self._visited:
                        continue
                    self._visited.add(norm)
                    await self._visit(page, url, depth)
                finally:
                    self._queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            try:
                await page.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    async def _make_context(self, browser: Browser) -> BrowserContext:
        kwargs: dict = {
            "extra_http_headers": self.cfg.extra_headers,
            "ignore_https_errors": True,
        }
        if self.cfg.auth_state:
            kwargs["storage_state"] = self.cfg.auth_state

        ctx = await browser.new_context(**kwargs)

        # Capture WebSocket connections
        ctx.on("websocket", self._on_websocket)
        return ctx

    # ------------------------------------------------------------------
    # Page visit
    # ------------------------------------------------------------------

    async def _visit(self, page: Page, url: str, depth: int) -> None:
        t0 = time.monotonic()
        nav_status: Optional[int] = None
        try:
            response = await page.goto(
                url, wait_until="networkidle", timeout=self.cfg.nav_timeout_ms,
            )
            nav_status = response.status if response else None
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            self.col.log_error(url, str(exc))
            self._record_skip(url, f"nav_error: {type(exc).__name__}", elapsed_ms)
            return

        # Auto-auth retry when the response indicates we lost the session.
        # Detected by 401/403 status OR landing on a login page after a redirect.
        if self.cfg.auto_auth_retry and not self._auto_auth_attempted:
            landed = page.url.lower()
            looks_like_auth_redirect = (
                (nav_status in (401, 403))
                or (
                    any(s in landed for s in ("/login", "/signin", "/sign-in"))
                    and "/login" not in url.lower()
                    and "/signin" not in url.lower()
                )
            )
            if looks_like_auth_redirect:
                async with self._auto_auth_lock:
                    if self._auto_auth_attempted:
                        merged = False  # another worker already tried
                    else:
                        self._auto_auth_attempted = True
                        merged = await self._try_auto_auth_retry(page, url)
                if merged:
                    # Re-navigate the original URL with fresh auth
                    try:
                        response = await page.goto(
                            url, wait_until="networkidle",
                            timeout=self.cfg.nav_timeout_ms,
                        )
                        nav_status = response.status if response else None
                    except Exception as exc:
                        self._record_skip(
                            url, f"nav_after_auth_retry: {type(exc).__name__}",
                            int((time.monotonic() - t0) * 1000),
                        )
                        return

        # Auto-scroll to trigger lazy-loaded content / infinite scroll
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(400)
        except Exception:
            pass

        # Harvest JS bundle endpoints before clicking anything
        await self._harvest_js_bundles(page)

        # SPA route extraction — pull routes from framework globals + DOM
        try:
            spa_routes = await extract_routes_from_page(page)
            for route in spa_routes:
                full = urljoin(self._origin + "/", route.lstrip("/"))
                await self._enqueue(full, depth + 1)
        except Exception:
            pass

        # max_depth=0 (or negative) means unlimited depth
        if self.cfg.max_depth > 0 and depth >= self.cfg.max_depth:
            return

        # Enqueue same-origin hrefs
        hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        for href in hrefs:
            await self._enqueue(href, depth + 1)

        # Fill and submit visible forms (discovers POST endpoints)
        if self.cfg.form_fill:
            await self._submit_forms(page, url)

        # Click interactive elements that are safe
        if self.cfg.auto_click:
            await self._click_interactive(page, url, depth)

        # Flush any in-flight body-capture tasks before this page closes,
        # so the bodies land in the Collector while the URL is still relevant.
        await self._flush_body_tasks()

    # ------------------------------------------------------------------
    # Form filling
    # ------------------------------------------------------------------

    async def _submit_forms(self, page: Page, page_url: str) -> None:
        """Fill and submit visible safe forms to trigger network requests."""
        try:
            forms = await page.locator("form").all()
        except Exception:
            return

        for form in forms[:10]:
            try:
                if not await form.is_visible():
                    continue
                # Skip file-upload forms
                if "multipart" in (await form.get_attribute("enctype") or "").lower():
                    continue
                # Skip forms with password fields — avoid breaking auth state
                if await form.locator("input[type=password]").count() > 0:
                    continue
                # Check submit button text for destructive signals
                submit_text = ""
                try:
                    btn = form.locator(
                        "input[type=submit]:visible, button[type=submit]:visible, button:not([type]):visible"
                    )
                    if await btn.count():
                        submit_text = await btn.first.inner_text(timeout=300)
                except Exception:
                    pass
                if FORM_SKIP_RE.search(submit_text):
                    continue

                await self._fill_form_inputs(form)
                await self._submit_form(page, form, page_url)
            except Exception:
                pass

    def _get_auto_auth(self):
        """Lazy-instantiate AutoAuth for credential generation in form-fill."""
        if self._auto_auth is None:
            from auto_auth import AutoAuth
            self._auto_auth = AutoAuth(self._origin)
        return self._auto_auth

    async def _try_auto_auth_retry(self, page: Page, original_url: str) -> bool:
        """Run AutoAuth to provision a fresh account, then merge any harvested
        cookies/headers into the live browser context. Returns True if creds
        were obtained. Called once per crawl when an auth-redirect is detected."""
        try:
            aa = self._get_auto_auth()
            session = await aa.run()
        except Exception as exc:
            print(f"  [auto-auth-retry] AutoAuth failed: {exc}", file=sys.stderr)
            return False
        if not session.has_auth:
            print("  [auto-auth-retry] no creds harvested", file=sys.stderr)
            return False

        ctx = page.context
        # Merge cookies
        if session.cookies:
            cookie_specs = []
            origin = urlparse(self._origin)
            for name, value in session.cookies.items():
                cookie_specs.append({
                    "name": name, "value": value,
                    "domain": origin.hostname or "", "path": "/",
                })
            try:
                await ctx.add_cookies(cookie_specs)
            except Exception:
                pass
        # Merge bearer-token header for all subsequent requests
        if session.token:
            try:
                merged_headers = dict(self.cfg.extra_headers)
                merged_headers["Authorization"] = f"Bearer {session.token}"
                await ctx.set_extra_http_headers(merged_headers)
            except Exception:
                pass
        kind = "token" if session.token else f"{len(session.cookies)} cookie(s)"
        print(f"  [auto-auth-retry] obtained {kind} as {session.credentials.username}",
              file=sys.stderr)
        return True

    async def _smart_fill_value(self, inp, input_type: str) -> str:
        """Pick a realistic value for a form input using auto_auth's field mapper.
        Falls back to legacy _PROBE_BY_HINT if AutoAuth can't be loaded."""
        name = (await inp.get_attribute("name") or "")
        placeholder = (await inp.get_attribute("placeholder") or "")
        elem_id = (await inp.get_attribute("id") or "")
        # Combine all hints into a single name string for the mapper
        hint_name = name or placeholder or elem_id
        try:
            aa = self._get_auto_auth()
            mapped = aa._map_field_value(hint_name, input_type)
            if mapped is not None and mapped != "":
                return mapped
        except Exception:
            pass
        # Fall back to legacy probe map
        hint = " ".join([name, placeholder, elem_id]).lower()
        value = _PROBE_BY_TYPE.get(input_type, _PROBE_DEFAULT)
        for keyword, probe in _PROBE_BY_HINT:
            if keyword in hint:
                value = probe
                break
        return value

    async def _fill_form_inputs(self, form) -> None:
        """Fill all text-like inputs in a form with semantically appropriate
        values from auto_auth._map_field_value (handles email/phone/etc)."""
        for input_type in ("text", "search", "email", "url", "tel", "number", "date"):
            try:
                for inp in (await form.locator(f"input[type={input_type}]:visible").all())[:6]:
                    value = await self._smart_fill_value(inp, input_type)
                    try:
                        await inp.fill(value, timeout=400)
                    except Exception:
                        pass
            except Exception:
                pass

        # Inputs without explicit type and textareas
        try:
            for inp in (await form.locator(
                "input:not([type]):visible, input[type=text]:visible, textarea:visible"
            ).all())[:4]:
                try:
                    await inp.fill(_PROBE_DEFAULT, timeout=400)
                except Exception:
                    pass
        except Exception:
            pass

        # Selects — choose second option (first is often a blank placeholder)
        try:
            for sel in (await form.locator("select:visible").all())[:3]:
                try:
                    opts = await sel.locator("option").all()
                    if len(opts) > 1:
                        val = await opts[1].get_attribute("value")
                        if val:
                            await sel.select_option(value=val, timeout=400)
                except Exception:
                    pass
        except Exception:
            pass

    async def _submit_form(self, page: Page, form, page_url: str) -> None:
        """Click submit or press Enter, wait briefly for network activity."""
        origin_netloc = urlparse(page_url).netloc
        try:
            btn = form.locator(
                "input[type=submit]:visible, button[type=submit]:visible, button:not([type]):visible"
            )
            action = btn.first.click if await btn.count() else None
            if action is None:
                # Fall back to Enter in the first visible input
                inputs = await form.locator("input:visible").all()
                if inputs:
                    action = lambda timeout=None: inputs[0].press("Enter", timeout=400)  # noqa: E731
            if action:
                try:
                    async with page.expect_response(
                        lambda r: urlparse(r.url).netloc == origin_netloc,
                        timeout=2000,
                    ):
                        await action(timeout=self.cfg.click_timeout_ms)
                except Exception:
                    pass
                await page.wait_for_timeout(self.cfg.idle_wait_ms)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Click strategy
    # ------------------------------------------------------------------

    async def _click_interactive(self, page: Page, page_url: str, depth: int) -> None:
        # Buttons and inputs not inside forms (forms get separate handling)
        selectors = [
            "button:visible",
            "input[type=submit]:visible",
            "input[type=button]:visible",
            "[role=button]:visible",
            "a[href]:visible",
        ]

        for sel in selectors:
            try:
                elements = await page.locator(sel).all()
            except Exception:
                continue

            for el in elements[:60]:
                try:
                    text = (await el.inner_text(timeout=300)).strip()
                except Exception:
                    text = ""

                if CLICK_BLACKLIST.search(text):
                    continue

                try:
                    href = await el.get_attribute("href")
                except Exception:
                    href = None

                if href:
                    full = urljoin(page_url, href)
                    await self._enqueue(full, depth + 1)
                    continue

                # Non-link clickable. Two parallel detectors:
                #   (1) network request (existing — for things that fire XHR)
                #   (2) URL change via history.pushState (modern SPAs)
                url_before = page.url
                try:
                    try:
                        async with page.expect_request(lambda _: True, timeout=400):
                            await el.click(timeout=self.cfg.click_timeout_ms)
                    except Exception:
                        # No network fired — but the click may have still mutated
                        # location.pathname. Click anyway (best-effort) and let
                        # the URL-change detector below pick it up.
                        try:
                            await el.click(timeout=self.cfg.click_timeout_ms)
                        except Exception:
                            continue
                    await page.wait_for_timeout(self.cfg.idle_wait_ms)
                except Exception:
                    pass

                # URL-change detection — covers SPA pushState navigation
                try:
                    url_after = page.url
                    if url_after != url_before and self._same_origin(url_after):
                        norm = self._normalize(url_after)
                        if norm not in self._visited:
                            await self._enqueue(url_after, depth + 1)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Network listeners
    # ------------------------------------------------------------------

    def _attach_listeners(self, page: Page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def _on_request(self, request: Request) -> None:
        method = request.method.upper()

        # Enforce write guard
        if method in ("DELETE", "PUT", "PATCH") and not self.cfg.allow_writes:
            return

        body = None
        try:
            body = request.post_data
        except Exception:
            pass

        self.col.add_request(CapturedRequest(
            method=method,
            url=request.url,
            headers=dict(request.headers),
            body=body,
            resource_type=request.resource_type,
        ))

    def _on_response(self, response: Response) -> None:
        # Sync part — record metadata immediately so it's available even if
        # the body-capture task fails or is skipped.
        self.col.add_response_meta(
            url=response.url,
            status=response.status,
            headers=dict(response.headers),
        )
        # Async part — spawn a body-capture task for relevant resource types.
        # The "can't await in sync handler" workaround: create_task runs the
        # coroutine in the event loop; we join all in-flight tasks at the end
        # of _visit() to ensure bodies land before the page closes.
        try:
            request = response.request
            rtype = request.resource_type
        except Exception:
            return
        if rtype not in self._BODY_CAPTURE_TYPES:
            return
        ct = response.headers.get("content-type", "").lower()
        if any(ct.startswith(p) for p in self._BODY_SKIP_CT_PREFIXES):
            return
        if self._captured_body_bytes >= self._BODY_CAPTURE_TOTAL_BUDGET:
            self._bodies_skipped_budget += 1
            return
        try:
            task = asyncio.create_task(self._capture_body(response))
            self._pending_body_tasks.append(task)
        except RuntimeError:
            # No running event loop — should never happen in normal scan flow
            pass

    async def _capture_body(self, response: Response) -> None:
        """Awaits response.text() and writes the body into the Collector.
        Bounded by per-body and per-scan budgets."""
        try:
            body = await response.text()
        except Exception:
            return
        if not body:
            return
        # Truncate at the per-body cap rather than skipping outright — partial
        # bodies are still useful for grep-based detection (SQL errors etc.)
        if len(body) > self._BODY_CAPTURE_MAX_BYTES:
            body = body[:self._BODY_CAPTURE_MAX_BYTES]
            self._bodies_skipped_oversize += 1
        # Re-check the total budget under the post-await state — many tasks
        # may be in flight and racing past the threshold.
        if self._captured_body_bytes + len(body) > self._BODY_CAPTURE_TOTAL_BUDGET:
            self._bodies_skipped_budget += 1
            return
        self._captured_body_bytes += len(body)
        self._bodies_captured += 1
        try:
            self.col.set_response_body(response.url, body)
        except Exception:
            pass

    async def _flush_body_tasks(self) -> None:
        """Wait for all in-flight body-capture tasks to complete. Called at
        end of _visit() (and again at the end of run() as a final safety net)
        so bodies are flushed before the page closes."""
        if not self._pending_body_tasks:
            return
        # Snapshot + clear so we don't await a list that may be mutated by
        # late-firing event handlers
        tasks, self._pending_body_tasks = self._pending_body_tasks, []
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            # A few stragglers — leave them; they'll be GC'd when context closes
            pass

    # ------------------------------------------------------------------
    # WebSocket listener
    # ------------------------------------------------------------------

    def _on_websocket(self, ws: WebSocket) -> None:
        entry = CapturedWebSocket(url=ws.url)
        self.col.add_websocket(entry)

        ws.on("framesent", lambda payload: entry.messages_sent.append(
            self._parse_ws_payload(payload)
        ))
        ws.on("framereceived", lambda payload: entry.messages_received.append(
            self._parse_ws_payload(payload)
        ))

    @staticmethod
    def _parse_ws_payload(payload) -> dict:
        body = payload.get("body", "") if isinstance(payload, dict) else str(payload)
        try:
            return {"raw": body, "parsed": json.loads(body)}
        except (json.JSONDecodeError, TypeError):
            return {"raw": body}

    # ------------------------------------------------------------------
    # JS bundle harvesting
    # ------------------------------------------------------------------

    async def _harvest_js_bundles(self, page: Page) -> None:
        script_srcs = await page.eval_on_selector_all(
            "script[src]", "els => els.map(e => e.src)"
        )

        for src in script_srcs:
            if not src:
                continue
            self.col.add_js_bundle_url(src)
            try:
                content = await page.evaluate(
                    f"fetch({json.dumps(src)}).then(r=>r.text())"
                )
                self._extract_from_js(content)
            except Exception:
                pass

        # Also scan inline scripts
        inline_scripts = await page.eval_on_selector_all(
            "script:not([src])", "els => els.map(e => e.textContent)"
        )
        for script in inline_scripts:
            if script:
                self._extract_from_js(script)

    def _extract_from_js(self, content: str) -> None:
        for match in JS_ENDPOINT_RE.finditer(content):
            self.col.add_js_discovered_route(match.group(1))

        for match in JS_CONSTANT_RE.finditer(content):
            full = match.group(0).strip()
            value = match.group(1)
            self.col.add_js_constant(full, value)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _same_origin(self, url: str) -> bool:
        """Return True if url is in scope (same origin or in allowed_hosts)."""
        netloc = urlparse(url).netloc
        if netloc == urlparse(self._origin).netloc:
            return True
        return bool(self.cfg.allowed_hosts and netloc in self.cfg.allowed_hosts)

    def _is_excluded(self, url: str) -> bool:
        return any(rx.search(url) for rx in self._excluded_re)

    @staticmethod
    def _normalize(url: str) -> str:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}{p.path}?{p.query}".rstrip("?")
        # Preserve the fragment for SPA hash routes (/#/login is distinct from /)
        if p.fragment and p.fragment.startswith("/"):
            return f"{base}#{p.fragment}"
        return base


# ---------------------------------------------------------------------------
# CLI entry point (standalone use / testing)
# ---------------------------------------------------------------------------

async def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="hxxpsin crawler")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--auth", help="Path to storage_state JSON")
    parser.add_argument("--max-pages", type=int, default=80)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--allow-writes", action="store_true")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--out", default="-", help="Output path (- for stdout)")
    args = parser.parse_args()

    # Inline import here so crawler.py can be tested standalone
    from collector import Collector

    cfg = CrawlConfig(
        start_url=args.url,
        auth_state=args.auth,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        headless=not args.headed,
        allow_writes=args.allow_writes,
    )

    col = Collector(origin=cfg.start_url)
    crawler = Crawler(cfg, col)
    await crawler.run()

    result = col.to_dict()
    output = json.dumps(result, indent=2)

    if args.out == "-":
        print(output)
    else:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[+] Wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(_main())
