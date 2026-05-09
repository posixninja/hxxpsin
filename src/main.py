"""
main.py — Single-entry CLI for the hxxpsin pipeline.

Commands:
  scan   Full pipeline: stackprint → crawl → classify → desync → enrich → report
  quick  No browser: stackprint → desync → enrich → report (~60 seconds)

Usage:
  python3 main.py scan  https://target.com --out ./output
  python3 main.py scan  https://target.com --auth auth.json --out ./output
  python3 main.py quick https://target.com --out ./output
  python3 main.py scan  https://target.com --auth-a attacker.json --auth-b victim.json

Timed challenge flow:
  0:00  python3 main.py quick https://target.com   # fingerprint while you log in
  0:05  python3 main.py scan  https://target.com --auth auth.json
  0:10  open ./output/report.md                    # read findings
  0:12  open Burp, start manual validation
"""

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

# Guard against missing playwright — quick mode works without it
try:
    from crawler import Crawler, CrawlConfig
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False

from access_replay import (
    AccessReplayProbe, BypassToken,
    tokens_from_jwt_attack, tokens_from_auth_bypass, tokens_from_idor,
)
from active_scanner import ActiveScanner, auto_fuzz_findings
from auth_bypass import AuthBypassProbe
from auto_auth import AutoAuth
from browser_verifier import BrowserVerifier
from dom_xss_probe import DOMXSSProbe
from file_grabber import FileGrabber, FileGrabResult
from har_import import HARImporter
from idor_probe import IDORProbe, Account
from canary import Canary
from challenge_tracker import ChallengeTracker
from classifier import classify
from collector import Collector, CapturedRequest
from crlf_probe import CRLFProbe
from ct_probe import CTProbe, CTProbeResult
from desync_probe import DesyncProbe, urls_from_classifier
from enricher import Enricher
from intruder import Intruder, IntruderRequest, load_payloads
from js_deep_analyzer import JSDeepAnalyzer, js_urls_from_profile, generate_test_cases
from jwt_attack import JWTAnalyzer
from llm_client import LLMClient
from llm_verifier import LLMVerifier
from nosql_probe import NoSQLProbe
from open_redirect import OpenRedirectProbe
from param_miner import ParamMiner
from sql_dump import SQLDumper
from upload_probe import UploadProbe
from repeater import Repeater, ReplayRequest
from reporter import Reporter
from stackprint import Stackprint, StackProfile
from verifier import Verifier, VerifyReport, verify_cors, verify_js_findings
from ws_probe import WSProbe, WSProbeResult


_progress_cb = None  # set by TUI via set_progress_cb()


def set_progress_cb(cb) -> None:
    global _progress_cb
    _progress_cb = cb


def _err(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr)
    if _progress_cb:
        _progress_cb("err", msg)


def _step(n: int, total: int, label: str) -> None:
    print(f"\n[{n}/{total}] {label}", file=sys.stderr)
    if _progress_cb:
        _progress_cb("step", n, total, label)


# CDN/WAF families that reliably block headless browsers (Playwright TLS
# fingerprint, JS-challenge enforcement). Hitting one of these in stackprint
# means the crawl will return 0 requests; we bail early unless the operator
# explicitly opts in with --ignore-cdn-block. Names match stackprint display.
_CDN_BOT_PROTECT = {"Cloudflare", "Akamai", "Sucuri"}


def _detect_cdn_block(profile: "StackProfile") -> set[str]:
    """Return the subset of detected CDNs that are known to block bots."""
    detected = set(profile.detected.get("cdn", []))
    return detected & _CDN_BOT_PROTECT


def _maybe_bail_on_cdn(args, profile: "StackProfile") -> bool:
    """Returns True if we should stop the scan because CDN bot-protection
    is detected and the operator hasn't opted to scan anyway."""
    blockers = _detect_cdn_block(profile)
    if not blockers:
        return False
    names = ", ".join(sorted(blockers))
    if getattr(args, "ignore_cdn_block", False):
        _err(f"⚠ {names} detected — proceeding anyway (--ignore-cdn-block). "
             f"Expect 0 captured requests from headless Playwright.")
        return False
    _err(f"✗ {names} detected — bot protection will block the headless crawl. "
         f"Stopping early. Use --ignore-cdn-block to scan anyway "
         f"(typically gives 0 results unless you supply a HAR via --har).")
    return True


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

async def cmd_scan(args) -> None:
    start = time.monotonic()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if not _PLAYWRIGHT_OK:
        _err("playwright not installed — falling back to quick mode")
        _err("Run: pip install playwright && playwright install chromium")
        await cmd_quick(args)
        return

    # total_steps: 2 stackprint+crawl + 11 pipeline steps = 13
    total_steps = 13

    # ── 1. stackprint ───────────────────────────────────────────────────
    _step(1, total_steps, f"Fingerprinting stack: {args.target}")
    sp = Stackprint(args.target, timeout=args.timeout)
    profile = await sp.run()
    _err(f"Detected: {_profile_summary(profile)}")
    _err(f"Interesting paths: {len(profile.interesting_paths)}")
    (out / "stackprint.json").write_text(json.dumps(profile.to_dict(), indent=2))

    if _maybe_bail_on_cdn(args, profile):
        return

    # ── 2. crawl OR HAR import ──────────────────────────────────────────
    # Live progress: pipe each new captured request through _progress_cb so the
    # TUI Spider tab can stream rows into its tree/list as the crawl runs.
    def _live_request(req_dict: dict) -> None:
        if _progress_cb:
            try:
                _progress_cb("request_added", req_dict)
            except Exception:
                pass

    col = Collector(args.target, on_request=_live_request)
    har_result, auto_auth_session = await _run_crawl_pipeline(
        args, profile, col, out, total_steps,
    )

    # Seed from OpenAPI/Swagger if the crawler/HAR found one
    added = await _seed_from_openapi(col, args.target)
    if added:
        _err(f"OpenAPI seeding: +{added} endpoint stubs from spec")

    _err(f"Requests captured: {len(col.requests)}")
    (out / "collector.json").write_text(json.dumps(col.to_dict(), indent=2))
    if _progress_cb:
        _progress_cb("collector", str(out), len(col.requests))
    if har_result:
        (out / "har_import.json").write_text(json.dumps(har_result.to_dict(), indent=2))

    await _finish_pipeline(args, profile, col, out, start, total_steps, step_offset=2,
                           har_result=har_result, pre_auth_session=auto_auth_session)


async def cmd_quick(args) -> None:
    """No browser. Stackprint + desync + enrichment. Runs in ~60 seconds."""
    args._quick_mode = True
    start = time.monotonic()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # total_steps: 1 stackprint + 11 pipeline steps = 12
    total_steps = 12

    # ── 1. stackprint ───────────────────────────────────────────────────
    _step(1, total_steps, f"Fingerprinting stack: {args.target}")
    sp = Stackprint(args.target, timeout=args.timeout)
    profile = await sp.run()
    _err(f"Detected: {_profile_summary(profile)}")
    (out / "stackprint.json").write_text(json.dumps(profile.to_dict(), indent=2))

    if _maybe_bail_on_cdn(args, profile):
        return

    # Synthesize a minimal collector from stackprint's probe hits
    def _live_request(req_dict: dict) -> None:
        if _progress_cb:
            try:
                _progress_cb("request_added", req_dict)
            except Exception:
                pass

    col = Collector(args.target, on_request=_live_request)
    _seed_collector_from_profile(col, profile)

    # Also seed from OpenAPI spec if available
    added = await _seed_from_openapi(col, args.target)
    if added:
        _err(f"OpenAPI seeding: +{added} endpoint stubs from spec")

    _err(f"Seeded {len(col.requests)} endpoint stubs total")

    await _finish_pipeline(args, profile, col, out, start, total_steps, step_offset=1)


# ---------------------------------------------------------------------------
# Standalone crawl — used by the TUI Spider tab
# ---------------------------------------------------------------------------

async def run_crawl(args, on_request=None) -> "Collector":
    """Stackprint + crawl only. Writes stackprint.json + collector.json.

    on_request: optional callback(req_dict) fired for each new request — used
    by the TUI Spider tab to stream rows into the live table.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    _step(1, 2, f"Fingerprinting stack: {args.target}")
    sp = Stackprint(args.target, timeout=args.timeout)
    profile = await sp.run()
    _err(f"Detected: {_profile_summary(profile)}")
    (out / "stackprint.json").write_text(json.dumps(profile.to_dict(), indent=2))

    if not _PLAYWRIGHT_OK:
        _err("playwright not installed — cannot crawl")
        col = Collector(args.target, on_request=on_request)
        _seed_collector_from_profile(col, profile)
    else:
        _step(2, 2, "Crawling (Playwright)")
        col = Collector(args.target, on_request=on_request)
        auth_hdrs = _load_auth_headers(args)
        cfg_cls = None
        try:
            from crawler import CrawlConfig as cfg_cls
        except ImportError:
            pass
        if cfg_cls:
            cfg = cfg_cls(
                start_url=args.target,
                auth_state=getattr(args, "auth", None),
                max_pages=getattr(args, "max_pages", 80),
                max_depth=getattr(args, "max_depth", 4),
                headless=not getattr(args, "headed", False),
                allow_writes=False,
                extra_headers=auth_hdrs,
                hash_routing=getattr(profile, "hash_routing", False),
                allowed_hosts=getattr(args, "allowed_hosts", []),
                excluded_patterns=getattr(args, "excluded_patterns", []),
            )
            from crawler import Crawler
            from urllib.parse import urljoin
            crawler = Crawler(cfg, col)
            for path in profile.interesting_paths[:30]:
                if crawler._is_spa_route_candidate(path):
                    await crawler._enqueue(urljoin(args.target, path), 0)
            await crawler.run()
            _err(f"Pages visited: {len(crawler._visited)}")

    (out / "collector.json").write_text(json.dumps(col.to_dict(), indent=2))
    if _progress_cb:
        _progress_cb("collector", str(out), len(col.requests))
    return col


# ---------------------------------------------------------------------------
# Crawl pipeline (single-phase, two-phase, or HAR import)
# ---------------------------------------------------------------------------

async def _run_crawl_pipeline(args, profile: StackProfile, col: Collector,
                              out: Path, total_steps: int):
    """Decide crawl mode and execute. Populates `col` with requests.

    Returns (har_result, auto_auth_session). When auto_auth_session is non-None
    (two-phase ran), _finish_pipeline must skip its own AutoAuth block to avoid
    double-provisioning.
    """
    har_path = getattr(args, "har", None)
    if har_path:
        har_result = _import_har(args, col, total_steps)
        return har_result, None

    cli_auth_hdrs = _load_auth_headers(args)
    skip_auto = getattr(args, "no_auto_auth", False)
    force_auto = getattr(args, "auto_auth", False)
    # AutoAuth fires by default whenever the user didn't supply --auth-headers,
    # OR they explicitly forced it with --auto-auth. When AutoAuth is going to
    # fire, we use the two-phase crawl so the authenticated browser session
    # actually walks the post-login app surface.
    will_autoauth = not skip_auto and (force_auto or not cli_auth_hdrs)

    if not will_autoauth:
        await _run_single_crawl(args, profile, col, out, cli_auth_hdrs)
        return None, None

    auto_auth_session = await _run_two_phase_crawl(args, profile, col, out,
                                                   total_steps, cli_auth_hdrs)
    return None, auto_auth_session


def _import_har(args, col: Collector, total_steps: int):
    """Import HAR file into collector. Returns HARImportResult."""
    _step(2, total_steps, f"Importing HAR file: {args.har}")
    har_result = HARImporter(
        args.har,
        scope_origin=args.target,
        include_assets=getattr(args, "har_include_assets", False),
    ).load()
    if not har_result.requests:
        _err(f"HAR import failed — no usable entries. Notes: {har_result.notes}")
        sys.exit(2)
    for cr in har_result.requests:
        col.add_request(cr)
        if cr.response_status is not None:
            col.add_response_meta(
                cr.url, cr.response_status,
                cr.response_headers or {},
                body=cr.response_body,
            )
    _err(f"Imported {len(har_result.requests)}/{har_result.entries_total} entries from "
         f"{har_result.source_tool} HAR")
    if har_result.auth_headers:
        _err(f"  Auto-harvested auth headers: {list(har_result.auth_headers.keys())}")
    if har_result.entries_skipped_other_origin:
        _err(f"  Skipped (other origin): {har_result.entries_skipped_other_origin}")
    _err(f"[crawl] mode=har_import requests={len(har_result.requests)}")
    return har_result


async def _run_single_crawl(args, profile: StackProfile, col: Collector,
                            out: Path, cli_auth_hdrs: dict) -> None:
    """Single-phase crawl — anonymous when no auth provided, authed when
    --auth/--auth-headers/--auth-a are present. Matches legacy behaviour."""
    _step(2, 13, "Crawling (Playwright)")
    auth_state = args.auth or getattr(args, "auth_a", None)
    cfg = CrawlConfig(
        start_url=args.target,
        auth_state=auth_state,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        headless=not args.headed,
        allow_writes=args.allow_writes,
        extra_headers=cli_auth_hdrs,
        hash_routing=getattr(profile, "hash_routing", False),
    )
    crawler = Crawler(cfg, col)
    for path in profile.interesting_paths[:30]:
        if crawler._is_spa_route_candidate(path):
            await crawler._enqueue(urljoin(args.target, path), 0)
    await crawler.run()
    _err(f"Pages visited: {len(crawler._visited)}")
    if crawler._bodies_captured:
        _err(f"Response bodies captured: {crawler._bodies_captured} "
             f"({crawler._captured_body_bytes // 1024} KB total)")
    skipped_path = crawler.dump_skipped(str(out))
    if skipped_path:
        _err(f"Pages skipped: {len(crawler._skipped)} (see {skipped_path})")
    mode_label = "single_authed" if (auth_state or cli_auth_hdrs) else "single_anon"
    _err(f"[crawl] mode={mode_label} pages={len(crawler._visited)}")


async def _run_two_phase_crawl(args, profile: StackProfile, col: Collector,
                               out: Path, total_steps: int,
                               cli_auth_hdrs: dict):
    """Phase A (lightweight discovery) → AutoAuth → Phase B (full authed crawl).

    Both phases write to the same Collector (idempotent dedup on _seen_req_keys).
    Returns the AuthSession from AutoAuth so _finish_pipeline can skip its own
    AutoAuth call. The session may have has_auth=False if AutoAuth failed; in
    that case Phase B is skipped but the session is still returned so downstream
    knows AutoAuth was attempted.
    """
    _step(2, total_steps, "Phase A — pre-auth discovery crawl (Playwright)")
    cfg_a = CrawlConfig(
        start_url=args.target,
        max_pages=12,
        max_depth=2,
        headless=not args.headed,
        allow_writes=False,
        extra_headers=dict(cli_auth_hdrs),
        hash_routing=getattr(profile, "hash_routing", False),
        form_fill=False,        # don't submit forms (avoid duplicate registers)
        auto_click=False,       # don't trigger destructive button clicks
        auto_auth_retry=False,  # we run AutoAuth ourselves between phases
    )
    crawler_a = Crawler(cfg_a, col)
    for path in profile.interesting_paths[:20]:
        if crawler_a._is_spa_route_candidate(path):
            await crawler_a._enqueue(urljoin(args.target, path), 0)
    await crawler_a.run()
    phase_a_pages = len(crawler_a._visited)
    _err(f"  Phase A: {phase_a_pages} pages, {len(col.requests)} requests captured")

    # Mid-flight classify so AutoAuth can use the discovered endpoint surface.
    # Cheap (in-memory pattern matching) — re-runs in _finish_pipeline on the
    # full merged collector after Phase B.
    mid_result = classify(col, origin=args.target)

    _err("[*] AutoAuth — registering + logging in (between crawl phases)")
    js_routes = list(col._js_routes) if hasattr(col, "_js_routes") else None
    try:
        auto_auth_session = await AutoAuth(
            args.target, timeout=args.timeout,
            email_domain=getattr(args, "auth_email_domain", None),
            email=getattr(args, "auth_email", None),
            password=getattr(args, "auth_password", None),
            username=getattr(args, "auth_username", None),
        ).run(
            classifier_result=mid_result,
            js_routes=js_routes,
        )
    except Exception as exc:
        _err(f"  ✗ AutoAuth crashed: {type(exc).__name__}: {exc}")
        _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} phase_b_pages=0 auto_auth=error")
        return None

    if not auto_auth_session.has_auth:
        _err(f"  ✗ AutoAuth failed ({len(auto_auth_session.notes)} attempts) — "
             f"continuing with anonymous Phase B crawl (still useful for "
             f"public surface: SPA routes, JS bundles, GraphQL introspection, "
             f"unprotected admin paths). Re-run with --auth-headers / "
             f"--auth-email-domain for an authed deep-crawl.")
        for note in auto_auth_session.notes[:5]:
            _err(f"    · {note}")
        _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} "
             f"phase_b=anon auto_auth=failed")
        phase_b_headers: dict = dict(cli_auth_hdrs)
    else:
        kind = "token" if auto_auth_session.token else f"{len(auto_auth_session.cookies)} cookie(s)"
        _err(f"  ✓ AutoAuth: {kind} acquired ({auto_auth_session.credentials.username})")
        for note in auto_auth_session.notes:
            _err(f"    · {note}")
        phase_b_headers = {**cli_auth_hdrs, **auto_auth_session.to_auth_headers()}

    label = "authenticated" if auto_auth_session.has_auth else "anonymous (AutoAuth failed)"
    _err(f"[*] Phase B — {label} deep crawl (Playwright)")
    seed_paths = _seed_paths_for_authed_crawl(mid_result, args.target)
    cfg_b = CrawlConfig(
        start_url=args.target,
        auth_state=args.auth,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        headless=not args.headed,
        allow_writes=args.allow_writes,
        extra_headers=phase_b_headers,
        hash_routing=getattr(profile, "hash_routing", False),
        seed_paths=seed_paths,
        auto_auth_retry=False,  # already authed; don't double-trigger
    )
    crawler_b = Crawler(cfg_b, col)
    for path in profile.interesting_paths[:30]:
        if crawler_b._is_spa_route_candidate(path):
            await crawler_b._enqueue(urljoin(args.target, path), 0)
    try:
        await crawler_b.run()
    except Exception as exc:
        _err(f"  ✗ Phase B crashed: {type(exc).__name__}: {exc} — "
             f"proceeding with Phase A data + AutoAuth headers")
        _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} phase_b_pages=0 auto_auth=success")
        return auto_auth_session

    phase_b_pages = len(crawler_b._visited)
    _err(f"  Phase B: {phase_b_pages} pages")
    if crawler_b._bodies_captured:
        _err(f"  Phase B response bodies captured: {crawler_b._bodies_captured} "
             f"({crawler_b._captured_body_bytes // 1024} KB)")
    skipped_path = crawler_b.dump_skipped(str(out))
    if skipped_path:
        _err(f"  Phase B pages skipped: {len(crawler_b._skipped)} (see {skipped_path})")
    _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} "
         f"phase_b_pages={phase_b_pages} auto_auth=success")
    return auto_auth_session


_AUTH_GATED_PATH_KEYWORDS = (
    "/me", "/profile", "/account", "/admin", "/basket", "/cart",
    "/order", "/dashboard", "/settings", "/user", "/users",
    "/whoami", "/wallet", "/checkout",
)

# Generic REST conventions worth hitting AFTER authentication. These follow
# widespread API conventions (NOT app-specific paths) — most modern stacks
# expose at least one of these. App-specific paths (Juice Shop's
# /rest/user/authentication-details/, crAPI's /identity/api/v2/*, etc.) are
# discovered organically via stackprint + classifier; this list only contains
# patterns that ANY framework might use.
_POST_AUTH_PROBE_PATHS = (
    # Standard "list users" endpoints (case variants — APIs vary)
    "/api/users", "/api/Users", "/api/v1/users", "/api/v2/users", "/api/v3/users",
    # Self / current-user endpoints
    "/api/me", "/api/v1/me", "/api/users/me", "/users/me", "/me",
    "/api/whoami", "/api/profile", "/api/account", "/api/user",
    # Admin user-list endpoints
    "/api/admin/users", "/admin/users", "/api/admin", "/admin/api/users",
    # Field-selection / mass-fetch attempts (works against Hapi/Sails/etc.
    # APIs that honour ?fields= or ?include= parameters)
    "/api/users?fields=password,email,role",
    "/api/users?include=password,hash,salt",
    "/api/users/1", "/api/users/2",
)


def _seed_paths_for_authed_crawl(classifier_result, target: str) -> list:
    """Pull paths from Phase A that are likely to need auth (admin, /me,
    profile, basket, etc.) PLUS a static set of cross-framework post-auth
    data-leak endpoints, so Phase B explores them directly even if their
    links weren't visible while anonymous."""
    from urllib.parse import urlparse
    seeds: list[str] = []
    seen: set[str] = set()
    # Static probe set first — these routinely leak per-user data
    for path in _POST_AUTH_PROBE_PATHS:
        if path not in seen:
            seeds.append(path)
            seen.add(path)
    for f in classifier_result.request_findings:
        try:
            path = urlparse(f.url).path
        except Exception:
            continue
        if not path or path in seen:
            continue
        path_l = path.lower()
        if any(k in path_l for k in _AUTH_GATED_PATH_KEYWORDS):
            seeds.append(path)
            seen.add(path)
        if len(seeds) >= 35:
            break
    return seeds


async def _rescan_auth_gated_findings(col: Collector, classifier_result,
                                       target: str, auth_hdrs: dict,
                                       timeout: float, max_fetches: int = 25) -> int:
    """Re-fetch any classified auth/admin/user finding whose response body we
    never captured. App-agnostic: identifies candidates by classifier category
    + URL keyword match, NOT hardcoded paths. Backfills col.set_response_body
    so the enricher sees the JSON the crawler missed."""
    import httpx
    from classifier import Cat
    candidate_cats = {Cat.AUTH, Cat.ADMIN, Cat.IDOR, Cat.BFLA, Cat.MASS_ASSIGN}
    # URL fragment hints — generic patterns common to any framework
    auth_user_keywords = (
        "/user", "/users", "/profile", "/account", "/me", "/whoami",
        "/admin", "/dashboard", "/identity", "/auth", "/session",
        "/credential", "/wallet",
    )
    seen_urls: set[str] = set()
    targets: list[tuple[str, str]] = []
    # Pre-index existing requests so we know which URLs already have a body
    have_body: set[str] = {r.url for r in col.requests
                           if getattr(r, "response_body", None)}
    for f in classifier_result.request_findings:
        if f.url in seen_urls or f.url in have_body:
            continue
        if f.method not in ("GET", "HEAD"):
            continue  # only safe to re-fetch reads
        cats = set(f.categories) if hasattr(f, "categories") else set()
        cats_match = bool(cats & candidate_cats)
        path_lower = f.url.lower()
        kw_match = any(k in path_lower for k in auth_user_keywords)
        if not (cats_match or kw_match):
            continue
        seen_urls.add(f.url)
        targets.append((f.method, f.url))
        if len(targets) >= max_fetches:
            break
    if not targets:
        return 0
    fetched = 0
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=timeout, headers=auth_hdrs,
    ) as client:
        for method, url in targets:
            try:
                r = await client.request(method, url)
            except Exception:
                continue
            body = r.text
            if not body or len(body) < 8:
                continue
            # Backfill via add_request so it shows up in collector.json AND
            # set_response_body so the existing CapturedRequest (if any) gets
            # the body too.
            col.add_request(CapturedRequest(
                method=method, url=url, headers={}, body=None,
                resource_type="xhr", response_status=r.status_code,
                response_headers=dict(r.headers), response_body=body,
            ))
            col.set_response_body(url, body)
            fetched += 1
    return fetched


async def _finish_pipeline(
    args, profile: StackProfile, col: Collector,
    out: Path, start: float, total_steps: int, step_offset: int,
    har_result=None,                  # Optional[HARImportResult]
    pre_auth_session=None,            # Optional[AuthSession] from two-phase crawl
) -> None:
    offset = step_offset

    # Write collector.json now if not already written (quick mode skips the crawl step)
    collector_path = out / "collector.json"
    if not collector_path.exists():
        collector_path.write_text(json.dumps(col.to_dict(), indent=2))
        if _progress_cb:
            _progress_cb("collector", str(out), len(col.requests))

    # Canary lifecycle — starts here, closed in finally
    canary = None
    oob_mode = getattr(args, "oob", None)
    if oob_mode:
        canary = await Canary.create(mode=oob_mode)
        if canary.available:
            _err(f"OOB: interactsh session active ({canary._session.server_url if canary._session else '?'})")
        else:
            _err("OOB: interactsh-client not found — OOB probes disabled")

    # BrowserVerifier — shared Playwright browser for execution-proof
    # verification (XSS, DOM XSS, redirect). Lifecycle mirrors canary.
    browser_verifier = BrowserVerifier()
    await browser_verifier.__aenter__()
    if browser_verifier.available:
        _err("BrowserVerifier: Chromium ready for execution-proof XSS/redirect checks")
    else:
        _err("BrowserVerifier: unavailable — XSS detection falls back to body-grep")

    # ── File grabber — bulk-download leaked binaries / images / archives ──
    # Runs over every URL we know about (collector + interesting_paths) and
    # saves anything with a downloadable extension to <out>/downloads/.
    # PDFs, .kdbx, .bak, .sql, images-with-EXIF, source archives — all the
    # recon-goldmine artifacts the browser refused to render.
    if getattr(args, "passive", False):
        _err("[+] File grabber: skipped (passive mode)")
        grabber_result = FileGrabResult(out_dir=str(out / "downloads"))
    else:
        _err("[+] File grabber: collecting binary URLs from crawl + stackprint...")
        grabber_urls: list[str] = []
        grabber_urls.extend(r.url for r in col.requests)
        grabber_urls.extend(urljoin(args.target, p) for p in profile.interesting_paths)
        grabber_result = await FileGrabber(
            out_dir=str(out),
            max_files=200,
            max_bytes_per_file=10 * 1024 * 1024,
            timeout=args.timeout,
        ).run(grabber_urls, auth_headers=_load_auth_headers(args))
    if grabber_result.candidates_seen:
        ext_summary = ", ".join(f"{e}:{n}" for e, n in
                                sorted(grabber_result.by_extension().items(),
                                       key=lambda kv: -kv[1])[:8])
        _err(f"  grabbed {len(grabber_result.grabbed)}/{grabber_result.candidates_seen} files "
             f"({grabber_result.total_bytes // 1024} KB) — by ext: {ext_summary or 'none'}")
        if grabber_result.skipped_oversize:
            _err(f"  skipped (oversize): {grabber_result.skipped_oversize}")
    else:
        _err("  no downloadable URLs found")
    (out / "file_grabber.json").write_text(json.dumps(grabber_result.to_dict(), indent=2))

    # ── Challenge tracker pre-snapshot ───────────────────────────────────
    # Polls vulnerable-app scoreboards (Juice Shop /api/Challenges, WebGoat
    # lessonprogress) so we can diff at the end and report ground-truth bugs.
    tracker = ChallengeTracker(args.target, timeout=args.timeout)
    pre_snapshot = await tracker.snapshot()
    if not pre_snapshot.is_empty():
        _err(f"[*] Challenge tracker: {pre_snapshot.target_app} detected, "
             f"{len(pre_snapshot.solved_ids)}/{len(pre_snapshot.all_challenges)} pre-solved")

    # ── JS deep analysis ─────────────────────────────────────────────────
    _step(offset + 1, total_steps, "JS bundle deep analysis")
    js_urls = list(col._js_bundle_urls) + js_urls_from_profile(profile, args.target)
    js_result = None
    if js_urls:
        js_analyzer = JSDeepAnalyzer(js_urls[:12])
        js_result = await js_analyzer.run()
        _err(f"JS bundles analyzed: {js_result.files_analyzed}")
        _err(f"  endpoints: {len(js_result.endpoints)}  secrets: {len(js_result.secrets)}  "
             f"dom_xss: {len(js_result.dom_xss)}  auth_smells: {len(js_result.auth_smells)}")
        # Feed discovered endpoints back into collector for classifier
        for ep in js_result.endpoints:
            path = ep.path.replace("{id}", "1")
            url = urljoin(args.target, path)
            col.add_request(CapturedRequest(
                method=ep.method_hint if ep.method_hint != "unknown" else "GET",
                url=url, headers={}, body=None, resource_type="xhr",
            ))
        if js_result.source_maps:
            _err(f"  source maps: {len(js_result.source_maps)}")
        (out / "js_analysis.json").write_text(json.dumps(js_result.to_dict(), indent=2))
    else:
        _err("No JS bundles found to analyze")

    # ── DOM XSS verification (uses BrowserVerifier) ──────────────────────
    # Static-detected DOM XSS candidates (js_result.dom_xss) are validated
    # by driving the source from the URL and checking for execution in a
    # real browser. Runs only when both the JS analyzer found candidates
    # AND the BrowserVerifier launched successfully.
    dom_xss_result = None
    if (
        js_result
        and js_result.dom_xss
        and browser_verifier.available
        and not getattr(args, "passive", False)
    ):
        _err(f"[+] DOM XSS verification: {len(js_result.dom_xss)} candidate(s)")
        dom_xss_result = await DOMXSSProbe(browser_verifier, timeout=args.timeout).run(
            target=args.target,
            js_dom_xss_findings=js_result.dom_xss,
            auth_headers=_load_auth_headers(args),
        )
        _err(f"DOM XSS: {dom_xss_result.candidates_probed} probed, "
             f"{len(dom_xss_result.confirmed)} confirmed, "
             f"{len(dom_xss_result.likely)} likely")
        for f in dom_xss_result.confirmed[:5]:
            _err(f"  ✓ [{f.source}→{f.sink}] {f.probe_url[:80]}")

    # ── classify ────────────────────────────────────────────────────────
    _step(offset + 2, total_steps, "Classifying findings")
    result = classify(col, origin=args.target)
    _err(f"Findings: {len(result.request_findings)} endpoints scored")
    for cat, findings in sorted(result.by_category.items(), key=lambda x: -len(x[1])):
        _err(f"  {cat}: {len(findings)}")

    auth_hdrs = _load_auth_headers(args)
    # If no headers loaded from --auth-headers but HAR import gave us some,
    # adopt them — saves the user from typing them again.
    if not auth_hdrs and har_result and har_result.auth_headers:
        auth_hdrs = dict(har_result.auth_headers)
        _err(f"[*] Using auth headers harvested from HAR ({list(auth_hdrs.keys())})")

    # ── Auto register + login ─────────────────────────────────────────────
    # If user didn't supply --auth/--auth-headers, try to provision fresh
    # credentials by registering + logging in. The harvested token is merged
    # into auth_hdrs so all downstream probes run authenticated.
    # --auto-auth forces it even when headers are present; --no-auto-auth disables.
    # When a two-phase crawl already ran AutoAuth, pre_auth_session is set —
    # adopt it directly instead of provisioning a third account.
    auto_auth_session = pre_auth_session
    if pre_auth_session is not None:
        if pre_auth_session.has_auth:
            harvested = pre_auth_session.to_auth_headers()
            auth_hdrs = {**harvested, **auth_hdrs}
            _err(f"[*] Adopting AutoAuth session from two-phase crawl "
                 f"({pre_auth_session.credentials.username})")
    else:
        force_auto = getattr(args, "auto_auth", False)
        skip_auto = getattr(args, "no_auto_auth", False) or getattr(args, "passive", False)
        if not skip_auto and (force_auto or not auth_hdrs):
            _err("[*] Auto-auth: provisioning fresh account...")
            js_routes = list(col._js_routes) if hasattr(col, "_js_routes") else None
            auto_auth_session = await AutoAuth(
                args.target, timeout=args.timeout,
                email_domain=getattr(args, "auth_email_domain", None),
                email=getattr(args, "auth_email", None),
                password=getattr(args, "auth_password", None),
                username=getattr(args, "auth_username", None),
            ).run(
                classifier_result=result,
                js_routes=js_routes,
            )
            if auto_auth_session.has_auth:
                harvested = auto_auth_session.to_auth_headers()
                auth_hdrs = {**harvested, **auth_hdrs}
                kind = "token" if auto_auth_session.token else f"{len(auto_auth_session.cookies)} cookie(s)"
                _err(f"  ✓ Auto-auth: {kind} acquired ({auto_auth_session.credentials.username})")
                for note in auto_auth_session.notes:
                    _err(f"    · {note}")
            else:
                _err(f"  ✗ Auto-auth: no credentials harvested ({len(auto_auth_session.notes)} attempts)")

    # ── JWT attack analysis ───────────────────────────────────────────────
    _step(offset + 3, total_steps, "JWT attack analysis")
    jwt_result = None
    if getattr(args, "passive", False):
        _err("JWT: skipped (passive mode)")
    else:
        auth_findings = result.by_category.get("Auth/Session", [])
        if auth_findings or result.cookie_findings:
            jwt_result = await JWTAnalyzer(
                auth_headers=auth_hdrs,
                timeout=args.timeout,
                canary=canary,
                grabbed_key_files=grabber_result.grabbed,
            ).run(auth_findings, result.cookie_findings)
            _err(f"JWT: {jwt_result.tokens_tested} tokens tested, "
                 f"{len(jwt_result.confirmed)} attacks confirmed")

    # ── hidden parameter discovery ────────────────────────────────────────
    _step(offset + 4, total_steps, "Hidden parameter discovery")
    param_result = None
    if getattr(args, "passive", False):
        _err("Param miner: skipped (passive mode)")
    elif not getattr(args, "no_param_mine", False):
        param_result = await ParamMiner(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
            top_n=getattr(args, "param_mine_top", 10),
        ).run(result.request_findings)
        interesting_n = len(param_result.interesting)
        _err(f"Param miner: {param_result.endpoints_probed} endpoints probed, "
             f"{interesting_n} interesting params found")
    else:
        _err("Param miner: disabled (--no-param-mine)")

    # ── verify ───────────────────────────────────────────────────────────
    passive = getattr(args, "passive", False)
    if passive:
        _step(offset + 5, total_steps, "Verify: skipped (passive mode)")
        # Build a real (empty) VerifyReport rather than a stub so every
        # downstream code path that touches it (subsystem counts, JSON dump,
        # passing through to active_result.run) sees a normal object.
        verify_report = VerifyReport(results=[])
    else:
        _step(offset + 5, total_steps, "Verifying findings (active probes)")
        verify_report = await Verifier(
            result.request_findings,
            auth_headers=auth_hdrs,
            timeout=args.timeout,
            origin=args.target,
            canary=canary,
        ).run()

        # CORS pass — deduplicated check across all discovered API URLs
        api_urls = [f.url for f in result.request_findings]
        cors_results = await verify_cors(api_urls, auth_hdrs, timeout=args.timeout)
        verify_report.results.extend(cors_results)

        # JS secrets + source maps pass
        if js_result is not None:
            js_verify = await verify_js_findings(js_result, args.target, auth_hdrs, timeout=args.timeout)
            verify_report.results.extend(js_verify)

    # NOTE: this counts only the Verifier subsystem. Auth-bypass, active-scan,
    # IDOR, etc. each report their own confirmation totals further below.
    # The unified roll-up appears at the top of the markdown report.
    _err(f"Verifier: {len(verify_report.confirmed)} confirmed  "
         f"{len(verify_report.likely)} likely  "
         f"{len([r for r in verify_report.results if r.verdict == 'not_confirmed'])} not-confirmed")
    for r in verify_report.confirmed:
        _err(f"  ✓ [{r.categories[0] if r.categories else '?'}] {r.method} {r.url[:60]}")
        _err(f"      {r.evidence}")
    (out / "verify.json").write_text(json.dumps(verify_report.to_dict(), indent=2))

    # ── open redirect probe (scan only — skip in quick mode, no crawl data) ─
    _step(offset + 6, total_steps, "Open redirect probing")
    redirect_result = None
    if passive:
        _err("Open redirect: skipped (passive mode)")
    elif getattr(args, "har", None) or not getattr(args, "_quick_mode", False):
        redirect_result = await OpenRedirectProbe(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
            browser_verifier=browser_verifier,
        ).run(result.request_findings)
        _err(f"Open redirect: {redirect_result.endpoints_tested} endpoints tested, "
             f"{len(redirect_result.confirmed)} confirmed")
    else:
        _err("Open redirect: skipped in quick mode")

    # ── active injection scan (opt-in) ────────────────────────────────────
    active_result = None
    nosql_result = None
    auth_bypass_result = None
    idor_result = None
    account_a: Optional[Account] = None
    account_b: Optional[Account] = None
    if getattr(args, "active_scan", False):
        _step(offset + 7, total_steps, "Active injection scan (--active-scan)")
        active_result = await ActiveScanner(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
            canary=canary,
            browser_verifier=browser_verifier,
        ).run(
            verify_report.results,
            param_result.interesting if param_result else None,
            classifier_findings=result.request_findings,
        )
        _err(f"Active scan: {active_result.endpoints_scanned} endpoints, "
             f"{len(active_result.confirmed)} confirmed")

        _err("[+] NoSQL injection probing (--active-scan)")
        nosql_result = await NoSQLProbe(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
        ).run(result.request_findings)
        _err(f"NoSQL: {nosql_result.endpoints_tested} endpoints tested, "
             f"{len(nosql_result.confirmed)} confirmed")

        _err("[+] Auth-bypass fuzzing (--active-scan)")
        auth_bypass_result = await AuthBypassProbe(
            timeout=args.timeout,
        ).run(result, target=args.target)
        _err(f"Auth bypass: {auth_bypass_result.endpoints_tested} login endpoints tested, "
             f"{auth_bypass_result.payloads_sent} payloads sent, "
             f"{len(auth_bypass_result.confirmed)} confirmed")
        for f in auth_bypass_result.confirmed[:5]:
            _err(f"  ✓ {f.endpoint} field={f.field} payload={f.payload!r}")

        # ── Cross-account IDOR (BOLA) probe ─────────────────────────────
        # Wires up the long-dormant --auth-a / --auth-b flags. In auto mode
        # we use the existing auto_auth_session as account A and provision
        # a second account via AutoAuth for account B.
        _err("[+] Cross-account IDOR / BOLA probing (--active-scan)")
        if getattr(args, "auth_a", None) and getattr(args, "auth_b", None):
            account_a = IDORProbe.load_account_from_storage_state(args.auth_a, "A")
            account_b = IDORProbe.load_account_from_storage_state(args.auth_b, "B")
            if account_a and account_b:
                _err("  loaded accounts from --auth-a / --auth-b")
            else:
                _err("  ✗ failed to load --auth-a or --auth-b storage states")
        elif not getattr(args, "no_auto_auth", False):
            # Use existing auth_a from prior auto_auth or manual headers
            if auto_auth_session and auto_auth_session.has_auth:
                account_a = IDORProbe.account_from_auto_auth(auto_auth_session, "A")
            elif auth_hdrs:
                account_a = Account(label="A", headers=dict(auth_hdrs))
            if account_a:
                _err("  provisioning second account for cross-account comparison...")
                js_routes2 = list(col._js_routes) if hasattr(col, "_js_routes") else None
                second_session = await AutoAuth(
                    args.target, timeout=args.timeout,
                    email_domain=getattr(args, "auth_email_domain", None),
                ).run(classifier_result=result, js_routes=js_routes2)
                account_b = IDORProbe.account_from_auto_auth(second_session, "B")
                if account_b:
                    _err(f"  ✓ second account: {second_session.credentials.username}")
                else:
                    _err("  ✗ second-account provisioning failed")

        idor_result = await IDORProbe(timeout=args.timeout).run(
            target=args.target,
            account_a=account_a,
            account_b=account_b,
            classifier_findings=result.request_findings,
        )
        _err(f"Cross-account IDOR: {idor_result.endpoints_tested} endpoints, "
             f"{len(idor_result.confirmed)} confirmed, {len(idor_result.likely)} likely")
        for f in idor_result.confirmed[:5]:
            _err(f"  ✓ [{f.test_kind}] {f.method} {f.url[:70]}")
    else:
        _step(offset + 7, total_steps, "Active scan: skipped (pass --active-scan to enable)")

    # ── desync probe ─────────────────────────────────────────────────────
    _step(offset + 8, total_steps, "Desync / cache / protocol probes")
    desync_result = None
    if passive:
        _err("Desync: skipped (passive mode)")
    else:
        desync_urls = urls_from_classifier(result)
        if not desync_urls:
            desync_urls = [args.target]
        desync_probe = DesyncProbe(
            desync_urls[:15],
            profile=profile,
            timeout=args.timeout,
        )
        desync_result = await desync_probe.run()
        _err(f"Desync findings: {len(desync_result.findings)} ({len(desync_result.high())} high)")

    # ── Auto-fuzz (opt-in: --auto-fuzz) ──────────────────────────────────
    # Runs the Intruder payload library against every discovered parameter:
    # URL path IDs, query params, and JSON body fields. Category-aware payload
    # selection (IDOR→ids, Injection→sqli+xss+ssti, SSRF→redirects, etc.).
    # Independent of --active-scan so it can be used without the full suite.
    auto_fuzz_result = None
    if getattr(args, "auto_fuzz", False):
        _step(offset + 9, total_steps, "Auto-fuzz: Intruder payloads on discovered params (--auto-fuzz)")
        auto_fuzz_result = await auto_fuzz_findings(
            result.request_findings,
            auth_headers=auth_hdrs,
            timeout=args.timeout,
        )
        _err(f"Auto-fuzz: {auto_fuzz_result.endpoints_fuzzed} endpoints, "
             f"{auto_fuzz_result.requests_sent} requests, "
             f"{len(auto_fuzz_result.findings)} anomalies")
        for af in auto_fuzz_result.findings[:8]:
            _err(f"  ? {af.method} {af.url[:60]}  pos={af.position!r}  "
                 f"payload={af.payload[:25]!r}  [{af.anomaly[:50]}]")
        (out / "auto_fuzz.json").write_text(
            json.dumps(auto_fuzz_result.to_dict(), indent=2)
        )
    else:
        _err("Auto-fuzz: skipped (pass --auto-fuzz to enable)")

    # ── CRLF probe (always-on, except passive mode) ──────────────────────
    _step(offset + 9, total_steps, "CRLF injection probing")
    if passive:
        crlf_result = None
        _err("CRLF: skipped (passive mode)")
    else:
        crlf_result = await CRLFProbe(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
        ).run([f.url for f in result.request_findings[:20]])
        _err(f"CRLF: {crlf_result.urls_tested} URLs tested, {len(crlf_result.confirmed)} confirmed")

    # ── Content-type confusion probe ─────────────────────────────────────
    # Replays XHR JSON state-change findings with text/plain and form-urlencoded
    # Content-Types. If the server returns the same 2xx, the body is processed
    # without a type check — a cross-origin HTML form can submit it without a
    # CORS preflight, bypassing CORS-as-CSRF-protection entirely.
    if passive:
        ct_probe_result = CTProbeResult()
    else:
        ct_probe_result = await CTProbe(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
        ).run(result.request_findings)
    if ct_probe_result.endpoints_tested:
        _err(
            f"CT confusion: {ct_probe_result.endpoints_tested} endpoints tested, "
            f"{len(ct_probe_result.findings)} confirmed"
        )
        for f in ct_probe_result.findings[:5]:
            _err(f"  ✓ [{f.severity.upper()}] {f.method} {f.url[:70]} "
                 f"accepts '{f.confused_ct}'")
        (out / "ct_probe.json").write_text(
            json.dumps(ct_probe_result.to_dict(), indent=2)
        )
    else:
        _err("CT confusion: no XHR JSON state-change endpoints found — skipped")

    # ── WebSocket security probe ─────────────────────────────────────────
    # Gather WS URLs from passive capture, JS bundle extraction, and stackprint.
    # Then actively test each one: CSWSH (spoofed Origin), unauthenticated
    # access (no auth headers), null-origin, and subscription/channel IDOR.
    ws_probe_result = None
    if passive:
        ws_probe_result = WSProbeResult()
    else:
        ws_urls: list[str] = [ws.url for ws in col.websockets]
        if js_result:
            ws_urls.extend(js_result.websocket_urls)
        ws_urls.extend(getattr(profile, "websocket_urls", []))
        ws_probe_result = await WSProbe(
            auth_headers=auth_hdrs,
            timeout=args.timeout,
        ).run(
            ws_urls=ws_urls,
            captured_websockets=col.websockets,
            # Always probe the target origin for Socket.io even when no WS URL
            # was passively captured (chatbot / real-time features that only fire
            # after user interaction won't show up in the passive crawler results).
            http_origins=[args.target],
        )
    if ws_probe_result.urls_tested:
        _err(
            f"WS probe: {len(ws_probe_result.urls_tested)} URLs tested, "
            f"{len(ws_probe_result.confirmed)} findings"
        )
        for f in ws_probe_result.confirmed:
            _err(f"  ✓ [{f['severity'].upper()}] {f['category']} — {f['url'][:70]}")
        (out / "ws_probe.json").write_text(
            json.dumps(ws_probe_result.to_dict(), indent=2)
        )
    else:
        _err("WS probe: no WebSocket URLs discovered — skipped")

    # ── Access bypass replay ─────────────────────────────────────────────
    # Re-attempt URLs that returned 401/403 during the crawl using any auth
    # bypass we discovered later (forged JWTs, harvested SQLi tokens, the
    # second IDOR account). When a forbidden URL flips to 2xx, save the body
    # for offline analysis — this is the "go back and download what we
    # couldn't access before" pass.
    access_replay_result = None
    if not getattr(args, "no_access_replay", False) and not getattr(args, "passive", False):
        bypass_tokens: list[BypassToken] = []
        bypass_tokens.extend(tokens_from_jwt_attack(jwt_result, baseline_headers=auth_hdrs))
        bypass_tokens.extend(tokens_from_auth_bypass(auth_bypass_result, baseline_headers=auth_hdrs))
        bypass_tokens.extend(tokens_from_idor(idor_result, account_b))
        # Always include the current session as a sanity baseline — if a 403
        # flips to 200 with the *same* headers we already had, that's a transient
        # crawl-time failure worth surfacing too.
        if auth_hdrs:
            bypass_tokens.append(BypassToken(
                label="current_session", source="baseline",
                headers=dict(auth_hdrs),
                evidence="re-fetch with the headers already in use",
            ))
        access_replay_result = await AccessReplayProbe(
            out_dir=str(out), timeout=args.timeout,
        ).run(col, bypass_tokens)
        if access_replay_result.forbidden_urls_seen:
            _err(f"Access replay: {access_replay_result.forbidden_urls_seen} forbidden URLs, "
                 f"{access_replay_result.bypass_tokens_tried} bypass tokens, "
                 f"{len(access_replay_result.unlocked)} unlocked "
                 f"({access_replay_result.total_bytes_recovered // 1024} KB recovered)")
            for u in access_replay_result.unlocked[:8]:
                _err(f"  ✓ {u.original_status}→{u.new_status} [{u.bypass_source}] {u.url[:70]}")
        else:
            _err("Access replay: no 401/403 responses recorded — nothing to replay")
        (out / "access_replay.json").write_text(
            json.dumps(access_replay_result.to_dict(), indent=2)
        )

    # ── Challenge tracker post-snapshot + diff ────────────────────────────
    challenge_diff = None
    if not pre_snapshot.is_empty():
        post_snapshot = await tracker.snapshot()
        challenge_diff = ChallengeTracker.diff(pre_snapshot, post_snapshot)
        _err(f"[*] Challenge tracker: {challenge_diff.newly_triggered} new challenges solved during scan")
        for c in challenge_diff.triggered[:10]:
            _err(f"  ✓ [{c.difficulty}] {c.name} — {c.category}")

    # ── targeted post-classifier rescan ──────────────────────────────────
    # Generic across any web app: for any classified Auth/Admin/IDOR/User
    # finding whose body we never captured (typically because the SPA
    # didn't link to it but JS analysis or stackprint discovered the path),
    # fetch it once with the harvested token so the enricher can mine it.
    # This is what lets us pull per-user passwords from endpoints like
    # /rest/user/authentication-details/ without hardcoding that path.
    if auth_hdrs:
        rescanned = await _rescan_auth_gated_findings(
            col, result, args.target, auth_hdrs, args.timeout,
        )
        if rescanned:
            _err(f"Rescan: backfilled {rescanned} auth-gated bodies the crawler missed")

    # ── enrichment ───────────────────────────────────────────────────────
    # Mine every captured response body for users, hosts, secrets, images
    # and unvisited URLs. Writes per-entity folders under <out>/enrichment/.
    _step(offset + 10, total_steps, "Enriching response bodies (users, hosts, secrets, images)")
    extra_bodies = []
    if access_replay_result:
        for u in access_replay_result.unlocked:
            if u.body_path and Path(u.body_path).exists():
                try:
                    extra_bodies.append({
                        "url": u.url, "method": u.method,
                        "body": Path(u.body_path).read_text(errors="replace"),
                        "content_type": u.content_type,
                    })
                except Exception:
                    pass
    enrichment_result = Enricher(
        out_dir=str(out), target_origin=args.target,
    ).run(
        col,
        extra_bodies=extra_bodies or None,
        file_grabber_result=grabber_result,
        auto_auth_session=auto_auth_session,
    )
    s = enrichment_result.summary()
    by_type = ", ".join(f"{k}:{v}" for k, v in sorted(s["users_by_type"].items())) or "—"
    _err(f"Enrichment: {s['users']} identities ({by_type}), "
         f"{s['oauth_apps']} oauth apps, {s['hosts']} hosts, "
         f"{s['secrets']} secrets, {s['images_analyzed']} images analyzed, "
         f"{s['unvisited_urls']} unvisited URLs")
    # Loud password summary so the operator immediately sees crack rate
    _err(f"  Passwords: {s['passwords_plaintext']} plaintext + "
         f"{s['passwords_cracked']} cracked  →  "
         f"{s['passwords_plaintext'] + s['passwords_cracked']} usable "
         f"({s['passwords_uncracked']} hashes still uncracked)")
    if s['passwords_plaintext'] + s['passwords_cracked'] > 0:
        _err(f"  → see {s['out_dir']}/passwords.txt for the full <user>:<pass> list")
    _err(f"  written to {s['out_dir']}/")

    # ── IDOR-driven data extraction ──────────────────────────────────────
    # When IDORProbe confirmed cross-account reads, walk the affected
    # endpoints with each available identity to pull per-victim records.
    data_extract_result = None
    if idor_result and (idor_result.confirmed or idor_result.likely):
        from data_extractor import DataExtractor, AccountTokens
        accounts: list[AccountTokens] = []
        if account_a and account_a.headers:
            accounts.append(AccountTokens(
                label=account_a.label, headers=dict(account_a.headers),
                username=account_a.username, email=account_a.email,
            ))
        if account_b and account_b.headers:
            accounts.append(AccountTokens(
                label=account_b.label, headers=dict(account_b.headers),
                username=account_b.username, email=account_b.email,
            ))
        if accounts:
            _err(f"[+] IDOR data extractor: pulling records for "
                 f"{len(idor_result.confirmed) + len(idor_result.likely)} endpoints "
                 f"with {len(accounts)} accounts")
            data_extract_result = await DataExtractor(
                out_dir=str(out), timeout=args.timeout,
            ).run(idor_result=idor_result, accounts=accounts)
            _err(f"  pulled {data_extract_result.records_pulled} records "
                 f"({data_extract_result.per_user_endpoints} per-user, "
                 f"{data_extract_result.shared_endpoints} site-wide), "
                 f"saved to {data_extract_result.out_dir}/")

    # ── File-upload bypass tests ─────────────────────────────────────────
    # For any classified Cat.UPLOAD endpoint (or POST + multipart + path
    # match), run the full bypass suite (magic-byte spoof, double-ext,
    # Content-Type bypass, traversal, SVG-XSS, polyglot, oversize).
    upload_probe_result = None
    if not getattr(args, "no_upload_probe", False):
        upload_probe_result = await UploadProbe(
            out_dir=str(out), timeout=args.timeout, auth_headers=auth_hdrs,
        ).run(result)
        if upload_probe_result.endpoints_tested:
            _err(f"Upload probe: {upload_probe_result.endpoints_tested} endpoints, "
                 f"{upload_probe_result.tests_sent} tests sent, "
                 f"{len(upload_probe_result.confirmed)} confirmed RCE/XSS, "
                 f"{len(upload_probe_result.accepted)} accepted")
            for f in upload_probe_result.confirmed[:5]:
                _err(f"  ✓ [{f.test_name}] {f.endpoint[:60]} — marker {f.execution_marker}")
            (out / "upload_probe.json").write_text(
                json.dumps(upload_probe_result.to_dict(), indent=2)
            )

    # ── SQL dump (when ActiveScanner confirmed SQLi) ─────────────────────
    # Fingerprint dialect from confirmed SQLi response, replay UNION extraction
    # to dump schema + interesting tables (users/accounts/sessions/orders).
    # Cross-links any extracted user rows back into enrichment/users/<id>/db_rows/.
    sql_dump_result = None
    if active_result and not getattr(args, "no_sql_dump", False):
        sql_dump_result = await SQLDumper(
            out_dir=str(out), timeout=args.timeout, auth_headers=auth_hdrs,
        ).run(active_result, enrichment_result=enrichment_result)
        if sql_dump_result.fingerprints:
            fp_str = ", ".join(f"{f.dialect}({f.confidence:.2f})"
                                for f in sql_dump_result.fingerprints)
            _err(f"SQL dump: dialect={fp_str}, "
                 f"{len(sql_dump_result.schema)} tables in schema, "
                 f"{sql_dump_result.tables_dumped} dumped, "
                 f"{sql_dump_result.rows_dumped} rows pulled")
        elif sql_dump_result.notes:
            for n in sql_dump_result.notes:
                _err(f"  SQL dump: {n}")
        (out / "sql_dump.json").write_text(
            json.dumps(sql_dump_result.to_dict(), indent=2)
        )

    # ── LLM verification (opt-in) ────────────────────────────────────────
    # Local Ollama LLM verifies "likely" heuristic findings — adds llm_verdict
    # to each finding without overriding the heuristic. Cache is on disk so
    # repeated scans don't re-spend tokens.
    llm_verification_result = None
    if getattr(args, "llm", False):
        _err(f"[+] LLM verification: model={args.llm_model} host={args.llm_host} "
             f"budget={args.llm_budget}")
        async with LLMClient(
            host=args.llm_host, model=args.llm_model,
            cache_dir=str(out / "llm_cache"),
            budget=args.llm_budget, timeout=60.0,
            verbose=False,
        ) as llm:
            if not await llm.is_alive():
                _err(f"  ✗ Ollama not reachable at {args.llm_host} — skipping LLM step")
            else:
                verifier = LLMVerifier(llm)
                await verifier.verify_idor(idor_result, account_a, account_b)
                await verifier.verify_active_scan(active_result)
                await verifier.verify_auth_bypass(auth_bypass_result)
                llm_verification_result = verifier.result
                s = llm.stats
                _err(f"  LLM stats: {s.calls_made} calls, {s.cache_hits} cache hits, "
                     f"{s.errors} errors, avg {s.total_elapsed_ms / max(s.calls_made, 1):.0f}ms")
                _err(f"  Verdicts: {verifier.result.promoted_to_confirmed} promoted, "
                     f"{verifier.result.refuted} refuted, "
                     f"{verifier.result.inconclusive} inconclusive")
                (out / "llm_verification.json").write_text(
                    json.dumps(llm_verification_result.to_dict(), indent=2)
                )

    # ── report ────────────────────────────────────────────────────────────
    _step(offset + 11, total_steps, "Writing report")
    reporter = Reporter(
        result,
        target=args.target,
        profile=profile,
        desync=desync_result,
        jwt=jwt_result,
        params=param_result,
        active_scan=active_result,
        redirect=redirect_result,
        crlf=crlf_result,
        nosql=nosql_result,
        auto_auth=auto_auth_session,
        auth_bypass=auth_bypass_result,
        challenges=challenge_diff,
        idor=idor_result,
        dom_xss=dom_xss_result,
        files=grabber_result,
        har=har_result,
        access_replay=access_replay_result,
        enrichment=enrichment_result,
        data_extract=data_extract_result,
        llm_verification=llm_verification_result,
        upload_probe=upload_probe_result,
        sql_dump=sql_dump_result,
        ws_probe=ws_probe_result,
        ct_probe=ct_probe_result,
        auto_fuzz=auto_fuzz_result,
    )
    md_path, json_path = reporter.write(str(out))

    # Close canary
    if canary:
        await canary.close()
    # Close browser verifier
    try:
        await browser_verifier.__aexit__(None, None, None)
    except Exception:
        pass

    elapsed = time.monotonic() - start

    # Per-subsystem confirmation breakdown — single source of truth.
    # The "Verifier: 0 confirmed" line earlier is misleading on its own
    # because injection / IDOR / auth bypass run separately.
    subsystem_counts: list[tuple[str, int]] = [
        ("Verifier",    len(verify_report.confirmed)),
        ("Active scan", len(active_result.confirmed) if active_result else 0),
        ("Auth bypass", len(auth_bypass_result.confirmed) if auth_bypass_result else 0),
        ("NoSQL",       len(nosql_result.confirmed) if nosql_result else 0),
        ("CRLF",        len(crlf_result.confirmed) if crlf_result else 0),
        ("Open redir",  len(redirect_result.confirmed) if redirect_result else 0),
        ("JWT",         len(jwt_result.confirmed) if jwt_result else 0),
        ("IDOR/BOLA",   len(idor_result.confirmed) if idor_result else 0),
        ("DOM XSS",     len(dom_xss_result.confirmed) if dom_xss_result else 0),
        ("Access bypass", len(access_replay_result.unlocked) if access_replay_result else 0),
        ("Upload bypass", len(upload_probe_result.confirmed) if upload_probe_result else 0),
        ("SQL dump rows", sql_dump_result.rows_dumped if sql_dump_result else 0),
        ("WebSocket",    len(ws_probe_result.confirmed) if ws_probe_result else 0),
        ("CT confusion", len(ct_probe_result.confirmed) if ct_probe_result else 0),
        ("Auto-fuzz",   len(auto_fuzz_result.findings) if auto_fuzz_result else 0),
    ]
    total_confirmed = sum(n for _, n in subsystem_counts)

    print(f"\n{'═' * 60}", file=sys.stderr)
    print(f"  Done in {elapsed:.0f}s", file=sys.stderr)
    print(f"  Report:  {md_path}", file=sys.stderr)
    print(f"  JSON:    {json_path}", file=sys.stderr)
    if enrichment_result and enrichment_result.summary()["users"]:
        s = enrichment_result.summary()
        print(f"  Enriched: {s['users']} identities, {s['secrets']} secrets, "
              f"{s['hosts']} hosts → {s['out_dir']}/", file=sys.stderr)
    if data_extract_result and data_extract_result.records_pulled:
        print(f"  IDOR pull: {data_extract_result.records_pulled} records → "
              f"{data_extract_result.out_dir}/", file=sys.stderr)
    print(f"  ─── Confirmed exploits across all subsystems: {total_confirmed} ───",
          file=sys.stderr)
    for name, n in subsystem_counts:
        if n:
            print(f"     {name:<12} {n}", file=sys.stderr)
    print(f"{'═' * 60}", file=sys.stderr)

    # Print top 5 findings to stdout for quick review
    print(f"\nTop findings for {args.target}:")
    for f in result.request_findings[:5]:
        cats = ", ".join(f.categories[:2])
        print(f"  [{f.score:>3}] {f.method:<6} {f.url[:70]}  [{cats}]")

    if desync_result.high():
        print("\nHigh desync/cache risks:")
        for d in desync_result.high():
            print(f"  [{d.severity.upper()}] {d.risk} — {d.url[:60]}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _seed_from_openapi(col: Collector, origin: str) -> int:
    """
    Fetch OpenAPI/Swagger spec and seed collector with synthetic requests
    for every discovered endpoint. Critical for pure JSON API targets where
    the Playwright crawler finds no HTML links to follow.
    """
    import httpx

    candidates = ["/openapi.json", "/openapi.yaml", "/swagger.json",
                  "/swagger/v1/swagger.json", "/api-docs", "/api/docs"]

    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
        for path in candidates:
            url = urljoin(origin, path)
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                data = resp.json()
            except Exception:
                continue

            api_paths = data.get("paths", {})
            if not api_paths:
                continue

            added = 0
            for api_path, methods_spec in api_paths.items():
                # Replace path params with numeric stub: {id} → 1, {user_id} → 1
                concrete = re.sub(r"\{[^}]+\}", "1", api_path)
                full_url = urljoin(origin, concrete)

                for method, _ in methods_spec.items():
                    method = method.upper()
                    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                        continue
                    if method in ("PUT", "PATCH"):
                        body = '{"role":"admin","is_admin":true,"plan":"enterprise","status":"active"}'
                    elif method == "POST":
                        body = "{}"
                    else:
                        body = None
                    col.add_request(CapturedRequest(
                        method=method,
                        url=full_url,
                        headers={},
                        body=body,
                        resource_type="xhr",
                    ))
                    added += 1

            return added  # stop after first successful spec

    return 0


def _load_auth_headers(args) -> dict:
    """
    Load raw HTTP headers to inject into every browser and httpx request.
    Accepts either:
      - flat JSON:  {"Authorization": "Bearer eyJ..."}
      - save-auth format: {"app-name": {"Authorization": "Bearer eyJ..."}}
        In this case --auth-name selects which app's headers to use.
    """
    path = getattr(args, "auth_headers", None)
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text())
        # Detect save-auth multi-app format
        first = next(iter(data.values()), None)
        if isinstance(first, dict):
            name = getattr(args, "auth_name", None) or ""
            return data.get(name, {})
        return data
    except Exception as exc:
        _err(f"[warn] Could not load --auth-headers {path}: {exc}")
        return {}


def _profile_summary(p: StackProfile) -> str:
    parts: list[str] = []
    for cat in ("cdn", "frontend", "backend", "api", "auth"):
        techs = p.detected.get(cat, [])
        if techs:
            parts.append(", ".join(techs))
    return " + ".join(parts) if parts else "unknown"


def _seed_collector_from_profile(col: Collector, profile: StackProfile) -> None:
    """Build minimal request stubs from stackprint probe hits for classifier input."""
    from urllib.parse import urljoin

    for path in profile.interesting_paths:
        url = urljoin(profile.target, path)
        method = "POST" if "graphql" in path.lower() else "GET"
        body = None
        if "graphql" in path.lower():
            body = '{"query":"{ __schema { types { name } } }"}'
        col.add_request(CapturedRequest(
            method=method, url=url, headers={}, body=body, resource_type="xhr"
        ))


# ---------------------------------------------------------------------------
# repeat command (Burp Repeater equivalent)
# ---------------------------------------------------------------------------

async def cmd_repeat(args) -> None:
    if args.request:
        req = ReplayRequest.from_file(args.request, scheme="https" if not args.http else "http")
        # CLI overrides on top of loaded request
        if args.method:
            req.method = args.method.upper()
        if args.body:
            req.body = args.body
        for h in (args.header or []):
            k, _, v = h.partition(":")
            req.headers[k.strip()] = v.strip()
    else:
        if not args.url:
            _err("repeat: --url or --request required")
            sys.exit(1)
        req = ReplayRequest(
            method=(args.method or "GET").upper(),
            url=args.url,
            headers={k.partition(":")[0].strip(): k.partition(":")[2].strip() for k in (args.header or [])},
            body=args.body,
        )

    replacements: list[tuple[str, str]] = []
    for pair in (args.replace or []):
        if len(pair) == 2:
            replacements.append((pair[0], pair[1]))

    repeater = Repeater(
        follow_redirects=not args.no_follow,
        timeout=args.timeout,
        proxy=args.proxy,
    )
    results = await repeater.run(
        req,
        times=args.times,
        replacements=replacements or None,
        save_to=args.save,
    )
    if args.save:
        _err(f"Saved to {args.save}")


# ---------------------------------------------------------------------------
# fuzz command (Burp Intruder equivalent)
# ---------------------------------------------------------------------------

async def cmd_fuzz(args) -> None:
    # Build IntruderRequest from CLI args or --request file
    if args.request:
        rr = ReplayRequest.from_file(args.request)
        if args.method:
            rr.method = args.method.upper()
        if args.body:
            rr.body = args.body
        for h in (args.header or []):
            k, _, v = h.partition(":")
            rr.headers[k.strip()] = v.strip()
        req = IntruderRequest(method=rr.method, url=rr.url, headers=rr.headers, body=rr.body)
    else:
        if not args.url:
            _err("fuzz: --url or --request required")
            sys.exit(1)
        req = IntruderRequest(
            method=(args.method or "GET").upper(),
            url=args.url,
            headers={k.partition(":")[0].strip(): k.partition(":")[2].strip() for k in (args.header or [])},
            body=args.body,
        )

    payload_lists = [load_payloads(p) for p in args.payloads]
    if not payload_lists:
        _err("fuzz: at least one --payloads required")
        sys.exit(1)

    intruder = Intruder(
        follow_redirects=not args.no_follow,
        timeout=args.timeout,
        rate=args.rate,
        proxy=args.proxy,
        concurrency=args.concurrency,
    )

    filter_status = set(args.filter_status) if args.filter_status else None
    hide_status = set(args.hide_status) if args.hide_status else None

    result = await intruder.run(
        req,
        payload_lists=payload_lists,
        mode=args.mode,
        grep=args.grep,
        filter_status=filter_status,
        hide_status=hide_status,
        save_to=args.save,
    )

    if result.grep_hits:
        print(f"\nGrep hits ({len(result.grep_hits)}):")
        for r in result.grep_hits:
            print(f"  #{r.num}  status={r.status}  payload={r.payloads}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hxxpsin",
        description="Web attack surface mapper and triage tool",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── shared options ────────────────────────────────────────────────────
    def _add_common(cmd):
        cmd.add_argument("target", help="Target URL (e.g. https://target.com)")
        cmd.add_argument("--out", default="./output", help="Output directory")
        cmd.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout per request")
        cmd.add_argument("--auth-headers", metavar="PATH",
                         help="JSON file with raw headers to inject (flat or save-auth format)")
        cmd.add_argument("--auth-name", metavar="NAME",
                         help="App name to select from a save-auth multi-app headers file")
        cmd.add_argument("--ignore-cdn-block", action="store_true",
                         help="Don't bail when stackprint detects bot-blocking CDN "
                              f"({', '.join(sorted(_CDN_BOT_PROTECT))}). Default behaviour "
                              "is to stop the scan early since headless Playwright is "
                              "reliably blocked by these — set this to scan anyway "
                              "(typically gives 0 results unless paired with --har).")

    # ── scan ──────────────────────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Full pipeline (stackprint + crawl + classify + desync + enrich + report)")
    _add_common(scan)
    scan.add_argument("--auth",    help="Playwright storage_state JSON (cookies+localStorage)")
    scan.add_argument("--auth-a",  help="Attacker storage_state JSON (two-account IDOR mode)")
    scan.add_argument("--auth-b",  help="Victim storage_state JSON (two-account IDOR mode)")
    scan.add_argument("--auth-email-domain", metavar="DOMAIN", default=None,
                      help="Email domain to use when AutoAuth provisions a fresh account "
                           "(default: 'hxxpsin-pentest.com'). Real-world sites reject the "
                           "RFC-reserved '.test' TLD; point this at a domain you own / a "
                           "mailinator subdomain / etc. when scanning targets that verify.")
    scan.add_argument("--auth-email", metavar="EMAIL", default=None,
                      help="Operator-supplied email for AutoAuth login. When combined with "
                           "--auth-password, registration is SKIPPED and AutoAuth tries to "
                           "log in with these creds directly. Use this for targets where "
                           "you already have an account or signup is closed/manual.")
    scan.add_argument("--auth-password", metavar="PASSWORD", default=None,
                      help="Operator-supplied password — paired with --auth-email. Both "
                           "must be set together to skip registration.")
    scan.add_argument("--auth-username", metavar="USERNAME", default=None,
                      help="Operator-supplied username override (default: derived from "
                           "the local part of --auth-email). Use when the target's login "
                           "form uses a separate `username` field distinct from email.")
    scan.add_argument("--har",     metavar="FILE",
                      help="Skip the live crawler — import requests + responses from a "
                           "HAR file (Burp / ZAP / Chrome DevTools \"Save all as HAR with content\")")
    scan.add_argument("--har-include-assets", action="store_true",
                      help="With --har: also import images/CSS/fonts (default: skipped)")
    scan.add_argument("--headed",  action="store_true", help="Show browser window")
    scan.add_argument("--allow-writes", action="store_true", help="Allow PUT/PATCH/DELETE auto-clicks")
    scan.add_argument("--max-pages",  type=int, default=80,
                      help="Page-visit cap for the crawler (default: 80). Use 0 for unlimited.")
    scan.add_argument("--max-depth",  type=int, default=4,
                      help="BFS depth cap for the crawler (default: 4). Use 0 for unlimited.")
    scan.add_argument("--active-scan", action="store_true",
                      help="Enable active injection testing (blind SQLi, CMDi, path traversal, XXE). Loud.")
    scan.add_argument("--auto-fuzz", action="store_true",
                      help="Auto-place §markers§ on all discovered parameters and run Intruder payload "
                           "sets (IDOR→ids, Injection→sqli/xss/ssti, SSRF→redirects). "
                           "Faster than --active-scan; reports anomalies by status/length delta.")
    scan.add_argument("--oob", metavar="MODE", nargs="?", const="interactsh",
                      help="Enable OOB callbacks. MODE: 'interactsh' (default) or custom OOB domain.")
    scan.add_argument("--no-param-mine", action="store_true",
                      help="Disable hidden parameter discovery (enabled by default).")
    scan.add_argument("--no-access-replay", action="store_true",
                      help="Disable replay of crawl-time 401/403 URLs with discovered auth bypasses.")
    scan.add_argument("--no-upload-probe", action="store_true",
                      help="Disable file-upload bypass tests (magic-byte spoof, double-ext, SVG XSS, polyglot, etc.)")
    scan.add_argument("--no-sql-dump", action="store_true",
                      help="Disable schema dump + table extract for confirmed SQLi (default: enabled when SQLi found).")
    scan.add_argument("--llm", action="store_true",
                      help="Enable local LLM (Ollama) to verify 'likely' findings. "
                           "Requires Ollama running at --llm-host (default localhost:11434).")
    scan.add_argument("--llm-host", default="http://localhost:11434", metavar="URL",
                      help="Ollama HTTP endpoint (default: http://localhost:11434). "
                           "All inference is local — no data leaves this machine.")
    scan.add_argument("--llm-model", default="qwen2.5:7b", metavar="MODEL",
                      help="Ollama model tag to use (default: qwen2.5:7b — solid at "
                           "structured security triage). Must be pulled via `ollama pull <model>`.")
    scan.add_argument("--llm-budget", type=int, default=50, metavar="N",
                      help="Max LLM calls per scan (default: 50). Cached calls don't count.")
    scan.add_argument("--param-mine-top", type=int, default=10, metavar="N",
                      help="Number of top endpoints to param-mine (default: 10).")
    auto_auth_group = scan.add_mutually_exclusive_group()
    auto_auth_group.add_argument("--auto-auth", action="store_true",
                                 help="Force auto register+login even when --auth/--auth-headers is provided.")
    auto_auth_group.add_argument("--no-auto-auth", action="store_true",
                                 help="Disable auto register+login entirely.")

    # ── quick ─────────────────────────────────────────────────────────────
    quick = sub.add_parser("quick", help="No browser — stackprint + desync + enrichment + report (~60s)")
    _add_common(quick)

    # ── repeat ────────────────────────────────────────────────────────────
    repeat = sub.add_parser(
        "repeat",
        help="Replay a single request with optional substitutions (Burp Repeater equivalent)",
    )
    repeat.add_argument("--url",     help="Target URL")
    repeat.add_argument("--request", metavar="FILE", help="Raw HTTP or JSON request file")
    repeat.add_argument("--method",  default=None, help="HTTP method override (default: GET)")
    repeat.add_argument("--header",  action="append", metavar="K:V", help="Extra header (repeatable)")
    repeat.add_argument("--body",    help="Request body string")
    repeat.add_argument("--replace", action="append", nargs=2, metavar=("OLD", "NEW"),
                        help="String substitution applied to URL, headers, and body (repeatable)")
    repeat.add_argument("--times",   type=int, default=1, help="Number of times to send (default: 1)")
    repeat.add_argument("--no-follow", action="store_true", help="Disable redirect following")
    repeat.add_argument("--http",    action="store_true", help="Use HTTP instead of HTTPS for --request files")
    repeat.add_argument("--timeout", type=float, default=10.0)
    repeat.add_argument("--proxy",   help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    repeat.add_argument("--save",    metavar="FILE", help="Save request+response JSON to file")

    # ── fuzz ──────────────────────────────────────────────────────────────
    fuzz = sub.add_parser(
        "fuzz",
        help="Payload fuzzer with §marker§ positions (Burp Intruder equivalent)",
    )
    fuzz.add_argument("--url",     help="URL with §markers§ for injection points")
    fuzz.add_argument("--request", metavar="FILE", help="Raw HTTP or JSON request file with §markers§")
    fuzz.add_argument("--method",  default=None, help="HTTP method override")
    fuzz.add_argument("--header",  action="append", metavar="K:V", help="Extra header (repeatable)")
    fuzz.add_argument("--body",    help="Request body string with §markers§")
    fuzz.add_argument("--payloads", action="append", required=True, metavar="SPEC",
                      help="Payload source: built-in name (xss,sqli,lfi,bypass,ids,usernames,passwords,"
                           "methods,extensions), file path, or comma-separated values. Repeatable for pitchfork/cluster_bomb.")
    fuzz.add_argument("--mode", default="sniper",
                      choices=["sniper", "battering_ram", "pitchfork", "cluster_bomb"],
                      help="Attack mode (default: sniper)")
    fuzz.add_argument("--grep",   help="Regex pattern to flag in responses")
    fuzz.add_argument("--filter-status", type=int, nargs="+", metavar="CODE",
                      help="Only show responses with these status codes")
    fuzz.add_argument("--hide-status",   type=int, nargs="+", metavar="CODE",
                      help="Hide responses with these status codes")
    fuzz.add_argument("--rate",       type=float, default=0.0, metavar="N",
                      help="Max requests per second (0 = unlimited)")
    fuzz.add_argument("--concurrency", type=int, default=10,
                      help="Concurrent requests (default: 10)")
    fuzz.add_argument("--no-follow",  action="store_true", help="Disable redirect following")
    fuzz.add_argument("--timeout",    type=float, default=10.0)
    fuzz.add_argument("--proxy",      help="HTTP proxy URL")
    fuzz.add_argument("--save",       metavar="FILE", help="Save results JSON to file")

    return p


def main() -> None:
    import warnings
    warnings.filterwarnings("ignore")

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cmd_scan(args))
    elif args.command == "quick":
        asyncio.run(cmd_quick(args))
    elif args.command == "repeat":
        asyncio.run(cmd_repeat(args))
    elif args.command == "fuzz":
        asyncio.run(cmd_fuzz(args))


if __name__ == "__main__":
    main()
