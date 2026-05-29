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
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

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
import auth_config
import captcha as captcha_mod
import mailbox as mailbox_mod
import msf_ingest
import payload_server as payload_server_mod
import tunnel as tunnel_mod
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
from challenge_solver import solve_findings
from claude_client import ClaudeClient
from llm_client import LLMClient
from llm_verifier import LLMVerifier
from ollama_agent import run_ollama_agent
from openai_client import OpenAIClient
from nosql_probe import NoSQLProbe
from open_redirect import OpenRedirectProbe
from param_miner import ParamMiner
from ldap_dump import LDAPDumper
from scm_probe import SCMProbe
from smb_sink import SMBSink
from sql_dump import SQLDumper
from sql_probe import SQLProbe
from upload_probe import UploadProbe
from repeater import Repeater, ReplayRequest
from reporter import Reporter
from adaptive_planner import plan_stages, static_plan
from http_cache import HttpCache, HttpGovernorConfig
from pipeline_state import PipelineState
from pipeline_stages import build_probe_stages
from scheduler import run_stages
from stackprint import Stackprint, StackProfile
from surface_mapper import SurfaceMapperConfig, map_surface
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


def _servus_configured(ctx) -> bool:
    """True when the operator has wired up servus (token in env or [servus]
    block in hxxpsin.toml). Used as a pre-flight for --solve since servus
    holds the upstream provider key, not hxxpsin."""
    if os.environ.get("SERVUS_AGENT_TOKEN"):
        return True
    cfg = getattr(ctx, "config", None) if ctx is not None else None
    servus = getattr(cfg, "servus", None) if cfg is not None else None
    return bool(getattr(servus, "agent_token", None))


def _step(n: int, total: int, label: str) -> None:
    print(f"\n[{n}/{total}] {label}", file=sys.stderr)
    if _progress_cb:
        _progress_cb("step", n, total, label)


def _emit(event: str, *args) -> None:
    """Best-effort emit of a non-step progress event (tunnel_up, tunnel_hit,
    surface_step, llm_decision). Silently no-ops if no callback is registered."""
    if _progress_cb:
        try:
            _progress_cb(event, *args)
        except Exception:
            pass


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
# Operator-config + OOB lifecycle
# ---------------------------------------------------------------------------

@dataclass
class _ScanContext:
    """Shared state built once at scan-start, stashed on `args._ctx`. Carries
    operator config + lazily-started OOB infra (payload server + tunnel)."""
    config: "auth_config.Config"
    target_profile: "auth_config.TargetProfile"
    mail_backend: Optional[object] = None
    captcha_solver: Optional[object] = None
    payload_server: Optional[object] = None
    tunnel: Optional[object] = None
    public_url: Optional[str] = None
    smb_sink: Optional[object] = None
    msf_client: Optional[object] = None        # msf_ingest.MSFClient or None
    msf_workspace: str = ""                    # effective workspace for this scan
    msf_result: Optional[object] = None        # msf_ingest.MSFIngestResult, mutated in place
    http_cache: Optional[HttpCache] = None

    def to_dict(self) -> dict:
        return {
            "config_sources": [str(p) for p in self.config.sources],
            "matched_target": self.target_profile.matched_key,
            "mail_backend": type(self.mail_backend).__name__ if self.mail_backend else None,
            "captcha_solver": type(self.captcha_solver).__name__ if self.captcha_solver else None,
            "tunnel_backend": (self.tunnel.backend_name if self.tunnel else None),
            "public_url": self.public_url,
            "smb_sink": (self.smb_sink.to_dict() if self.smb_sink else None),
            "msf_backend": (self.msf_client.backend if self.msf_client else None),
            "msf_workspace": self.msf_workspace or None,
        }


async def _build_scan_context(args) -> _ScanContext:
    """Load operator config, resolve per-target overrides, and start the OOB
    tunnel + payload server. Returns a populated _ScanContext that downstream
    constructors read from. Failures degrade gracefully — probes check
    payload_server/public_url and no-op when missing."""
    try:
        cfg = auth_config.load(getattr(args, "auth_config", None))
    except auth_config.ConfigError as exc:
        _err(f"⚠ operator config error: {exc} — continuing with defaults")
        cfg = auth_config.Config()

    # Wire the [servus] section into the singleton ServusLLMClient so every
    # provider shim (ClaudeClient / OpenAIClient / LLMClient) picks up the
    # configured base URL, bearer token, and initiator subject. Env-var
    # overrides still win (see auth_config.load).
    try:
        import servus_client
        servus_client.configure_from_profile(cfg.servus)
    except Exception as e:
        _err(f"⚠ servus client init failed: {e} — falling back to env vars")

    tp = cfg.resolve_for(args.target)
    if cfg.sources or tp.matched_key:
        _err(f"[*] config: {auth_config.summary_for_target(cfg, args.target)}")

    ctx = _ScanContext(config=cfg, target_profile=tp)

    try:
        hg = cfg.http
        gov_cfg = HttpGovernorConfig(
            max_concurrent=hg.max_concurrent,
            requests_per_second=hg.requests_per_second,
            allow_hosts=list(hg.allow_hosts),
            deny_paths=list(hg.deny_paths),
        )
        ctx.http_cache = HttpCache(args.target, gov_cfg, timeout=getattr(args, "timeout", 8.0))
        await ctx.http_cache.__aenter__()
        _err(f"[*] HttpCache: rps={hg.requests_per_second} max_concurrent={hg.max_concurrent}")
    except Exception as exc:
        _err(f"⚠ HttpCache init failed: {exc}")

    # Mail backend — operator's [mail.*] block referenced by target, else None
    if tp.mail is not None:
        try:
            ctx.mail_backend = mailbox_mod.from_profile(tp.mail, target_url=args.target)
        except Exception as exc:
            _err(f"⚠ mail backend init failed: {exc}")

    # Captcha solver — only when [captcha].mode != 'none'
    snapshot = Path(args.out) / "manual-auth.json"
    try:
        ctx.captcha_solver = captcha_mod.from_profile(cfg.captcha, snapshot_path=snapshot)
    except NotImplementedError as exc:
        _err(f"⚠ {exc}")
    except Exception as exc:
        _err(f"⚠ captcha solver init failed: {exc}")

    # Payload server + tunnel — start both, surface the public URL
    if cfg.tunnel.backend != "none":
        try:
            ctx.payload_server = payload_server_mod.from_profile(cfg.payload_server)
            await ctx.payload_server.start()
            # Wire a per-hit callback so the TUI receives `tunnel_hit` events as
            # incoming OOB callbacks arrive (SSRF, XXE, OAuth leaks).
            try:
                ctx.payload_server.on_hit = lambda hit: _emit("tunnel_hit", hit.to_dict())
            except Exception:
                pass
            ctx.tunnel = tunnel_mod.from_profile(cfg.tunnel, local_url=ctx.payload_server.local_url)
            ctx.public_url = await ctx.tunnel.start()
            if ctx.public_url:
                _err(f"[*] OOB tunnel up: {cfg.tunnel.backend} → {ctx.public_url}")
                _emit("tunnel_up", cfg.tunnel.backend, ctx.public_url)
            else:
                _err(f"⚠ tunnel ({cfg.tunnel.backend}) started but no public URL surfaced")
        except tunnel_mod.TunnelError as exc:
            _err(f"⚠ tunnel skipped: {exc}")
            ctx.tunnel = None
            ctx.public_url = None
        except Exception as exc:
            _err(f"⚠ tunnel init failed: {type(exc).__name__}: {exc}")

    # SMB sink — opt-in via --allow-windows-destructive + --active-scan, since
    # binding an SMB listener is loud and only useful for the MSSQL UNC-coerce
    # path. Failure to start (port conflict, missing impacket) is non-fatal —
    # SQLProbe falls back to HTTP/DNS canary callbacks.
    if (getattr(args, "active_scan", False)
            and getattr(args, "allow_windows_destructive", False)):
        smb_port = getattr(args, "smb_port", 4445)
        try:
            sink = SMBSink(listen_port=smb_port)
            await sink.start()
            ctx.smb_sink = sink
            _err(f"[*] SMB sink up: 0.0.0.0:{smb_port} (share={sink.share_name}) — "
                 "NTLM hashes captured to sql_probe.json")
        except Exception as exc:
            _err(f"⚠ SMB sink not started: {type(exc).__name__}: {exc}")
            _err("    (port may need root or another process is bound; "
                 "xp_dirtree coercion will fall back to canary OOB only)")
            ctx.smb_sink = None

    # MSF Framework workspace — opt-in via [msf].enabled or --msf flag.
    # Tries msfrpcd first; falls back to direct Postgres. Failure here
    # never aborts the scan — the integration is supplementary.
    msf_profile = cfg.msf
    cli_force_on = bool(getattr(args, "msf", False))
    cli_force_off = bool(getattr(args, "no_msf", False))
    msf_active = ((msf_profile.enabled or cli_force_on) and not cli_force_off)
    if msf_active:
        # CLI overrides
        msf_profile.enabled = True  # in-memory mutation, doesn't persist
        if getattr(args, "msf_workspace", None):
            msf_profile.workspace = args.msf_workspace
        if getattr(args, "msf_push", False):
            msf_profile.push_findings = True
        ctx.msf_workspace = msf_profile.workspace or "default"
        try:
            ctx.msf_client = await msf_ingest.make_msf_client(msf_profile)
        except msf_ingest.MSFIngestError as exc:
            _err(f"⚠ msf skipped: {exc}")
            ctx.msf_client = None
        except Exception as exc:
            _err(f"⚠ msf init failed: {type(exc).__name__}: {exc}")
            ctx.msf_client = None
        if ctx.msf_client is not None:
            _err(f"[*] MSF integration up: backend={ctx.msf_client.backend} "
                 f"workspace={ctx.msf_workspace}"
                 + (" push=on" if msf_profile.push_findings else ""))
            _emit("msf_ingest_step", "connected", 0)

    return ctx


def _auto_auth_kwargs_from_ctx(args, fresh_account: bool = False) -> dict:
    """Pull AutoAuth-relevant fields off the scan context. CLI flags still win
    when set — config supplies fallbacks for absent values.

    `fresh_account=True` is used by the second-account IDOR provisioning path:
    we still want mail backend + captcha solver wired (to clear registration
    barriers), but we deliberately skip the named email/password/username so
    AutoAuth generates a distinct identity instead of re-logging the operator's
    primary account."""
    ctx: Optional[_ScanContext] = getattr(args, "_ctx", None)
    if ctx is None:
        return {}
    tp = ctx.target_profile
    kw: dict = {}
    if ctx.mail_backend is not None:
        kw["mail_backend"] = ctx.mail_backend
    if ctx.captcha_solver is not None:
        kw["captcha_solver"] = ctx.captcha_solver
    if tp.totp_secret and not fresh_account:
        kw["totp_secret"] = tp.totp_secret
    if not fresh_account:
        if tp.email and not getattr(args, "auth_email", None):
            kw["email"] = tp.email
        if tp.password and not getattr(args, "auth_password", None):
            kw["password"] = tp.password
        if tp.username and not getattr(args, "auth_username", None):
            kw["username"] = tp.username
    kw["manual_snapshot_path"] = Path(args.out) / "manual-auth.json"
    return kw


async def _teardown_scan_context(ctx: Optional[_ScanContext], out: Path) -> None:
    """Persist tunnel hits + close everything."""
    if ctx is None:
        return
    if ctx.http_cache is not None:
        try:
            await ctx.http_cache.__aexit__(None, None, None)
        except Exception:
            pass
    if ctx.payload_server is not None:
        try:
            hits = [h.to_dict() for h in ctx.payload_server.hits]
            (out / "tunnel_hits.json").write_text(json.dumps({
                "context": ctx.to_dict(),
                "hits": hits,
            }, indent=2))
            if hits:
                _err(f"OOB tunnel: {len(hits)} hit(s) captured → {out}/tunnel_hits.json")
        except Exception as exc:
            _err(f"⚠ tunnel_hits.json write failed: {exc}")
    if ctx.tunnel is not None:
        try:
            await ctx.tunnel.stop()
        except Exception:
            pass
    if ctx.payload_server is not None:
        try:
            await ctx.payload_server.stop()
        except Exception:
            pass
    if ctx.smb_sink is not None:
        try:
            await ctx.smb_sink.stop()
        except Exception:
            pass
    if ctx.mail_backend is not None:
        try:
            await ctx.mail_backend.aclose()
        except Exception:
            pass
    if ctx.msf_client is not None:
        try:
            await ctx.msf_client.disconnect()
        except Exception:
            pass


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

    # Operator config + OOB lifecycle — stashed on args for downstream
    # functions (AutoAuth, ActiveScanner, OpenRedirectProbe, UploadProbe)
    args._ctx = await _build_scan_context(args)
    try:
        await _cmd_scan_body(args, start, out)
    finally:
        await _teardown_scan_context(args._ctx, out)


async def _run_surface_mapper(args, out: Path) -> None:
    """Stage 0: attack-surface expansion. No-op unless the operator opted in
    via --auto-scope, --port-scan, --analyze-block, or has MSF enabled (MSF
    seeds the same scope from an existing workspace)."""
    auto_scope = getattr(args, "auto_scope", False)
    port_scan = getattr(args, "port_scan", "none")
    analyze_block = getattr(args, "analyze_block", False)
    ctx = getattr(args, "_ctx", None)
    msf_on = bool(ctx and ctx.msf_client is not None)
    if not (auto_scope or port_scan != "none" or analyze_block or msf_on):
        return

    cfg = SurfaceMapperConfig(
        auto_scope=auto_scope,
        port_scan=port_scan,
        analyze_block=analyze_block,
        analyze_block_max=getattr(args, "analyze_block_max", 20),
        scope_suffix=getattr(args, "scope_suffix", None),
    )

    def _log(event, fields):
        _err(f"[recon] {event} {fields}")
        # Surface mapper structured events include counts the TUI can show live.
        if isinstance(fields, dict):
            count = fields.get("count")
            if count is None:
                count = fields.get("n") or fields.get("hosts") or fields.get("vhosts")
            try:
                _emit("surface_step", str(event), int(count) if count is not None else 0)
            except Exception:
                pass

    _err("[+] Stage 0: surface mapping "
         f"(auto_scope={auto_scope} port_scan={port_scan} "
         f"analyze_block={analyze_block})")
    _emit("surface_step", "start", 0)
    scope = await map_surface(args.target, cfg, out_dir=out, log=_log)
    args._scope = scope

    # MSF host/service seed (in-place dedupe merge into scope.hosts).
    await _run_msf_recon_seed(args, scope, out)

    n_hosts = len(scope.hosts)
    n_ports = sum(len(h.open_ports) for h in scope.hosts)
    n_vh = sum(1 for v in scope.vhost_hits if v.distinct_from_baseline)
    n_asn = len(scope.asn)
    _err(f"[+] Surface map: {n_hosts} hosts, {n_ports} open ports, "
         f"{n_asn} ASN(s), {n_vh} distinct vhost responses "
         f"→ {out}/recon/scope.json")
    _emit("surface_step", "done", n_hosts)


async def _run_msf_recon_seed(args, scope, out: Path) -> None:
    """Pull MSF hosts/services into the Scope and persist updated scope.json.

    Runs from _run_surface_mapper after map_surface(); also called from
    _finish_pipeline when surface_mapper was skipped so MSF data can still
    augment enrichment without --auto-scope being set."""
    ctx = getattr(args, "_ctx", None)
    if ctx is None or ctx.msf_client is None:
        return

    def _log(event: str, fields: dict) -> None:
        _err(f"[msf] {event} {fields}")
        try:
            count = 0
            if isinstance(fields, dict):
                count = int(fields.get("hosts", 0) or fields.get("count", 0) or 0)
            _emit("msf_ingest_step", event, count)
        except Exception:
            pass

    workspace = ctx.msf_workspace or "default"
    result = await msf_ingest.augment_scope_from_msf(
        scope, ctx.msf_client, workspace, log_cb=_log,
    )
    if getattr(ctx.config.msf, "pull_sessions", True):
        await msf_ingest.pull_sessions_into_result(
            ctx.msf_client, args.target, workspace, result, log_cb=_log,
        )
        if result.sessions_on_target:
            host = urlparse(args.target).hostname or args.target
            sids = ", ".join(str(s.get("id")) for s in result.sessions_on_target)
            _err(f"⚠ MSF has live meterpreter on {host} "
                 f"(session id(s): {sids}) — you may already own this host")
    ctx.msf_result = result
    _err(f"[+] MSF: pulled {result.pulled_hosts} hosts, "
         f"{result.pulled_services} services, "
         f"{result.pulled_sessions} session(s) from workspace={workspace} "
         f"(backend={result.backend}, overlap={len(result.overlapped_hosts)})")

    # Persist the augmented scope so the TUI + downstream loaders see MSF data.
    recon_dir = out / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    try:
        (recon_dir / "scope.json").write_text(json.dumps(scope.to_dict(), indent=2))
    except Exception as exc:
        _err(f"⚠ scope.json rewrite failed: {exc}")


async def _cmd_scan_body(args, start, out) -> None:

    # total_steps: 2 stackprint+crawl + 11 pipeline steps = 13
    total_steps = 13

    # ── 0. surface mapper (opt-in via --auto-scope / --port-scan / --analyze-block)
    await _run_surface_mapper(args, out)

    # ── 1. stackprint ───────────────────────────────────────────────────
    _step(1, total_steps, f"Fingerprinting stack: {args.target}")
    sp = Stackprint(args.target, timeout=args.timeout)
    profile = await sp.run()
    _err(f"Detected: {_profile_summary(profile)}")
    _err(f"Interesting paths: {len(profile.interesting_paths)}")
    (out / "stackprint.json").write_text(json.dumps(profile.to_dict(), indent=2))

    if _maybe_bail_on_cdn(args, profile):
        return

    # ── 1b. SCM / config exposure probe (Stage 0) ───────────────────────
    # Walk a high-value path catalog (.git/HEAD, .env*, wp-config.php.bak,
    # composer.lock, .DS_Store, …) and confirm exposure via shape-aware
    # body matching. Any .env-shaped bodies are scanned through the
    # unified [[secrets]] catalog so leaked AWS/GitHub/Stripe keys surface
    # alongside the file finding. Runs pre-crawl, so we use whatever CLI-
    # supplied auth headers exist; in-crawl harvested tokens aren't
    # available yet at this point in the pipeline.
    scm_probe_result = None
    if not getattr(args, "no_scm_probe", False):
        scm_probe_result = await SCMProbe(
            out_dir=str(out), timeout=args.timeout,
            auth_headers=_load_auth_headers(args),
        ).run(args.target,
              extra_bases=list(profile.interesting_paths)[:8])
        if scm_probe_result.findings:
            crit = len(scm_probe_result.critical)
            _err(f"SCM probe: {len(scm_probe_result.findings)} exposure(s) "
                 f"({crit} critical)")
            for f in scm_probe_result.critical[:5]:
                _err(f"  ✗ [{f.severity}] {f.kind}: {f.url}")
        (out / "scm_probe.json").write_text(
            json.dumps(scm_probe_result.to_dict(), indent=2)
        )

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
                           har_result=har_result, pre_auth_session=auto_auth_session,
                           scm_probe_result=scm_probe_result)


async def cmd_quick(args) -> None:
    """No browser. Stackprint + desync + enrichment. Runs in ~60 seconds."""
    args._quick_mode = True
    start = time.monotonic()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # total_steps: 1 stackprint + 11 pipeline steps = 12
    total_steps = 12

    # ── 0. surface mapper (opt-in via --auto-scope / --port-scan / --analyze-block)
    await _run_surface_mapper(args, out)

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
            **_auto_auth_kwargs_from_ctx(args),
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
    sys.stderr.flush()
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
    # Hard wall-clock cap so a stuck Playwright / hung Chromium subprocess
    # can't burn 20+ minutes silently. The previous failure mode after a
    # mid-flight network change was a Playwright deadlock — no exception,
    # no traceback, just a hung process. asyncio.wait_for() turns that into
    # a recoverable TimeoutError instead of a silent freeze.
    phase_b_timeout = max(60, args.phase_b_timeout)
    # Flush stderr so the last status line before any future hang/SIGKILL
    # is visible — protects against tee/buffering swallowing it.
    sys.stderr.flush()
    try:
        await asyncio.wait_for(crawler_b.run(), timeout=phase_b_timeout)
    except asyncio.TimeoutError:
        _err(f"  ✗ Phase B exceeded {phase_b_timeout}s wall-clock cap — "
             f"Playwright is likely stuck (orphaned Chromium, network "
             f"change mid-flight, or a stalled navigation). Proceeding "
             f"with whatever Phase B captured before the timeout.")
        _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} "
             f"phase_b_pages={len(crawler_b._visited)} auto_auth=success timeout=true")
        sys.stderr.flush()
        return auto_auth_session
    except Exception as exc:
        _err(f"  ✗ Phase B crashed: {type(exc).__name__}: {exc} — "
             f"proceeding with Phase A data + AutoAuth headers")
        _err(f"[crawl] mode=two_phase phase_a_pages={phase_a_pages} phase_b_pages=0 auto_auth=success")
        sys.stderr.flush()
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


async def _run_scheduled_probe_wave(
    args,
    ps: PipelineState,
    *,
    offset: int,
    total_steps: int,
) -> PipelineState:
    """Run parallel probe stages via the scheduler."""
    _step(offset + 3, total_steps, "Scheduled probe wave (concurrent)")

    category_counts = {
        cat: len(findings)
        for cat, findings in ps.result.by_category.items()
    }
    stack_summary = f"server={ps.profile.detected.get('server', '?')} cdn={bool(ps.profile.detected.get('cdn'))}"
    llm_gen = None
    if getattr(args, "adaptive_plan", False) and _servus_configured(ps.ctx()):
        try:
            import servus_client
            client = servus_client.default_client()

            async def _gen(prompt, system=None, **kw):
                reply = await client.generate(
                    messages=[{"role": "user", "content": prompt}],
                    system=system or "",
                    expect_json=True,
                )
                return reply.reply

            llm_gen = _gen
        except Exception:
            pass

    ps.planner = await plan_stages(
        target=args.target,
        stack_summary=stack_summary,
        category_counts=category_counts,
        llm_generate=llm_gen,
        passive=ps.passive(),
        active_scan=getattr(args, "active_scan", False),
        auto_fuzz=getattr(args, "auto_fuzz", False),
    )
    if not getattr(args, "adaptive_plan", False):
        ps.planner = static_plan(
            passive=ps.passive(),
            active_scan=getattr(args, "active_scan", False),
            auto_fuzz=getattr(args, "auto_fuzz", False),
            has_graphql=category_counts.get("GraphQL", 0) > 0,
            has_race=category_counts.get("Race Condition", 0) > 0,
            has_oauth_urls=category_counts.get("Auth/Session", 0) > 0,
        )
    (ps.out / "planner.json").write_text(json.dumps(ps.planner.to_dict(), indent=2))

    def _on_stage_event(event: str, payload: dict) -> None:
        _emit(event, payload)
        name = payload.get("name", "?")
        if event == "stage_start":
            _err(f"  [stage] ▶ {name}")
        elif event == "stage_done":
            st = payload.get("status", "?")
            ms = payload.get("elapsed_ms", 0)
            _err(f"  [stage] ✓ {name} ({st}, {ms:.0f}ms)")

    resume_dir = Path(args.resume) if getattr(args, "resume", None) else None
    ps.scheduler_result = await run_stages(
        build_probe_stages(ps),
        ps,
        out_dir=ps.out if not resume_dir else resume_dir,
        max_concurrent=getattr(args, "stage_concurrency", 6),
        resume=bool(resume_dir),
        on_event=_on_stage_event,
    )
    for rec in ps.scheduler_result.records.values():
        if rec.error:
            ps.stage_errors.append(f"{rec.name}: {rec.error.message}")
    if ps.http_cache is not None:
        st = ps.http_cache.stats()
        _err(f"[*] HttpCache: {st['cached_entries']} cached responses")
    return ps


async def _write_pipeline_report(
    args, ps: PipelineState, profile: StackProfile, col: Collector,
    out: Path, start: float, offset: int, total_steps: int,
    har_result=None, scm_probe_result=None,
) -> tuple[str, str]:
    """Always-run report writer — safe to call from finally."""
    _step(offset + 11, total_steps, "Writing report")
    _ctx = ps.ctx()
    _tunnel_hits = list(_ctx.payload_server.hits) if (_ctx and _ctx.payload_server) else []
    _tunnel_info = _ctx.to_dict() if _ctx else {}
    _msf_ingest_obj = _ctx.msf_result if (_ctx and _ctx.msf_result) else None
    stage_timings = ps.scheduler_result.stage_timings if ps.scheduler_result else []
    reporter = Reporter(
        ps.result,
        target=args.target,
        profile=profile,
        desync=ps.desync_result,
        jwt=ps.jwt_result,
        params=ps.param_result,
        active_scan=ps.active_result,
        redirect=ps.redirect_result,
        crlf=ps.crlf_result,
        nosql=ps.nosql_result,
        sql_probe=ps.sql_probe_result,
        auto_auth=ps.auto_auth_session,
        auth_bypass=ps.auth_bypass_result,
        challenges=ps.challenge_diff,
        idor=ps.idor_result,
        dom_xss=ps.dom_xss_result,
        files=ps.grabber_result,
        har=har_result,
        access_replay=ps.access_replay_result,
        enrichment=ps.enrichment_result,
        data_extract=ps.data_extract_result,
        llm_verification=ps.llm_verification_result,
        solver=ps.solver_result,
        upload_probe=ps.upload_probe_result,
        sql_dump=ps.sql_dump_result,
        ldap_dump=ps.ldap_dump_result,
        scm_probe=scm_probe_result,
        ws_probe=ps.ws_probe_result,
        ct_probe=ps.ct_probe_result,
        auto_fuzz=ps.auto_fuzz_result,
        tunnel_hits=_tunnel_hits,
        tunnel_info=_tunnel_info,
        msf_ingest=_msf_ingest_obj,
        graphql_probe=ps.graphql_result,
        oauth_probe=ps.oauth_result,
        race_probe=ps.race_result,
        stage_timings=stage_timings,
        stage_errors=ps.stage_errors,
        verify_report=ps.verify_report,
    )
    return reporter.write(str(out))


async def _finish_pipeline(
    args, profile: StackProfile, col: Collector,
    out: Path, start: float, total_steps: int, step_offset: int,
    har_result=None,                  # Optional[HARImportResult]
    pre_auth_session=None,            # Optional[AuthSession] from two-phase crawl
    scm_probe_result=None,            # Optional[SCMProbeResult] from pre-crawl probe
) -> None:
    # `os` is referenced below the function's later `import os` statements,
    # which would otherwise make Python treat the name as local from byte 0.
    # Importing it at the top avoids UnboundLocalError on early references.
    import os
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
                **_auto_auth_kwargs_from_ctx(args),
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

    # ── Scheduled concurrent probe wave ─────────────────────────────────
    _ctx_scan = getattr(args, "_ctx", None)
    ps = PipelineState(
        args=args, profile=profile, col=col, out=out,
        start=start, total_steps=total_steps, step_offset=offset,
        har_result=har_result, pre_auth_session=pre_auth_session,
        scm_probe_result=scm_probe_result,
        canary=canary, browser_verifier=browser_verifier,
        http_cache=_ctx_scan.http_cache if _ctx_scan else None,
        grabber_result=grabber_result, pre_snapshot=pre_snapshot,
        js_result=js_result, dom_xss_result=dom_xss_result,
        result=result, auto_auth_session=auto_auth_session,
        auth_hdrs=auth_hdrs,
    )
    ps = await _run_scheduled_probe_wave(args, ps, offset=offset, total_steps=total_steps)
    jwt_result = ps.jwt_result
    param_result = ps.param_result
    verify_report = ps.verify_report or VerifyReport(results=[])
    redirect_result = ps.redirect_result
    active_result = ps.active_result
    nosql_result = ps.nosql_result
    sql_probe_result = ps.sql_probe_result
    auth_bypass_result = ps.auth_bypass_result
    idor_result = ps.idor_result
    account_a = ps.account_a
    account_b = ps.account_b
    desync_result = ps.desync_result
    auto_fuzz_result = ps.auto_fuzz_result
    crlf_result = ps.crlf_result
    ct_probe_result = ps.ct_probe_result
    ws_probe_result = ps.ws_probe_result
    graphql_result = ps.graphql_result
    oauth_result = ps.oauth_result
    race_result = ps.race_result
    access_replay_result = ps.access_replay_result

    md_path, json_path = ("", "")
    challenge_diff = enrichment_result = data_extract_result = None
    upload_probe_result = sql_dump_result = ldap_dump_result = None
    llm_verification_result = solver_result = None
    try:
        # ── Challenge tracker post-snapshot + diff ────────────────────────────
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
        # MSF creds/loot/notes/vulns → enrichment (in place; mutates
        # ctx.msf_result so the Reporter sees one combined object).
        _ctx_msf = getattr(args, "_ctx", None)
        if _ctx_msf is not None and _ctx_msf.msf_client is not None:
            try:
                _ctx_msf.msf_result = await msf_ingest.merge_msf_into_enrichment(
                    enrichment_result, _ctx_msf.msf_client,
                    _ctx_msf.msf_workspace or "default",
                    accum=_ctx_msf.msf_result,
                    log_cb=lambda ev, fields: _err(f"[msf] {ev} {fields}"),
                )
                r = _ctx_msf.msf_result
                _err(f"[+] MSF merge: creds={r.pulled_creds} loot={r.pulled_loot} "
                     f"notes={r.pulled_notes} vulns={r.pulled_vulns}")
            except Exception as exc:
                _err(f"⚠ msf merge failed: {type(exc).__name__}: {exc}")
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
            _ctx = getattr(args, "_ctx", None)
            upload_probe_result = await UploadProbe(
                out_dir=str(out), timeout=args.timeout, auth_headers=auth_hdrs,
                payload_server=(_ctx.payload_server if _ctx else None),
                public_url=(_ctx.public_url if _ctx else None),
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
        
        # ── LDAP/AD dump (when ActiveScanner / classifier surfaces LDAP injection) ──
        # Vendor-fingerprint the directory (OpenLDAP / Active Directory / ApacheDS /
        # OpenDJ), confirm boolean-blind injection at the param level, then extract
        # high-value attributes (sAMAccountName, memberOf, userAccountControl, SPN,
        # adminCount, LAPS, GMSA). AD UAC flags get parsed into named tags so
        # KERBEROASTABLE / ASREPROASTABLE / DOMAIN_ADMIN / LAPS_READABLE surface
        # directly in the report. Cross-links into enrichment/users/<id>/ldap/.
        ldap_dump_result = None
        if active_result and not getattr(args, "no_ldap_dump", False):
            ldap_dump_result = await LDAPDumper(
                out_dir=str(out), timeout=args.timeout, auth_headers=auth_hdrs,
            ).run(active_result,
                  classifier_findings=result.request_findings,
                  enrichment_result=enrichment_result)
            if ldap_dump_result.fingerprints:
                fp_str = ", ".join(f"{f.vendor}({f.confidence:.2f})"
                                    for f in ldap_dump_result.fingerprints)
                _err(f"LDAP dump: vendor={fp_str}, "
                     f"{len(ldap_dump_result.confirmed_injections)} confirmed injection(s), "
                     f"{len(ldap_dump_result.accounts)} account(s) dumped, "
                     f"{len(ldap_dump_result.high_value)} high-value tag(s)")
            elif ldap_dump_result.notes:
                for n in ldap_dump_result.notes:
                    _err(f"  LDAP dump: {n}")
            (out / "ldap_dump.json").write_text(
                json.dumps(ldap_dump_result.to_dict(), indent=2)
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
        
        # ── Agentic solver (opt-in) ─────────────────────────────────────────
        # Hand the top classifier findings to an LLM agent with http_request /
        # browser_eval / read_finding / run_nuclei tools. Each finding gets a
        # bounded turn budget; the agent returns a verdict + evidence per
        # finding. Provider is selectable: 'claude' (Anthropic API, native
        # tool-use) or 'ollama' (local model, ReAct JSON prompting).
        solver_result = None
        if getattr(args, "solve", False):
            provider = (getattr(args, "solve_provider", "claude") or "claude").lower()
            storage_state = args.auth or getattr(args, "auth_a", None)
            # Pick model default based on provider when the user didn't specify
            if not args.solve_model:
                args.solve_model = {
                    "ollama": "qwen2.5:7b",
                    "openai": "gpt-5",
                    "claude": "claude-opus-4-7",
                }.get(provider, "claude-opus-4-7")
        
            # Forward solver events to the TUI so the LLM tab can show decisions live.
            def _solver_event(kind, *evargs):
                try:
                    if kind == "solve_start" and len(evargs) >= 3:
                        idx, method, url = evargs[0], evargs[1], evargs[2]
                        _emit("llm_decision", {
                            "stage": "start", "finding_index": idx,
                            "method": method, "url": url,
                            "model": args.solve_model, "provider": provider,
                        })
                    elif kind == "solve_done" and len(evargs) >= 3:
                        idx, verdict, reason = evargs[0], evargs[1], evargs[2]
                        _emit("llm_decision", {
                            "stage": "verdict", "finding_index": idx,
                            "verdict": verdict, "reason": reason,
                            "model": args.solve_model, "provider": provider,
                        })
                except Exception:
                    pass
        
            if provider == "ollama":
                _err(f"[+] Solver (ollama): model={args.solve_model} "
                     f"top_n={args.solve_top} max_turns={args.solve_max_turns} "
                     f"budget={args.solve_budget}")
                async with LLMClient(
                    host=args.llm_host, model=args.solve_model,
                    cache_dir=str(out / "ollama_solver_cache"),
                    budget=args.solve_budget, timeout=120.0,
                    verbose=False,
                ) as llm:
                    if not await llm.is_alive():
                        _err(f"  ✗ Ollama not reachable at {args.llm_host} — skipping")
                    else:
                        solver_result = await solve_findings(
                            llm_generate=llm.generate,
                            model_name=args.solve_model,
                            budget_stats=llm.stats,
                            classifier_result=result,
                            target=args.target,
                            out_dir=out,
                            auth_headers=auth_hdrs,
                            storage_state_path=storage_state,
                            top_n=args.solve_top,
                            verbose=args.solve_verbose,
                            public_url=(_ctx.public_url if _ctx else None),
                            on_event=_solver_event,
                        )
                        s = llm.stats
                        _err(f"  Ollama stats: {s.calls_made} calls, "
                             f"{s.cache_hits} cache hits, {s.errors} errors, "
                             f"avg {s.total_elapsed_ms / max(s.calls_made, 1):.0f}ms")
                        _err(f"  Verdicts: {solver_result.confirmed} confirmed, "
                             f"{solver_result.refuted} refuted, "
                             f"{solver_result.inconclusive} inconclusive"
                             + (f", ⚠ {solver_result.refusals} refusal(s)"
                                if solver_result.refusals else ""))
                        (out / "solver.json").write_text(
                            json.dumps(solver_result.to_dict(), indent=2)
                        )
            elif provider == "openai":
                if not _servus_configured(_ctx):
                    _err(
                        "[!] --solve requires servus — set SERVUS_AGENT_TOKEN "
                        "(or [servus].agent_token_env in hxxpsin.toml); skipping"
                    )
                else:
                    _err(f"[+] Solver (openai via servus): model={args.solve_model} "
                         f"top_n={args.solve_top} max_turns={args.solve_max_turns} "
                         f"budget={args.solve_budget}")
                    async with OpenAIClient(
                        model=args.solve_model,
                        cache_dir=str(out / "openai_cache"),
                        budget=args.solve_budget,
                        timeout=120.0,
                        max_tokens=2048,
                        verbose=False,
                    ) as oa:
                        if not await oa.is_alive():
                            _err("  ✗ servus unreachable — skipping")
                        else:
                            solver_result = await solve_findings(
                                llm_generate=oa.generate,
                                model_name=oa.model,
                                budget_stats=oa.stats,
                                classifier_result=result,
                                target=args.target,
                                out_dir=out,
                                auth_headers=auth_hdrs,
                                storage_state_path=storage_state,
                                top_n=args.solve_top,
                                verbose=args.solve_verbose,
                                public_url=(_ctx.public_url if _ctx else None),
                                on_event=_solver_event,
                            )
                            s = oa.stats
                            _err(f"  OpenAI stats: {s.calls_made} calls, "
                                 f"{s.cache_hits} cache hits, {s.errors} errors, "
                                 f"{s.total_input_tokens}in / {s.total_output_tokens}out tokens")
                            _err(f"  Verdicts: {solver_result.confirmed} confirmed, "
                                 f"{solver_result.refuted} refuted, "
                                 f"{solver_result.inconclusive} inconclusive"
                                 + (f", ⚠ {solver_result.refusals} refusal(s)"
                                    if solver_result.refusals else ""))
                            (out / "solver.json").write_text(
                                json.dumps(solver_result.to_dict(), indent=2)
                            )
            else:
                if not _servus_configured(_ctx):
                    _err(
                        "[!] --solve requires servus — set SERVUS_AGENT_TOKEN "
                        "(or [servus].agent_token_env in hxxpsin.toml); skipping"
                    )
                else:
                    _err(f"[+] Solver (claude via servus): model={args.solve_model} "
                         f"top_n={args.solve_top} max_turns={args.solve_max_turns} "
                         f"budget={args.solve_budget}")
                    async with ClaudeClient(
                        model=args.solve_model,
                        cache_dir=str(out / "claude_cache"),
                        budget=args.solve_budget,
                        timeout=120.0,
                        max_tokens=2048,
                        verbose=False,
                    ) as claude:
                        if not await claude.is_alive():
                            _err("  ✗ servus unreachable — skipping")
                        else:
                            solver_result = await solve_findings(
                                llm_generate=claude.generate,
                                model_name=claude.model,
                                budget_stats=claude.stats,
                                classifier_result=result,
                                target=args.target,
                                out_dir=out,
                                auth_headers=auth_hdrs,
                                storage_state_path=storage_state,
                                top_n=args.solve_top,
                                verbose=args.solve_verbose,
                                public_url=(_ctx.public_url if _ctx else None),
                                on_event=_solver_event,
                            )
                            s = claude.stats
                            _err(f"  Claude stats: {s.calls_made} calls, "
                                 f"{s.cache_hits} cache hits, {s.errors} errors, "
                                 f"{s.total_input_tokens}in / {s.total_output_tokens}out tokens")
                            _err(f"  Verdicts: {solver_result.confirmed} confirmed, "
                                 f"{solver_result.refuted} refuted, "
                                 f"{solver_result.inconclusive} inconclusive"
                                 + (f", ⚠ {solver_result.refusals} refusal(s)"
                                    if solver_result.refusals else ""))
                            (out / "solver.json").write_text(
                                json.dumps(solver_result.to_dict(), indent=2)
                            )
        
        # ── MSF push-back (opt-in via [msf].push_findings or --msf-push) ────
        _ctx_push = getattr(args, "_ctx", None)
        if (_ctx_push is not None and _ctx_push.msf_client is not None
                and _ctx_push.config.msf.push_findings):
            try:
                _ctx_push.msf_result = await msf_ingest.push_findings(
                    _ctx_push.msf_client, args.target,
                    result.request_findings,
                    out_dir=out,
                    min_score=_ctx_push.config.msf.push_min_score,
                    accum=_ctx_push.msf_result,
                    log_cb=lambda ev, fields: _err(f"[msf] {ev} {fields}"),
                )
                n_pushed = len(_ctx_push.msf_result.pushed_vulns)
                if n_pushed:
                    _err(f"[+] MSF push: {n_pushed} finding(s) recorded as vulns "
                         f"in workspace={_ctx_push.msf_workspace}")
            except Exception as exc:
                _err(f"⚠ msf push failed: {type(exc).__name__}: {exc}")
        
        # ── MSF module suggestions (PR1/Bundle B — non-network, pure mapping) ──
        if (_ctx_push is not None and _ctx_push.msf_client is not None
                and getattr(_ctx_push.config.msf, "suggest_modules", True)):
            if _ctx_push.msf_result is None:
                _ctx_push.msf_result = msf_ingest.MSFIngestResult(
                    backend=_ctx_push.msf_client.backend,
                    workspace=_ctx_push.msf_workspace or "default",
                )
            for f in (result.request_findings or []):
                url = getattr(f, "url", "") or ""
                if not url:
                    continue
                hints = await msf_ingest.suggest_modules(_ctx_push.msf_client, f)
                if hints:
                    _ctx_push.msf_result.suggested_modules[url] = hints
        
    except Exception as exc:
        _err(f"⚠ pipeline post-phase error: {type(exc).__name__}: {exc}")
    finally:
        ps.challenge_diff = challenge_diff
        ps.enrichment_result = enrichment_result
        ps.data_extract_result = data_extract_result
        ps.upload_probe_result = upload_probe_result
        ps.sql_dump_result = sql_dump_result
        ps.ldap_dump_result = ldap_dump_result
        ps.llm_verification_result = llm_verification_result
        ps.solver_result = solver_result
        try:
            md_path, json_path = await _write_pipeline_report(
                args, ps, profile, col, out, start, offset, total_steps,
                har_result=har_result, scm_probe_result=scm_probe_result,
            )
        except Exception as exc:
            _err(f"⚠ report write failed: {type(exc).__name__}: {exc}")
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
        ("MSSQL",       len(sql_probe_result.confirmed) if sql_probe_result else 0),
        ("NTLM hashes", sql_probe_result.ntlm_hashes_captured if sql_probe_result else 0),
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
        # ── Stage 0 recon (surface_mapper) — all OFF by default ─────────
        cmd.add_argument("--auto-scope", action="store_true",
                         help="Run Stage 0 attack-surface expansion BEFORE stackprint: "
                              "RDAP whois on the seed domain, passive subdomain "
                              "enumeration (crt.sh + Wayback CDX), and ASN/CIDR "
                              "lookup via Team Cymru. Passive only — no port scans, "
                              "no brute force. Writes output/recon/scope.json.")
        cmd.add_argument("--port-scan", choices=("none", "web", "full"),
                         default="none", metavar="MODE",
                         help="Per-host TCP port scan. 'none' (default) skips it; "
                              "'web' tries a curated ~80-port web-app list; 'full' "
                              "adds another ~50 non-web service ports. Refuses "
                              "RFC1918, link-local, and shared-CDN ranges. Also "
                              "enables Host-header vhost differencing on every "
                              "open web port when multiple hostnames resolve to "
                              "the same IP.")
        cmd.add_argument("--analyze-block", action="store_true",
                         help="Reverse-DNS sweep the ASN-owned CIDR for the seed "
                              "host. Refuses prefixes wider than /20 unless "
                              "--analyze-block-max is raised. Loud — only enable "
                              "on programs whose scope clearly covers the netblock.")
        cmd.add_argument("--analyze-block-max", type=int, default=20, metavar="N",
                         help="Maximum CIDR width allowed for --analyze-block "
                              "sweeps (default: 20 → /20 max, ~4k hosts). Raise "
                              "with care.")
        cmd.add_argument("--scope-suffix", default=None, metavar="DOMAIN",
                         help="Override the auto-derived eTLD+1 used by --auto-scope. "
                              "Pass this for multi-label TLDs like 'target.co.uk' "
                              "or when you want a tighter scope than the apex domain.")
        # ── Metasploit Framework workspace integration ───────────────────
        msf_group = cmd.add_mutually_exclusive_group()
        msf_group.add_argument("--msf", action="store_true",
                               help="Force-enable Metasploit workspace integration "
                                    "(overrides [msf].enabled in operator config). "
                                    "Tries msfrpcd first; falls back to direct PG. "
                                    "Pulls hosts/services/creds/loot/notes into "
                                    "Stage 0 recon + enrichment. See [msf] in "
                                    "hxxpsin.toml.example for the full schema.")
        msf_group.add_argument("--no-msf", action="store_true",
                               help="Force-disable MSF integration even when "
                                    "operator config has [msf].enabled = true.")
        cmd.add_argument("--msf-workspace", metavar="NAME", default=None,
                         help="Override [msf].workspace for this run (default: "
                              "whatever the config says, usually 'default').")
        cmd.add_argument("--msf-push", action="store_true",
                         help="Push confirmed hxxpsin findings back into the MSF "
                              "workspace as vulns. Idempotent via msf_pushed.json. "
                              "Requires the RPC backend (push not supported when "
                              "auto-fallback lands on direct-PG).")

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
    scan.add_argument("--auth-config", metavar="PATH", default=None,
                      help="Path to an extra operator-config TOML file. Loaded on top "
                           "of ~/.config/hxxpsin/config.toml and ./hxxpsin.toml. "
                           "Controls mail backends (IMAP/Mailhog/mail.tm), captcha "
                           "handling, the public tunnel (cloudflared/ngrok/static), "
                           "and per-target overrides (TOTP secret, real email, etc.). "
                           "See hxxpsin.toml.example for the full schema.")
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
    scan.add_argument("--phase-b-timeout", type=int, default=600, metavar="SEC",
                      help="Wall-clock cap on Phase B (authenticated deep crawl) "
                           "in seconds (default: 600). On timeout, Phase B is "
                           "abandoned and the scan continues with Phase A data "
                           "+ AutoAuth headers. Prevents Playwright deadlocks "
                           "from burning the whole scan budget.")
    scan.add_argument("--active-scan", action="store_true",
                      help="Enable active injection testing (blind SQLi, CMDi, path traversal, XXE). Loud.")
    scan.add_argument("--allow-windows-destructive", action="store_true",
                      help="Enable destructive Windows probes: MSSQL xp_cmdshell loud commands "
                           "(net user, systeminfo, dir c:\\), sp_addlogin, and DOS-reserved-name "
                           "uploads (CON/NUL/AUX — can LOCK Windows fileshares). Also starts the "
                           "SMB sink on --smb-port to capture NTLMv2 hashes via xp_dirtree UNC "
                           "coercion. Off by default. Read the warnings in --help carefully.")
    scan.add_argument("--smb-port", type=int, default=4445, metavar="PORT",
                      help="Listen port for the NTLM-capture SMB sink (default: 4445). "
                           "Port 445 requires root + pf/iptables redirect. Use a port-suffixed "
                           "UNC payload (\\\\host:4445\\share) when 445 is unavailable.")
    scan.add_argument("--auto-fuzz", action="store_true",
                      help="Auto-place §markers§ on all discovered parameters and run Intruder payload "
                           "sets (IDOR→ids, Injection→sqli/xss/ssti, SSRF→redirects). "
                           "Faster than --active-scan; reports anomalies by status/length delta.")
    scan.add_argument("--resume", metavar="OUT_DIR", default=None,
                      help="Resume a prior scan: skip stages already in OUT_DIR/stages/*.json")
    scan.add_argument("--desync-confirm", action="store_true",
                      help="Run safe CL.TE/TE.CL differential smuggling confirmation (opt-in)")
    scan.add_argument("--adaptive-plan", action="store_true",
                      help="Use servus LLM to prioritize probe stages (requires SERVUS_AGENT_TOKEN)")
    scan.add_argument("--stage-concurrency", type=int, default=6, metavar="N",
                      help="Max concurrent pipeline stages (default: 6)")
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
    scan.add_argument("--no-ldap-dump", action="store_true",
                      help="Disable LDAP/AD attribute extraction for confirmed LDAP injection (default: enabled when LDAP injection found).")
    scan.add_argument("--no-scm-probe", action="store_true",
                      help="Disable SCM/config exposure probe (.git/.svn/.env/wp-config.php.bak/etc).")
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
    scan.add_argument("--solve", action="store_true",
                      help="Enable the agentic solver — for each of the top findings, "
                           "run a tool-use loop (http/browser/nuclei) to confirm or "
                           "refute the bug. Provider is set with --solve-provider.")
    scan.add_argument("--solve-provider", default="claude",
                      choices=["claude", "openai", "ollama"],
                      help="Backend for --solve. ALL providers route through "
                           "servus's chat-complete endpoint (set "
                           "SERVUS_AGENT_TOKEN). 'claude' / 'openai' / "
                           "'ollama' selects which upstream servus calls; "
                           "API keys live in servus, not here. Default: claude.")
    scan.add_argument("--solve-model", default=None, metavar="MODEL",
                      help="Model ID for --solve. Default depends on provider: "
                           "claude→claude-opus-4-7, openai→gpt-5.5, "
                           "ollama→qwen2.5:7b.")
    scan.add_argument("--solve-top", type=int, default=5, metavar="N",
                      help="Number of top classifier findings to hand to the solver "
                           "(default: 5).")
    scan.add_argument("--solve-max-turns", type=int, default=10, metavar="N",
                      help="Max agent turns per finding (default: 10).")
    scan.add_argument("--solve-budget", type=int, default=40, metavar="N",
                      help="Max total Claude API calls across the whole scan "
                           "(default: 40). Cached calls don't count.")
    scan.add_argument("--solve-verbose", action="store_true",
                      help="Stream every prompt, assistant turn, tool call, "
                           "and tool result to stderr while the solver runs. "
                           "Lets you watch Claude reason in real time.")
    scan.add_argument("--solve-thinking", type=int, default=0, metavar="TOKENS",
                      help="Enable Claude extended thinking with this many "
                           "reasoning tokens per turn (e.g. 4096). 0 disables. "
                           "When enabled, temperature is forced to 1.0 per the "
                           "Anthropic API constraint.")
    scan.add_argument("--nuclei-bin", default="nuclei", metavar="PATH",
                      help="Path to the nuclei binary used by the solver's run_nuclei "
                           "tool (default: 'nuclei' on PATH).")
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
