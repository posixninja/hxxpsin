"""
pipeline_stages.py — Scheduled probe stages for _finish_pipeline.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from access_replay import (
    AccessReplayProbe, BypassToken,
    tokens_from_jwt_attack, tokens_from_auth_bypass, tokens_from_idor,
)
from active_scanner import ActiveScanner, auto_fuzz_findings
from auth_bypass import AuthBypassProbe
from auto_auth import AutoAuth
from classifier import Cat
from crlf_probe import CRLFProbe
from ct_probe import CTProbe, CTProbeResult
from desync_probe import DesyncProbe, urls_from_classifier
from graphql_probe import GraphQLProbe
from idor_probe import IDORProbe, Account
from jwt_attack import JWTAnalyzer
from nosql_probe import NoSQLProbe
from oauth_probe import OAuthProbe
from open_redirect import OpenRedirectProbe
from param_miner import ParamMiner
from race_probe import RaceProbe
from scheduler import Stage, persist_stage_result
from sql_probe import SQLProbe
from verifier import Verifier, VerifyReport, verify_cors, verify_js_findings
from ws_probe import WSProbe, WSProbeResult

if TYPE_CHECKING:
    from pipeline_state import PipelineState


def _err(ps: "PipelineState", msg: str) -> None:
    print(msg, file=sys.stderr)


def _planner_allows(ps: "PipelineState", name: str) -> bool:
    if ps.planner is None:
        return True
    return ps.planner.is_enabled(name)


def _http(ps: "PipelineState"):
    return ps.http_cache


def _save_stage(ps: "PipelineState", name: str, data: dict | None) -> None:
    if not data:
        return
    ps.stage_artifacts[name] = data
    try:
        persist_stage_result(ps.out, name, data)
    except Exception:
        pass


def _auto_auth_kwargs(args, fresh_account: bool = False) -> dict:
    ctx = getattr(args, "_ctx", None)
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


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

async def stage_jwt(ps: "PipelineState") -> None:
    if ps.passive():
        _err(ps, "JWT: skipped (passive mode)")
        return
    auth_findings = ps.result.by_category.get("Auth/Session", [])
    if not (auth_findings or ps.result.cookie_findings):
        _err(ps, "JWT: no auth surfaces")
        return
    ps.jwt_result = await JWTAnalyzer(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        canary=ps.canary,
        grabbed_key_files=ps.grabber_result.grabbed,
    ).run(auth_findings, ps.result.cookie_findings)
    _err(ps, f"JWT: {ps.jwt_result.tokens_tested} tokens, {len(ps.jwt_result.confirmed)} confirmed")
    _save_stage(ps, "jwt", ps.jwt_result.to_dict() if hasattr(ps.jwt_result, "to_dict") else None)


async def stage_param_miner(ps: "PipelineState") -> None:
    if ps.passive() or getattr(ps.args, "no_param_mine", False):
        _err(ps, "Param miner: skipped")
        return
    ps.param_result = await ParamMiner(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        top_n=getattr(ps.args, "param_mine_top", 10),
    ).run(ps.result.request_findings)
    _err(ps, f"Param miner: {ps.param_result.endpoints_probed} endpoints, "
         f"{len(ps.param_result.interesting)} interesting")


async def stage_verifier(ps: "PipelineState") -> None:
    if ps.passive():
        ps.verify_report = VerifyReport(results=[])
        _err(ps, "Verifier: skipped (passive)")
        return
        ps.verify_report = await Verifier(
            ps.result.request_findings,
            auth_headers=ps.auth_hdrs,
            timeout=ps.args.timeout,
            origin=ps.args.target,
            canary=ps.canary,
            http_cache=_http(ps),
        ).run()
    api_urls = [f.url for f in ps.result.request_findings]
    cors_results = await verify_cors(api_urls, ps.auth_hdrs, timeout=ps.args.timeout)
    ps.verify_report.results.extend(cors_results)
    if ps.js_result is not None:
        js_verify = await verify_js_findings(
            ps.js_result, ps.args.target, ps.auth_hdrs, timeout=ps.args.timeout,
        )
        ps.verify_report.results.extend(js_verify)
    _err(ps, f"Verifier: {len(ps.verify_report.confirmed)} confirmed")
    (ps.out / "verify.json").write_text(json.dumps(ps.verify_report.to_dict(), indent=2))
    _save_stage(ps, "verifier", ps.verify_report.to_dict())


async def stage_open_redirect(ps: "PipelineState") -> None:
    if ps.passive() or os.environ.get("HXXPSIN_SKIP_REDIRECT"):
        return
    if not (getattr(ps.args, "har", None) or not getattr(ps.args, "_quick_mode", False)):
        _err(ps, "Open redirect: skipped in quick mode")
        return
    ctx = ps.ctx()
    ps.redirect_result = await OpenRedirectProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        browser_verifier=ps.browser_verifier,
        payload_server=(ctx.payload_server if ctx else None),
        public_url=(ctx.public_url if ctx else None),
    ).run(ps.result.request_findings)
    _err(ps, f"Open redirect: {len(ps.redirect_result.confirmed)} confirmed")


async def stage_desync(ps: "PipelineState") -> None:
    if ps.passive():
        return
    desync_urls = urls_from_classifier(ps.result) or [ps.args.target]
    confirm = getattr(ps.args, "desync_confirm", False)
    ps.desync_result = await DesyncProbe(
        desync_urls[:15],
        profile=ps.profile,
        timeout=ps.args.timeout,
        confirm_smuggling=confirm,
    ).run()
    _err(ps, f"Desync: {len(ps.desync_result.findings)} findings")


async def stage_crlf(ps: "PipelineState") -> None:
    if ps.passive():
        return
        ps.crlf_result = await CRLFProbe(
            auth_headers=ps.auth_hdrs,
            timeout=ps.args.timeout,
            http_cache=_http(ps),
        ).run([f.url for f in ps.result.request_findings[:20]])
    _err(ps, f"CRLF: {len(ps.crlf_result.confirmed)} confirmed")


async def stage_ct_probe(ps: "PipelineState") -> None:
    if ps.passive():
        ps.ct_probe_result = CTProbeResult()
        return
        ps.ct_probe_result = await CTProbe(
            auth_headers=ps.auth_hdrs,
            timeout=ps.args.timeout,
            http_cache=_http(ps),
        ).run(ps.result.request_findings)
    (ps.out / "ct_probe.json").write_text(json.dumps(ps.ct_probe_result.to_dict(), indent=2))


async def stage_ws_probe(ps: "PipelineState") -> None:
    if ps.passive():
        ps.ws_probe_result = WSProbeResult()
        return
    ws_urls = [ws.url for ws in ps.col.websockets]
    if ps.js_result:
        ws_urls.extend(ps.js_result.websocket_urls)
    ws_urls.extend(getattr(ps.profile, "websocket_urls", []))
    ps.ws_probe_result = await WSProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
    ).run(
        ws_urls=ws_urls,
        captured_websockets=ps.col.websockets,
        http_origins=[ps.args.target],
    )
    (ps.out / "ws_probe.json").write_text(json.dumps(ps.ws_probe_result.to_dict(), indent=2))


async def stage_graphql_probe(ps: "PipelineState") -> None:
    urls = [f.url for f in ps.result.request_findings]
    ps.graphql_result = await GraphQLProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
    ).run(ps.args.target, urls, http_cache=_http(ps))
    (ps.out / "graphql_probe.json").write_text(json.dumps(ps.graphql_result.to_dict(), indent=2))
    _save_stage(ps, "graphql_probe", ps.graphql_result.to_dict())
    _err(ps, f"GraphQL: {len(ps.graphql_result.confirmed)} confirmed")


async def stage_oauth_probe(ps: "PipelineState") -> None:
    urls = [f.url for f in ps.result.request_findings]
    ps.oauth_result = await OAuthProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
    ).run(ps.args.target, urls, http_cache=_http(ps))
    (ps.out / "oauth_probe.json").write_text(json.dumps(ps.oauth_result.to_dict(), indent=2))
    _save_stage(ps, "oauth_probe", ps.oauth_result.to_dict())


async def stage_race_probe(ps: "PipelineState") -> None:
    ps.race_result = await RaceProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
    ).run(ps.result, http_cache=_http(ps))
    (ps.out / "race_probe.json").write_text(json.dumps(ps.race_result.to_dict(), indent=2))
    _save_stage(ps, "race_probe", ps.race_result.to_dict())


async def stage_active_scan(ps: "PipelineState") -> None:
    if not getattr(ps.args, "active_scan", False):
        return
    ctx = ps.ctx()
    ps.active_result = await ActiveScanner(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        canary=ps.canary,
        browser_verifier=ps.browser_verifier,
        payload_server=(ctx.payload_server if ctx else None),
        public_url=(ctx.public_url if ctx else None),
    ).run(
        ps.verify_report.results if ps.verify_report else [],
        ps.param_result.interesting if ps.param_result else None,
        classifier_findings=ps.result.request_findings,
    )
    ps.nosql_result = await NoSQLProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        http_cache=_http(ps),
    ).run(ps.result.request_findings)
    ps.sql_probe_result = await SQLProbe(
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
        canary=ps.canary,
        payload_server=(ctx.payload_server if ctx else None),
        smb_sink=(ctx.smb_sink if ctx else None),
        public_url=(ctx.public_url if ctx else None),
        stack_profile=ps.profile,
        allow_destructive=getattr(ps.args, "allow_windows_destructive", False),
    ).run(ps.result.request_findings, active_result=ps.active_result)
    ps.auth_bypass_result = await AuthBypassProbe(timeout=ps.args.timeout).run(
        ps.result, target=ps.args.target,
    )
    # IDOR accounts
    if getattr(ps.args, "auth_a", None) and getattr(ps.args, "auth_b", None):
        ps.account_a = IDORProbe.load_account_from_storage_state(ps.args.auth_a, "A")
        ps.account_b = IDORProbe.load_account_from_storage_state(ps.args.auth_b, "B")
    elif not getattr(ps.args, "no_auto_auth", False):
        if ps.auto_auth_session and ps.auto_auth_session.has_auth:
            ps.account_a = IDORProbe.account_from_auto_auth(ps.auto_auth_session, "A")
        elif ps.auth_hdrs:
            ps.account_a = Account(label="A", headers=dict(ps.auth_hdrs))
        if ps.account_a:
            js_routes2 = list(ps.col._js_routes) if hasattr(ps.col, "_js_routes") else None
            second_session = await AutoAuth(
                ps.args.target, timeout=ps.args.timeout,
                email_domain=getattr(ps.args, "auth_email_domain", None),
                **_auto_auth_kwargs(ps.args, fresh_account=True),
            ).run(classifier_result=ps.result, js_routes=js_routes2)
            ps.account_b = IDORProbe.account_from_auto_auth(second_session, "B")
    ps.idor_result = await IDORProbe(timeout=ps.args.timeout).run(
        target=ps.args.target,
        account_a=ps.account_a,
        account_b=ps.account_b,
        classifier_findings=ps.result.request_findings,
    )
    _err(ps, f"Active scan: {len(ps.active_result.confirmed)} confirmed")


async def stage_auto_fuzz(ps: "PipelineState") -> None:
    if not getattr(ps.args, "auto_fuzz", False):
        return
    ps.auto_fuzz_result = await auto_fuzz_findings(
        ps.result.request_findings,
        auth_headers=ps.auth_hdrs,
        timeout=ps.args.timeout,
    )
    (ps.out / "auto_fuzz.json").write_text(json.dumps(ps.auto_fuzz_result.to_dict(), indent=2))


async def stage_access_replay(ps: "PipelineState") -> None:
    if getattr(ps.args, "no_access_replay", False) or ps.passive():
        return
    bypass_tokens: list[BypassToken] = []
    bypass_tokens.extend(tokens_from_jwt_attack(ps.jwt_result, baseline_headers=ps.auth_hdrs))
    bypass_tokens.extend(tokens_from_auth_bypass(ps.auth_bypass_result, baseline_headers=ps.auth_hdrs))
    bypass_tokens.extend(tokens_from_idor(ps.idor_result, ps.account_b))
    if ps.auth_hdrs:
        bypass_tokens.append(BypassToken(
            label="current_session", source="baseline",
            headers=dict(ps.auth_hdrs),
            evidence="re-fetch with the headers already in use",
        ))
    ps.access_replay_result = await AccessReplayProbe(
        out_dir=str(ps.out), timeout=ps.args.timeout,
    ).run(ps.col, bypass_tokens)
    (ps.out / "access_replay.json").write_text(
        json.dumps(ps.access_replay_result.to_dict(), indent=2)
    )
    _save_stage(ps, "access_replay", ps.access_replay_result.to_dict())


def build_probe_stages(ps: "PipelineState") -> list[Stage]:
    """Build scheduler stages with dependency graph."""

    def _enabled(name: str):
        return lambda ctx: _planner_allows(ctx, name)

    stages = [
        Stage("param_miner", stage_param_miner, depends_on=(), enabled=_enabled("param_miner")),
        Stage("jwt", stage_jwt, depends_on=(), enabled=_enabled("jwt")),
        Stage("desync", stage_desync, depends_on=(), enabled=_enabled("desync")),
        Stage("crlf", stage_crlf, depends_on=(), enabled=_enabled("crlf")),
        Stage("ct_probe", stage_ct_probe, depends_on=(), enabled=_enabled("ct_probe")),
        Stage("ws_probe", stage_ws_probe, depends_on=(), enabled=_enabled("ws_probe")),
        Stage("graphql_probe", stage_graphql_probe, depends_on=(), enabled=_enabled("graphql_probe")),
        Stage("oauth_probe", stage_oauth_probe, depends_on=(), enabled=_enabled("oauth_probe")),
        Stage("race_probe", stage_race_probe, depends_on=(), enabled=_enabled("race_probe")),
        Stage("verifier", stage_verifier, depends_on=(), enabled=_enabled("verifier")),
        Stage("open_redirect", stage_open_redirect, depends_on=("verifier",), enabled=_enabled("open_redirect")),
        Stage("auto_fuzz", stage_auto_fuzz, depends_on=(), enabled=_enabled("auto_fuzz")),
        Stage(
            "active_scan", stage_active_scan,
            depends_on=("verifier", "param_miner"),
            enabled=_enabled("active_scan"),
        ),
        Stage(
            "access_replay", stage_access_replay,
            depends_on=("active_scan", "jwt"),
            enabled=_enabled("access_replay"),
        ),
    ]
    return stages
