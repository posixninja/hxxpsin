"""
Probe runner — thin async wrappers that execute individual probes on a single
request dict without requiring the full pipeline (no Collector, no classifier,
no two-account setup).

Probes supported here are those that need only the request itself:
  crlf   — CRLFProbe.run([url])
  jwt    — JWTAnalyzer.run([finding], [])  (finding built from request headers)
  param  — ParamMiner.run([finding])       (min_score bypassed)

Complex probes (IDOR, desync, active scanner, upload) still require the full
pipeline and are handled as navigation actions.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def _ensure_src_path() -> None:
    src = str(Path(__file__).resolve().parents[1])
    if src not in sys.path:
        sys.path.insert(0, src)


def _req_to_finding(req: dict) -> Any:
    """
    Build a minimal classifier.Finding from a raw request dict.
    Sets score=10 so min_score filters pass. Adds Cat.AUTH when the request
    carries a Bearer token so JWTAnalyzer extracts it.
    """
    _ensure_src_path()
    from classifier import Finding, Cat

    headers = req.get("headers") or {}
    body = req.get("body")
    resp = req.get("response") or {}

    # Derive categories so probes don't skip this finding
    categories: list[str] = []
    auth_hdr = headers.get("authorization", headers.get("Authorization", ""))
    if auth_hdr.lower().startswith("bearer ") or "token" in auth_hdr.lower():
        categories.append(Cat.AUTH)
    if not categories:
        # Include a generic category so probes that filter on non-empty don't skip
        categories.append(Cat.INJECTION)

    return Finding(
        method=req.get("method", "GET"),
        url=req.get("url", ""),
        score=10,
        categories=categories,
        evidence=[],
        body=body,
        headers=headers,
        response_status=resp.get("status"),
        response_headers=resp.get("headers"),
        response_body=resp.get("body"),
    )


# ---------------------------------------------------------------------------
# Per-probe runners
# ---------------------------------------------------------------------------

async def run_crlf(req: dict) -> list[dict]:
    """Run CRLF injection probe against the request URL."""
    _ensure_src_path()
    from crlf_probe import CRLFProbe

    url = req.get("url", "")
    if not url:
        return []
    auth = req.get("headers") or {}
    result = await CRLFProbe(auth_headers=auth, timeout=8.0).run([url])
    return [f.to_dict() for f in result.findings]


async def run_jwt(req: dict) -> list[dict]:
    """
    Run JWT attack analysis on the request.
    Extracts the Bearer token from the Authorization header (or any JWT found
    in the request body) and tests alg=none, weak secrets, kid SQLi, etc.
    """
    _ensure_src_path()
    from jwt_attack import JWTAnalyzer

    finding = _req_to_finding(req)
    result = await JWTAnalyzer(timeout=8.0).run([finding], [])
    return [f.to_dict() for f in result.findings]


async def run_param(req: dict) -> list[dict]:
    """
    Run hidden-parameter discovery against the request endpoint.
    Uses a wordlist of common param names and compares responses.
    """
    _ensure_src_path()
    from param_miner import ParamMiner

    finding = _req_to_finding(req)
    auth = req.get("headers") or {}
    result = await ParamMiner(auth_headers=auth, timeout=6.0, min_score=0).run([finding])
    return [f.to_dict() for f in result.findings]


async def run_fingerprint(req: dict) -> list[dict]:
    """Run Stackprint tech fingerprinting on the request's origin."""
    _ensure_src_path()
    from urllib.parse import urlparse
    from stackprint import Stackprint

    url = req.get("url", "")
    if not url:
        return []
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    profile = await Stackprint(origin, timeout=12.0).run()
    d = profile.to_dict()

    findings: list[dict] = []
    for category, techs in d.get("stack", {}).items():
        for tech in techs:
            findings.append({
                "_probe": "fingerprint",
                "url": origin,
                "category": category,
                "tech": tech,
                "verdict": f"Detected: {tech}",
            })
    for flag in d.get("risk_flags", []):
        findings.append({
            "_probe": "fingerprint",
            "url": origin,
            "category": "risk",
            "tech": flag,
            "verdict": f"Risk flag: {flag}",
        })
    for path in d.get("interesting_paths", []):
        findings.append({
            "_probe": "fingerprint",
            "url": origin + path,
            "category": "path",
            "tech": path,
            "verdict": f"Interesting path confirmed",
        })
    if not findings:
        findings.append({
            "_probe": "fingerprint",
            "url": origin,
            "category": "info",
            "tech": "—",
            "verdict": "No technologies detected",
        })
    return findings


# ---------------------------------------------------------------------------
# Dispatch table — maps probe key to runner coroutine function
# ---------------------------------------------------------------------------

async def _run_js_shim(req: dict) -> list[dict]:
    """Shim that loads js_probe lazily (keeps probe_runner import-clean)."""
    from tui.js_probe import run_js
    return await run_js(req)


# ---------------------------------------------------------------------------
# access_replay — use selected requests as candidate bypass tokens and replay
# against every 401/403 URL captured in the current AppState.requests list.
# ---------------------------------------------------------------------------


class _ReqShim:
    """Duck-type for access_replay._collect_forbidden: needs url, method, response_status."""
    __slots__ = ("url", "method", "response_status")

    def __init__(self, url: str, method: str, response_status):
        self.url = url
        self.method = method
        self.response_status = response_status


class _CollectorShim:
    def __init__(self, requests):
        self.requests = requests


def _build_forbidden_collector(state_requests: list[dict]) -> _CollectorShim:
    """Build a Collector-shaped object from raw request dicts, keeping only
    the 401/403 responses access_replay actually cares about."""
    shims = []
    for r in state_requests or []:
        if not isinstance(r, dict):
            continue
        resp = r.get("response") or {}
        status = resp.get("status") or r.get("response_status")
        if status not in (401, 403):
            continue
        shims.append(_ReqShim(
            url=r.get("url", ""),
            method=r.get("method", "GET"),
            response_status=status,
        ))
    return _CollectorShim(shims)


async def run_access_replay(req: dict, *, state_requests: list[dict] | None = None,
                            out_dir: str | None = None) -> list[dict]:
    """Re-fetch every 401/403 URL with the selected request's headers as a
    candidate bypass token. Returns one finding per URL that flipped 4xx→2xx."""
    _ensure_src_path()
    import tempfile
    from access_replay import AccessReplayProbe, BypassToken

    headers = req.get("headers") or {}
    if not headers:
        return [{
            "_probe": "access_replay",
            "url": req.get("url", ""),
            "verdict": "no headers on selected request — nothing to try as bypass",
        }]

    collector = _build_forbidden_collector(state_requests or [])
    if not collector.requests:
        return [{
            "_probe": "access_replay",
            "url": "",
            "verdict": "no 401/403 URLs captured — load a scan output first",
        }]

    work_dir = out_dir or tempfile.mkdtemp(prefix="hxxpsin_replay_")
    token = BypassToken(
        label="selected_request_headers",
        source="tui_manual",
        headers=dict(headers),
        evidence=f"headers from {req.get('method', 'GET')} {req.get('url', '')}",
    )
    result = await AccessReplayProbe(out_dir=work_dir, timeout=8.0).run(
        collector, [token],
    )
    findings = []
    for u in result.unlocked:
        d = u.to_dict()
        d["_probe"] = "access_replay"
        d["verdict"] = d.get("evidence", "unlocked")
        findings.append(d)
    if not findings:
        findings.append({
            "_probe": "access_replay",
            "url": "",
            "verdict": (
                f"no URLs unlocked — tried {result.attempts} replay(s) against "
                f"{result.forbidden_urls_seen} forbidden URL(s)"
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# dns_recon — pull the host from the request URL and run a full DNS pass.
# ---------------------------------------------------------------------------


async def run_dns_recon(req: dict) -> list[dict]:
    _ensure_src_path()
    from urllib.parse import urlparse
    from dns_recon import full_dns_recon

    url = req.get("url", "")
    host = urlparse(url).hostname if url else ""
    if not host:
        return [{"_probe": "dns_recon", "url": url, "verdict": "no hostname in URL"}]

    rec = await full_dns_recon(host)
    findings: list[dict] = []
    findings.append({
        "_probe": "dns_recon",
        "url": f"DNS:{host}",
        "category": "summary",
        "verdict": (
            f"records:{sum(len(v) for v in (rec.records or {}).values())} "
            f"hosts:{len(rec.discovered_hostnames or [])} "
            f"wildcard:{'yes' if rec.wildcard else 'no'} "
            f"axfr:{'yes' if rec.axfr else 'no'}"
        ),
        "_record": rec.to_dict(),
    })
    for rtype, vals in (rec.records or {}).items():
        for v in vals[:20]:
            findings.append({
                "_probe": "dns_recon",
                "url": f"DNS:{host}",
                "category": rtype,
                "verdict": str(v),
            })
    if rec.axfr:
        for ns, lines in rec.axfr.items():
            findings.append({
                "_probe": "dns_recon",
                "url": f"AXFR@{ns}",
                "category": "axfr",
                "verdict": f"{len(lines)} record(s) transferred",
            })
    return findings


RUNNERS: dict[str, Any] = {
    "crlf":          run_crlf,
    "jwt":           run_jwt,
    "param":         run_param,
    "js":            _run_js_shim,
    "fingerprint":   run_fingerprint,
    "access_replay": run_access_replay,
    "dns_recon":     run_dns_recon,
}
