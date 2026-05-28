"""Skills under the ``probe`` agent — per-family active probes.

Each skill targets one of hxxpsin's probe families. Direct handlers
live in ``_DIRECT_HANDLERS``; probes that need a populated
``ClassifierResult`` or Playwright browser context still delegate to a
``scan_full`` subprocess with guidance to filter the resulting report
for that family.

Directly-wired families:
  - ``probe_cloud_metadata``, ``probe_scm_exposure``, ``probe_ct_confusion``
  - ``probe_open_redirect``, ``probe_jwt``, ``probe_crlf``,
    ``probe_desync``, ``probe_nosql``

To add a directly-wired handler, register it under
``_DIRECT_HANDLERS[skill_id]`` and bypass the scan-delegation fallback.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from . import REGISTRY
from ._common import load_auth_headers as _load_auth_headers
from ._common import normalize_result as _normalize_result


def _stub_finding(url: str, method: str = "GET", **extra):
    """Construct a minimal ``Finding`` so probes that expect a findings list
    have one target to work against. Lazy-imports ``classifier.Finding`` so
    the agent-card render doesn't pay for the classifier import."""
    from classifier import Finding  # type: ignore[import-not-found]

    return Finding(
        method=method,
        url=url,
        score=10,
        categories=extra.pop("categories", ["a2a_skill"]),
        evidence=extra.pop("evidence", ["a2a_skill_request"]),
        headers=extra.pop("headers", None),
        body=extra.pop("body", None),
    )

REGISTRY.declare_agent(
    "probe",
    name="hxxpsin probe families",
    description="Per-vulnerability-class active probes against an authorized target.",
)


# ---------------------------------------------------------------------------
# Direct handlers — probes that don't need full classifier context
# ---------------------------------------------------------------------------


async def _probe_cloud_metadata(*, url: str) -> dict[str, Any]:
    from cloud_probe import CloudProbe  # type: ignore[import-not-found]

    probe = CloudProbe(url)
    result = await probe.run()
    return _normalize_result(result)


async def _probe_scm_exposure(*, url: str) -> dict[str, Any]:
    from scm_probe import SCMProbe  # type: ignore[import-not-found]

    probe = SCMProbe(url)
    result = await probe.run()
    return _normalize_result(result)


async def _probe_ct(*, url: str) -> dict[str, Any]:
    """Content-Type confusion probe — works against a single URL without
    needing a populated classifier."""
    from ct_probe import CTProbe  # type: ignore[import-not-found]

    probe = CTProbe()
    result = await probe.run([url])
    return _normalize_result(result)


async def _probe_open_redirect(*, url: str, auth_file: str | None = None) -> dict[str, Any]:
    from open_redirect import OpenRedirectProbe  # type: ignore[import-not-found]

    auth_headers = _load_auth_headers(auth_file)
    probe = OpenRedirectProbe(auth_headers=auth_headers)
    result = await probe.run([_stub_finding(url, categories=["redirect"])])
    return _normalize_result(result)


async def _probe_jwt(
    *,
    url: str,
    token: str | None = None,
    auth_file: str | None = None,
) -> dict[str, Any]:
    """Active JWT attacks against a token. The token may be supplied
    inline OR carried via the auth_file's Authorization header."""
    from jwt_attack import JWTAnalyzer  # type: ignore[import-not-found]

    auth_headers = _load_auth_headers(auth_file) or {}
    if not token:
        # Try to pull it out of the supplied auth header
        bearer = (auth_headers.get("Authorization") or "").strip()
        if bearer.lower().startswith("bearer "):
            token = bearer.split(None, 1)[1].strip()
    if not token:
        return {"error": "no JWT token supplied — pass token= or an auth_file with Authorization: Bearer ..."}

    finding = _stub_finding(
        url,
        categories=["auth"],
        headers={"authorization": f"Bearer {token}"},
    )
    probe = JWTAnalyzer(auth_headers=auth_headers)
    result = await probe.run(request_findings=[finding], cookie_findings=[])
    return _normalize_result(result)


async def _probe_crlf(*, url: str, auth_file: str | None = None) -> dict[str, Any]:
    from crlf_probe import CRLFProbe  # type: ignore[import-not-found]

    auth_headers = _load_auth_headers(auth_file)
    probe = CRLFProbe(auth_headers=auth_headers)
    result = await probe.run([url])
    return _normalize_result(result)


async def _probe_desync(*, url: str, urls: list[str] | None = None) -> dict[str, Any]:
    from desync_probe import DesyncProbe  # type: ignore[import-not-found]

    target_urls = [url] + list(urls or [])
    probe = DesyncProbe(urls=target_urls)
    result = await probe.run()
    return _normalize_result(result)


async def _probe_nosql(*, url: str, auth_file: str | None = None) -> dict[str, Any]:
    from nosql_probe import NoSQLProbe  # type: ignore[import-not-found]

    auth_headers = _load_auth_headers(auth_file)
    probe = NoSQLProbe(auth_headers=auth_headers)
    result = await probe.run([_stub_finding(url, categories=["nosql"])])
    return _normalize_result(result)


_DIRECT_HANDLERS: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
    "probe_cloud_metadata": _probe_cloud_metadata,
    "probe_scm_exposure": _probe_scm_exposure,
    "probe_ct_confusion": _probe_ct,
    "probe_open_redirect": _probe_open_redirect,
    "probe_jwt": _probe_jwt,
    "probe_crlf": _probe_crlf,
    "probe_desync": _probe_desync,
    "probe_nosql": _probe_nosql,
}


# ---------------------------------------------------------------------------
# Scan-delegated handlers — probes that need classifier context. Each one
# kicks off ``scan_full`` with a hint that the caller should pull the
# corresponding section out of report.json once the scan completes.
# ---------------------------------------------------------------------------


def _scan_delegated(family: str, *, family_label: str) -> Callable[..., Awaitable[dict[str, Any]]]:
    async def handler(*, url: str, auth_file: str | None = None, **_: Any) -> dict[str, Any]:
        from mcp_agent.scan_runner import ScanRunner

        rec = ScanRunner().start(
            target=url,
            mode="scan",
            auth=auth_file,
            active_scan=family in {"sql_injection", "command_injection", "xxe", "ssti", "path_traversal"},
        )
        return {
            "scan_id": rec.scan_id,
            "status": rec.status,
            "out_dir": rec.out_dir,
            "family": family,
            "label": family_label,
            "next_steps": (
                f"Poll MCP scan_status until completed, then call scan_findings "
                f"or read report.json — filter findings by category == {family_label!r}."
            ),
        }

    return handler


_SCAN_DELEGATED: dict[str, str] = {
    "probe_open_redirect": "open_redirect",
    "probe_idor": "idor",
    "probe_jwt": "jwt",
    "probe_ssrf": "ssrf",
    "probe_dom_xss": "dom_xss",
    "probe_desync": "desync",
    "probe_upload": "upload",
    "probe_sql_injection": "sql_injection",
    "probe_command_injection": "command_injection",
    "probe_xxe": "xxe",
    "probe_ssti": "ssti",
    "probe_path_traversal": "path_traversal",
    "probe_ldap": "ldap_injection",
    "probe_nosql": "nosql_injection",
    "probe_ws": "websocket",
    "probe_crlf": "crlf",
    "probe_auth_bypass": "auth_bypass",
}


# ---------------------------------------------------------------------------
# Registration — uniform schema for the whole probe surface
# ---------------------------------------------------------------------------


_PROBE_DESCRIPTIONS: dict[str, str] = {
    "probe_open_redirect": "49 bypass classes × 14 redirect surfaces (query, path, header, body).",
    "probe_idor": "Cross-account access testing. Requires auth_file for two accounts (auth-a, auth-b).",
    "probe_jwt": "alg=none, weak HS256, kid traversal, alg confusion against discovered tokens.",
    "probe_ssrf": "Internal-IP / metadata / OOB SSRF probes.",
    "probe_dom_xss": "Headless-Chromium DOM-sink discovery and exploitation.",
    "probe_desync": "H2↓H1 desync, cache, unkeyed-header probes.",
    "probe_upload": "File-upload bypasses (magic byte, extension, content-type, double-extension).",
    "probe_sql_injection": "SQLi via active_scanner — boolean, time, error, union, dumping.",
    "probe_command_injection": "OS command injection via active_scanner.",
    "probe_xxe": "XXE (in-band + OOB) via active_scanner.",
    "probe_ssti": "Server-side template injection via active_scanner.",
    "probe_path_traversal": "Path traversal via active_scanner.",
    "probe_ldap": "LDAP injection + LDAP dumping when bind credentials surface.",
    "probe_nosql": "NoSQL ($where, $regex, operator) injection.",
    "probe_ws": "WebSocket auth, origin checks, message tampering.",
    "probe_crlf": "CRLF injection (in-band + OOB).",
    "probe_auth_bypass": "Auth-bypass via header tricks (X-Original-URL, X-Forwarded-Host, …).",
    "probe_cloud_metadata": "IMDS / GCP / Azure metadata-service exposure.",
    "probe_scm_exposure": "Exposed .git, source maps, backup files.",
    "probe_ct_confusion": "Content-Type confusion — Accept vs response disagreement.",
}


_URL_ONLY_SCHEMA = {
    "type": "object",
    "required": ["url"],
    "properties": {
        "url": {"type": "string"},
        "auth_file": {"type": "string", "description": "Optional auth.json path"},
    },
}


_PROBE_SCHEMAS: dict[str, dict[str, Any]] = {
    "probe_jwt": {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "token": {"type": "string", "description": "JWT to attack (else pulled from auth_file)"},
            "auth_file": {"type": "string"},
        },
    },
    "probe_desync": {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "urls": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Additional URLs to include in the desync probe set",
            },
        },
    },
}


for skill_id, description in _PROBE_DESCRIPTIONS.items():
    if skill_id in _DIRECT_HANDLERS:
        handler = _DIRECT_HANDLERS[skill_id]
    else:
        family = _SCAN_DELEGATED.get(skill_id, skill_id)
        handler = _scan_delegated(family, family_label=family)
    REGISTRY.add(
        agent_id="probe",
        skill_id=skill_id,
        description=description,
        input_schema=_PROBE_SCHEMAS.get(skill_id, _URL_ONLY_SCHEMA),
        handler=handler,
    )
