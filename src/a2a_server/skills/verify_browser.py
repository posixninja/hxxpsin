"""verify/verify_browser — Playwright-backed exploit verification.

Wraps ``browser_verifier.BrowserVerifier`` for one-shot verification of
XSS execution or open-redirect destination. The browser is instantiated
per call (small overhead) so each invocation is independent — fine for
the A2A request/response shape."""

from __future__ import annotations

from typing import Any

from . import REGISTRY
from ._common import load_auth_headers


async def _handler(
    *,
    url: str,
    verification_type: str = "xss",
    target_origin: str | None = None,
    auth_file: str | None = None,
    timeout_ms: int = 8000,
    settle_ms: int = 600,
) -> dict[str, Any]:
    from browser_verifier import BrowserVerifier  # type: ignore[import-not-found]

    auth_headers = load_auth_headers(auth_file)
    vtype = (verification_type or "xss").lower()

    async with BrowserVerifier(
        timeout_ms=timeout_ms,
        settle_ms=settle_ms,
        max_verifications=1,
    ) as v:
        if not v.available:
            return {
                "verdict": "skipped",
                "evidence": "browser unavailable (playwright not installed or chromium launch failed)",
                "available": False,
            }
        if vtype == "xss":
            result = await v.verify_xss(url, auth_headers=auth_headers)
            return result.to_dict()
        if vtype == "redirect":
            if not target_origin:
                return {"error": "verification_type=redirect requires target_origin"}
            result = await v.verify_redirect(url, target_origin=target_origin, auth_headers=auth_headers)
            return result.to_dict()
        return {"error": f"unknown verification_type {verification_type!r}; expected xss|redirect"}


REGISTRY.add(
    agent_id="verify",
    skill_id="verify_browser",
    description=(
        "Real-browser verification of a finding. type=xss navigates and "
        "watches for canary execution / dialogs / CSP violations. "
        "type=redirect navigates and checks the final origin."
    ),
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "description": "URL to navigate"},
            "verification_type": {
                "type": "string",
                "enum": ["xss", "redirect"],
                "description": "Verification mode (default 'xss')",
            },
            "target_origin": {
                "type": "string",
                "description": "Expected origin (required for type=redirect)",
            },
            "auth_file": {"type": "string", "description": "Optional auth.json path"},
            "timeout_ms": {"type": "integer", "description": "Per-navigation timeout (default 8000)"},
            "settle_ms": {"type": "integer", "description": "Post-nav wait for deferred JS (default 600)"},
        },
    },
    handler=_handler,
)
