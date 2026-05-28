"""
secrets.py — Unified secret-detection regex catalog for hxxpsin.

Single source of truth for "what does an exposed credential look like."
Consumed by [[enricher]] (response-body sweep), [[js_deep_analyzer]] (bundle
scan), [[codec]] (annotate decoded layers), [[classifier]] (Cat.SECRETS
tag), and [[cloud_probe]] (leaked-credential surface).

API:
    scan(text, *, min_confidence=0.0) -> list[SecretMatch]
    scan_with_context(text, *, ctx=40) -> list[SecretMatch]
    metadata_for(kind) -> SecretKindMeta   # severity, public_by_design, label
    list_kinds() -> list[str]

Each pattern carries:
  - kind            stable string id (e.g. "aws_access_key")
  - regex           compiled re.Pattern
  - confidence      0–1 baseline confidence for *any* hit; downstream
                    callers can boost or filter based on context
  - severity        critical | high | medium | low | info
  - public_by_design whether discovery is interesting even though the
                     credential is meant to be public (e.g. stripe_test,
                     google_maps frontend keys)

The pattern list is union-of-everything from the prior ad-hoc lists across
modules + PAT "API Key Leaks" + the additions specified in the sprint plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class SecretKindMeta:
    kind: str
    severity: str          # critical | high | medium | low | info
    public_by_design: bool
    confidence: float
    label: str = ""        # human-friendly name


@dataclass
class SecretMatch:
    kind: str
    value: str             # full match — caller decides whether to truncate
    confidence: float
    severity: str
    public_by_design: bool
    span: tuple[int, int] = (0, 0)
    context: str = ""      # ±ctx characters around the match (scan_with_context)


# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------

# Each entry: (kind, compiled regex, confidence, severity, public_by_design,
#              human label)
_PATTERNS: list[tuple[str, re.Pattern, float, str, bool, str]] = [
    # Cloud — access keys
    ("aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.95, "critical", False, "AWS access key ID"),
    ("aws_secret_key_paired",
        # Captured only when preceded by a labeled key — pure 40-char b64
        # strings are too noisy on their own.
        re.compile(r"(?i)aws_secret_access_key[\"' :=]{1,3}([A-Za-z0-9/+]{40})"),
        0.9, "critical", False, "AWS secret access key (paired)"),
    ("gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        0.85, "critical", False, "GCP service-account JSON"),
    ("gcp_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        0.70, "medium", True, "Google / Firebase / Maps API key"),
    ("azure_connection_string",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        0.95, "critical", False, "Azure storage connection string"),

    # SCM / source forges
    ("github_pat",
        re.compile(r"\bghp_[A-Za-z0-9_]{36,}\b"),
        0.95, "critical", False, "GitHub personal access token"),
    ("github_oauth",
        re.compile(r"\bgho_[A-Za-z0-9_]{36,}\b"),
        0.95, "critical", False, "GitHub OAuth token"),
    ("github_app",
        re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9_]{36,}\b"),
        0.95, "critical", False, "GitHub App / Server token"),
    ("gitlab_pat",
        re.compile(r"\bglpat-[A-Za-z0-9\-_]{20}\b"),
        0.90, "critical", False, "GitLab personal access token"),

    # Payments
    ("stripe_live",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
        0.95, "critical", False, "Stripe live secret key"),
    ("stripe_publishable_live",
        re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
        0.70, "medium", True, "Stripe publishable live key"),
    ("stripe_test",
        re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"),
        0.60, "low", True, "Stripe test key"),

    # Messaging / collaboration
    ("slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        0.95, "high", False, "Slack token"),
    ("sendgrid",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        0.95, "high", False, "SendGrid API key"),
    ("mailgun",
        re.compile(r"\bkey-[a-z0-9]{32}\b"),
        0.60, "high", False, "Mailgun API key"),
    ("twilio_account_sid",
        re.compile(r"\bAC[a-f0-9]{32}\b"),
        0.70, "medium", False, "Twilio Account SID"),
    ("twilio_auth_token",
        re.compile(r"\bSK[a-f0-9]{32}\b"),
        0.85, "high", False, "Twilio Auth Token"),

    # Package registries
    ("npm_token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        0.90, "high", False, "npm access token"),
    ("pypi_token",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
        0.95, "high", False, "PyPI API token"),

    # AI providers
    ("openai_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b"),
        0.95, "critical", False, "OpenAI API key"),
    ("anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{90,}\b"),
        0.95, "critical", False, "Anthropic API key"),
    ("huggingface_token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        0.85, "high", False, "Hugging Face token"),

    # OAuth artifacts
    ("google_oauth_client_id",
        re.compile(r"\b\d{10,}-[a-z0-9]+\.apps\.googleusercontent\.com\b"),
        0.75, "medium", True, "Google OAuth client ID"),

    # Bearer / contextual
    ("bearer_header",
        re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
        0.60, "high", False, "Bearer-prefixed auth header"),

    # Private key material — broad PEM-header match. The original enricher
    # regex was `-----BEGIN[^-]+PRIVATE KEY-----…` which is too permissive
    # for streaming text; we lock the suffix to `KEY-----` or `MESSAGE-----`.
    ("private_key",
        re.compile(r"-----BEGIN [A-Z][A-Z0-9 ]{1,40}(?:KEY|MESSAGE)-----"),
        0.99, "critical", False, "Private key block"),

    # JWT (token format itself — value alone doesn't prove secrecy)
    ("jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}"
                    r"\.[A-Za-z0-9_\-]{8,}\b"),
        0.85, "medium", False, "JWT-shaped string"),

    # Context-anchored secrets — assignment-style; lower confidence because
    # value shape is unconstrained but the surrounding name is a strong hint.
    # Tolerates JSON-style `"name":` quoting AND JS-style `name=` / `name:`.
    ("jwt_secret_assignment",
        re.compile(
            r"""(?i)["']?(?:secret|signing_key|jwt_secret|hmac_key)["']?"""
            r"""\s*[:=]\s*"""
            r"""["'`]([A-Za-z0-9+/=_\-]{20,})["'`]"""),
        0.55, "high", False, "JWT/HMAC signing secret (assignment)"),
]


# Index by kind for fast metadata lookup
_KIND_INDEX: dict[str, SecretKindMeta] = {
    kind: SecretKindMeta(
        kind=kind, severity=sev, public_by_design=pbd,
        confidence=conf, label=label,
    )
    for kind, _re, conf, sev, pbd, label in _PATTERNS
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_kinds() -> list[str]:
    """Return the stable kind ids in pattern order."""
    return [k for k, *_ in _PATTERNS]


def metadata_for(kind: str) -> Optional[SecretKindMeta]:
    """Return metadata (severity, public_by_design, label) for a kind, or
    None if the kind is unknown."""
    return _KIND_INDEX.get(kind)


def scan(text: str, *, min_confidence: float = 0.0,
         kinds: Optional[set[str]] = None) -> list[SecretMatch]:
    """Find every secret-shaped match in `text`.

    Args:
        text: input to scan (response body, JS bundle, file contents).
        min_confidence: drop matches with confidence below this floor.
        kinds: restrict to these kinds (None means all).

    Each pattern is evaluated once over the entire input. Matches are
    deduplicated by ``(kind, value)`` so the same key appearing twice
    yields one record.
    """
    if not text:
        return []
    out: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    for kind, pat, conf, sev, pbd, _label in _PATTERNS:
        if conf < min_confidence:
            continue
        if kinds is not None and kind not in kinds:
            continue
        for m in pat.finditer(text):
            # Prefer group(1) when the pattern captures the value separately
            # from a labeled prefix (e.g. context-anchored assignments).
            try:
                value = m.group(1)
            except IndexError:
                value = m.group(0)
            value = value or m.group(0)
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(
                kind=kind, value=value, confidence=conf,
                severity=sev, public_by_design=pbd,
                span=(m.start(), m.end()),
            ))
    return out


def scan_with_context(text: str, *, ctx: int = 40,
                       min_confidence: float = 0.0,
                       kinds: Optional[set[str]] = None
                       ) -> list[SecretMatch]:
    """Like ``scan`` but each match also carries ``ctx`` characters of
    surrounding text in ``.context``. Useful for the codec annotation
    pass and any caller that needs to grep back to the leak site."""
    matches = scan(text, min_confidence=min_confidence, kinds=kinds)
    for m in matches:
        start, end = m.span
        a = max(0, start - ctx)
        b = min(len(text), end + ctx)
        m.context = text[a:b]
    return matches


__all__ = [
    "SecretMatch", "SecretKindMeta",
    "scan", "scan_with_context",
    "list_kinds", "metadata_for",
]
