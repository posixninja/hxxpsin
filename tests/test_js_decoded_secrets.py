"""Tests for the codec wiring in js_deep_analyzer.

Verifies that _extract_decoded_secrets surfaces encoded blobs that the
regex-based _extract_secrets misses.

Run:  python -m pytest tests/test_js_decoded_secrets.py -v
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import js_deep_analyzer as jda  # noqa: E402


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_decodes_base64_url_constant():
    encoded = _b64("https://internal-api.corp.local/v1/admin")
    content = f'''const CFG = {{ endpoint: "{encoded}" }};'''
    out = jda._extract_decoded_secrets(content, "app.js")
    assert out, f"expected a decoded secret from {encoded!r}, got nothing"
    assert any("internal-api.corp.local" in d.decoded for d in out)
    assert any(d.hint == "URL" for d in out)


def test_decodes_jwt_payload_constant():
    # A real-looking unsigned JWT (alg:none) baked into the bundle
    token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJleGFtcGxlIiwic3ViIjoidXNlcjQyIn0."
    content = f'const STATIC_TOKEN = "{token}";'
    out = jda._extract_decoded_secrets(content, "auth.js")
    schemes = [d.scheme for d in out]
    assert "jwt" in schemes, f"expected jwt detection, got schemes={schemes}"


def test_skips_minified_garbage():
    # Random minified-looking identifiers — must NOT produce decoded secrets
    content = 'var a="xY7zQ1Lp2kVn",b="qWeR4tYu8iOp",c="nMbBvCxZaSdF";'
    out = jda._extract_decoded_secrets(content, "min.js")
    # Even if detect() guesses base64 for some of these, _looks_interesting
    # should filter their decoded forms out as garbage.
    for d in out:
        assert d.hint != "decoded text" or any(
            kw in d.decoded.lower() for kw in ("http", "{", "=", "secret")
        ), f"surfaced uninteresting blob: {d.decoded!r}"


def test_classify_decoded_high_for_secret_keywords():
    encoded = _b64('{"api_key":"sk_live_real_key_value"}')
    content = f'const C = "{encoded}";'
    out = jda._extract_decoded_secrets(content, "config.js")
    assert out
    assert any(d.severity in ("high", "critical") for d in out), \
        f"expected high/critical severity for api_key, got " \
        f"{[(d.scheme, d.severity, d.decoded) for d in out]}"


def test_decoded_secrets_appear_in_result_to_dict():
    encoded = _b64("https://hidden.api.corp.local/secret-endpoint")
    content = f'const X = "{encoded}";'
    result = jda.JSAnalysisResult()
    result.decoded_secrets.extend(jda._extract_decoded_secrets(content, "x.js"))
    out = result.to_dict()
    assert "decoded_secrets" in out
    assert len(out["decoded_secrets"]) >= 1
    assert "scheme" in out["decoded_secrets"][0]


def test_dedup_collapses_same_literal_across_files():
    encoded = _b64("https://shared.api.corp.local/v1/users")
    content = f'const X = "{encoded}";'
    result = jda.JSAnalysisResult()
    result.decoded_secrets.extend(jda._extract_decoded_secrets(content, "a.js"))
    result.decoded_secrets.extend(jda._extract_decoded_secrets(content, "b.js"))
    assert len(result.decoded_secrets) == 2  # two before dedupe
    jda._deduplicate(result)
    assert len(result.decoded_secrets) == 1, \
        "expected dedupe to collapse same literal across files"
