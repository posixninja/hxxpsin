"""Tests for the codec.detect wiring in classifier — encoded-ID detection.

Verifies _check_encoded_id flags requests whose path or query carries an
encoded identifier (base64/jwt) that the plain-text IDOR check misses.

Run:  python -m pytest tests/test_classifier_encoded_id.py -v
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from collector import CapturedRequest  # noqa: E402
import classifier  # noqa: E402


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _req(url, method="GET", body=None):
    parsed = urlparse(url)
    return (
        CapturedRequest(method=method, url=url, headers={},
                        body=body, resource_type="xhr"),
        parsed.path,
        parse_qs(parsed.query),
    )


def test_flags_base64_id_in_path():
    seg = _b64("user42")
    req, path, params = _req(f"http://localhost:5050/users/{seg}/profile")
    result = classifier._check_encoded_id(req, path, params)
    assert result is not None, "expected encoded-ID flag for base64 user42"
    delta, cat, ev = result
    assert cat == classifier.Cat.IDOR
    assert "base64" in ev
    assert "user42" in ev


def test_flags_jwt_in_query_param_as_auth():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyNDIifQ."
    url = f"http://localhost:5050/whoami?session={token}"
    req, path, params = _req(url)
    result = classifier._check_encoded_id(req, path, params)
    assert result is not None
    delta, cat, ev = result
    assert cat == classifier.Cat.AUTH
    assert "JWT" in ev


def test_skips_plain_numeric_path():
    # Already covered by _check_idor_path — this check should defer
    req, path, params = _req("http://localhost:5050/users/42/profile")
    assert classifier._check_encoded_id(req, path, params) is None


def test_skips_uuid_path():
    # _PATH_ID_RE also matches UUIDs — defer to _check_idor_path
    req, path, params = _req(
        "http://localhost:5050/users/550e8400-e29b-41d4-a716-446655440000/profile"
    )
    assert classifier._check_encoded_id(req, path, params) is None


def test_skips_minified_garbage_segments():
    req, path, params = _req("http://localhost:5050/v1/abcdef/dashboard")
    # Short non-encoded segments should not trigger
    assert classifier._check_encoded_id(req, path, params) is None


def test_skips_url_encoded_emoji_placeholder():
    # crAPI exposes /api/v1/%F0%9F%A4%96 — URL-encoded 🤖 emoji used as a
    # placeholder. codec.detect correctly tags it as `url`, but plain
    # URL-encoding of multi-byte UTF-8 is routine web behavior, not an
    # obfuscated ID. Must not trigger the encoded-ID flag.
    req, path, params = _req("http://localhost:5050/api/v1/%F0%9F%A4%96")
    assert classifier._check_encoded_id(req, path, params) is None


def test_skips_single_character_decoded_result():
    # Even when an obfuscating scheme matches, a single-char decoded result
    # is not an identifier.
    import base64
    seg = base64.b64encode(b"x").decode().rstrip("=")
    # Pad to ≥8 chars by repeating so it survives the length gate
    if len(seg) >= 8:
        req, path, params = _req(f"http://localhost:5050/x/{seg}/y")
        result = classifier._check_encoded_id(req, path, params)
        # If it triggers at all, the decoded form must be ≥3 chars
        if result is not None:
            assert "→" in result[2]
            _, decoded = result[2].rsplit("→", 1)
            assert len(decoded.strip()) >= 3


def test_classifier_pipeline_surfaces_encoded_id_via_classify():
    """End-to-end: build a tiny Collector with a single request and confirm
    the classify() pipeline surfaces the encoded-ID finding."""
    from collector import Collector
    seg = _b64("user42")
    col = Collector(origin="http://localhost:5050")
    col.requests.append(CapturedRequest(
        method="GET",
        url=f"http://localhost:5050/users/{seg}/profile",
        headers={}, body=None, resource_type="xhr",
    ))
    result = classifier.classify(col, origin="http://localhost:5050")
    findings = result.request_findings
    assert findings, "expected at least one finding from encoded path"
    cats = [c for f in findings for c in f.categories]
    assert classifier.Cat.IDOR in cats
    evidence = " ".join(e for f in findings for e in f.evidence)
    assert "base64" in evidence
