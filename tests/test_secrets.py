"""Unit tests for src/secrets.py — unified credential-detection catalog
and integration regression tests for codec.annotate / js_deep_analyzer /
enricher / classifier consumers.

Run:  python -m pytest tests/test_secrets.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import secrets  # noqa: E402


# Synthetic Stripe-format keys. Split so the literal token never appears
# contiguously in source (avoids secret-scanner push-protection false positives);
# reassembled at runtime so secrets.scan() detects them exactly as before.
_STRIPE_LIVE = "sk_live_" + "abcdefghijklmnop12345678"
_STRIPE_TEST = "sk_test_" + "abcdefghijklmnop12345678"


# ── Catalog ─────────────────────────────────────────────────────────────────

def test_list_kinds_includes_expected_cloud_and_scm():
    kinds = set(secrets.list_kinds())
    for k in ("aws_access_key", "gcp_service_account", "azure_connection_string",
              "github_pat", "github_oauth", "gitlab_pat",
              "stripe_live", "slack_token", "private_key",
              "openai_key", "anthropic_key"):
        assert k in kinds, f"missing kind {k}"


def test_metadata_severity_and_public_by_design():
    aws = secrets.metadata_for("aws_access_key")
    assert aws.severity == "critical"
    assert not aws.public_by_design
    test_key = secrets.metadata_for("stripe_test")
    assert test_key.public_by_design  # test keys are public-by-design


def test_metadata_unknown_returns_none():
    assert secrets.metadata_for("not_a_real_kind") is None


# ── scan() — high-confidence catches ────────────────────────────────────────

def test_scan_aws_access_key():
    out = secrets.scan("config: AKIAIOSFODNN7EXAMPLE")
    assert len(out) == 1
    assert out[0].kind == "aws_access_key"
    assert out[0].value == "AKIAIOSFODNN7EXAMPLE"
    assert out[0].severity == "critical"


def test_scan_aws_temporary_access_key_via_asia_prefix():
    out = secrets.scan("ASIA0123456789ABCDEF in config")
    assert out and out[0].kind == "aws_access_key"


def test_scan_github_pat():
    out = secrets.scan("Authorization: token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
    assert out and out[0].kind == "github_pat"


def test_scan_stripe_live_and_test_differ_in_severity():
    body = (f"STRIPE_LIVE={_STRIPE_LIVE}\n"
            f"STRIPE_TEST={_STRIPE_TEST}")
    out = {m.kind: m for m in secrets.scan(body)}
    assert out["stripe_live"].severity == "critical"
    assert out["stripe_test"].severity == "low"
    assert out["stripe_test"].public_by_design


def test_scan_private_key_pem_header():
    out = secrets.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")
    assert out and out[0].kind == "private_key"


def test_scan_openssh_private_key():
    out = secrets.scan("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert out and out[0].kind == "private_key"


def test_scan_openai_key_format():
    key = "sk-" + "A" * 24 + "T3BlbkFJ" + "B" * 24
    out = secrets.scan(f"OPENAI_API_KEY={key}")
    assert out and out[0].kind == "openai_key"


def test_scan_anthropic_key_format():
    key = "sk-ant-" + "a" * 95
    out = secrets.scan(f"ANTHROPIC_KEY={key}")
    assert out and out[0].kind == "anthropic_key"


def test_scan_jwt_token():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature"
    out = secrets.scan(f"Authorization: Bearer {jwt}")
    kinds = {m.kind for m in out}
    assert "jwt" in kinds


def test_scan_google_oauth_client_id():
    out = secrets.scan(
        "client_id: 1234567890-abcdef.apps.googleusercontent.com"
    )
    assert out and any(m.kind == "google_oauth_client_id" for m in out)


def test_scan_gcp_service_account_marker():
    json_blob = '{"type": "service_account", "project_id": "x"}'
    out = secrets.scan(json_blob)
    assert any(m.kind == "gcp_service_account" for m in out)


def test_scan_azure_connection_string():
    body = ("connection: DefaultEndpointsProtocol=https;"
            "AccountName=mystorage;AccountKey=abcd+/12==")
    out = secrets.scan(body)
    assert any(m.kind == "azure_connection_string" for m in out)


# ── scan() — context-anchored / lower-confidence ───────────────────────────

def test_scan_jwt_secret_assignment_json_style():
    body = '{"jwt_secret": "thisIsAnEncodedSecret12345"}'
    out = secrets.scan(body)
    assert any(m.kind == "jwt_secret_assignment" for m in out)


def test_scan_jwt_secret_assignment_js_style():
    body = "var hmac_key = 'BASE64ENCODEDsecretvalue123'"
    out = secrets.scan(body)
    assert any(m.kind == "jwt_secret_assignment" for m in out)


# ── scan() — boundary / negative ────────────────────────────────────────────

def test_scan_empty_text_returns_empty():
    assert secrets.scan("") == []


def test_scan_plain_text_returns_empty():
    assert secrets.scan("This is just a regular sentence.") == []


def test_scan_deduplicates_same_value():
    body = "key=AKIAIOSFODNN7EXAMPLE other=AKIAIOSFODNN7EXAMPLE"
    out = secrets.scan(body)
    assert len(out) == 1, "expected dedup by (kind, value)"


def test_scan_min_confidence_filters():
    body = (f"STRIPE_TEST={_STRIPE_TEST}\n"
            "AWS=AKIAIOSFODNN7EXAMPLE")
    high_only = secrets.scan(body, min_confidence=0.9)
    kinds = {m.kind for m in high_only}
    assert "aws_access_key" in kinds
    assert "stripe_test" not in kinds  # 0.60 conf, filtered


def test_scan_kind_filter_restricts():
    body = ("AKIAIOSFODNN7EXAMPLE\n"
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
    out = secrets.scan(body, kinds={"aws_access_key"})
    assert len(out) == 1 and out[0].kind == "aws_access_key"


# ── scan_with_context ───────────────────────────────────────────────────────

def test_scan_with_context_returns_surrounding_text():
    body = "prefix---AKIAIOSFODNN7EXAMPLE---suffix"
    matches = secrets.scan_with_context(body, ctx=6)
    assert matches
    m = matches[0]
    # Context should include both some prefix and some suffix bytes
    assert "AKIA" in m.context
    assert "---" in m.context


# ── Consumer integration regression ─────────────────────────────────────────

def test_codec_annotate_uses_unified_catalog():
    """codec.annotate should now delegate to secrets.scan; new kinds in
    secrets.py (e.g. openai_key) should appear automatically in annotations."""
    import codec
    key = "sk-" + "A" * 24 + "T3BlbkFJ" + "B" * 24
    tags = codec.annotate(key)
    assert any("openai_key" in t for t in tags)


def test_js_deep_analyzer_extract_secrets_uses_catalog():
    """js_deep_analyzer's secret extraction should pull from the same
    catalog. We feed a key only present in the new unified catalog and
    confirm it surfaces."""
    import js_deep_analyzer
    body = "const k = 'sk-ant-" + "a" * 95 + "'"
    out = js_deep_analyzer._extract_secrets(body, "bundle.js")
    kinds = {s.kind for s in out}
    assert "anthropic_key" in kinds


def test_classifier_secrets_check_tags_response_with_secret():
    """_check_response_secrets should tag a request whose response body
    contains an actionable (non-public_by_design) secret."""
    import classifier
    from collector import CapturedRequest
    req = CapturedRequest(
        method="GET",
        url="https://target/config",
        headers={},
        body=None,
        resource_type="xhr",
        response_status=200,
        response_headers={},
        response_body='{"aws_access_key": "AKIAIOSFODNN7EXAMPLE"}',
    )
    result = classifier._check_response_secrets(req, "/config", {})
    assert result is not None
    _delta, cat, evidence = result
    assert cat == classifier.Cat.SECRETS
    assert "aws_access_key" in evidence


def test_classifier_secrets_check_ignores_test_keys():
    """public_by_design keys (Stripe test, Google Maps key) shouldn't trip
    the response-body check."""
    import classifier
    from collector import CapturedRequest
    req = CapturedRequest(
        method="GET",
        url="https://target/config",
        headers={},
        body=None,
        resource_type="xhr",
        response_body=f'{{"stripe_test": "{_STRIPE_TEST}"}}',
    )
    assert classifier._check_response_secrets(req, "/config", {}) is None
