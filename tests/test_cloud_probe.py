"""Unit tests for src/cloud_probe.py — bucket guessing, OIDC config,
dangling-CNAME, function-host classification, credential sweep.

Run:  python -m pytest tests/test_cloud_probe.py -v
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import cloud_probe  # noqa: E402

# Synthetic Stripe-format key. Split so the literal token never appears
# contiguously in source (avoids secret-scanner push-protection false positives).
_STRIPE_TEST = "sk_test_" + "abcdefghijklmnop12345678"


def _run(coro):
    return asyncio.run(coro)


# ── Stub HTTP layer ─────────────────────────────────────────────────────────

class _StubResponse:
    def __init__(self, status: int, body: str, json_body=None):
        self.status_code = status
        self.text = body
        self._json = json_body

    def json(self):
        if self._json is None:
            return json.loads(self.text)
        return self._json


class _StubAsyncClient:
    responder = staticmethod(lambda url: _StubResponse(404, ""))

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        return _StubAsyncClient.responder(url)


@pytest.fixture(autouse=True)
def patch_httpx(monkeypatch):
    monkeypatch.setattr(cloud_probe.httpx, "AsyncClient", _StubAsyncClient)
    yield


def _drive(responder, target="https://acme.example.com/",
           subdomains=None, credential_corpus=None):
    _StubAsyncClient.responder = staticmethod(responder)
    probe = cloud_probe.CloudProbe(out_dir="")
    return _run(probe.run(target, subdomains=subdomains,
                           credential_corpus=credential_corpus))


# ── Helpers ─────────────────────────────────────────────────────────────────

def test_company_from_host_strips_subdomain_and_www():
    assert cloud_probe.CloudProbe._company_from_host("www.juice-shop.com") == "juice-shop"
    assert cloud_probe.CloudProbe._company_from_host("api.acme.com") == "acme"
    assert cloud_probe.CloudProbe._company_from_host("localhost") == ""


def test_bucket_candidates_includes_all_providers():
    cands = cloud_probe.CloudProbe._bucket_candidates("acme")
    providers = {p for p, _ in cands}
    for required in ("aws_s3", "gcp_gcs", "azure_blob",
                      "cloudflare_r2", "digitalocean"):
        assert required in providers, f"missing {required}"


def test_bucket_candidates_uses_suffix_set():
    cands = cloud_probe.CloudProbe._bucket_candidates("acme")
    urls = [u for _, u in cands]
    # Suffix variants should appear
    assert any("acme-prod" in u for u in urls)
    assert any("acme-backup" in u for u in urls)


def test_provider_for_secret_routing():
    p = cloud_probe.CloudProbe._provider_for_secret
    assert p("aws_access_key") == "aws"
    assert p("gcp_service_account") == "gcp"
    assert p("azure_connection_string") == "azure"
    assert p("github_pat") == "github"
    assert p("openai_key") == "openai"
    assert p("not_a_real_kind") == "other"


# ── Function-host classification ────────────────────────────────────────────

def test_classify_lambda_function_url():
    f = cloud_probe.CloudProbe._classify_function_host(
        "abc123.lambda-url.us-east-1.on.aws"
    )
    assert f and f.provider == "aws_lambda"


def test_classify_cloud_run():
    f = cloud_probe.CloudProbe._classify_function_host("svc-abc.a.run.app")
    assert f and f.provider == "gcp_cloudrun"


def test_classify_azure_functions():
    f = cloud_probe.CloudProbe._classify_function_host("myapp.azurewebsites.net")
    assert f and f.provider == "azure_functions"


def test_classify_non_function_returns_none():
    assert cloud_probe.CloudProbe._classify_function_host("acme.com") is None


# ── Bucket probe ────────────────────────────────────────────────────────────

def test_bucket_listing_critical_when_xml_returned():
    def responder(url):
        if "acme.s3.amazonaws.com" in url:
            return _StubResponse(200,
                "<?xml version='1.0'?><ListBucketResult><Name>acme</Name></ListBucketResult>"
            )
        return _StubResponse(404, "")
    result = _drive(responder)
    buckets = [f for f in result.findings
                if f.surface == "bucket_exposure" and f.severity == "critical"]
    assert buckets, f"expected critical bucket finding, got {[f.surface for f in result.findings]}"
    assert "acme" in buckets[0].url


def test_bucket_listing_json_format_also_confirmed():
    def responder(url):
        if "storage.googleapis.com" in url:
            return _StubResponse(200,
                '{"kind":"storage#objects","items":[{"name":"file1"}]}'
            )
        return _StubResponse(404, "")
    result = _drive(responder)
    buckets = [f for f in result.findings if f.surface == "bucket_exposure"]
    gcs = [f for f in buckets if f.provider == "gcp_gcs"]
    assert gcs, f"expected GCS finding, got providers {[f.provider for f in buckets]}"


def test_bucket_403_access_denied_yields_info():
    def responder(url):
        if "acme.s3.amazonaws.com" in url:
            return _StubResponse(403,
                "<Error><Code>AccessDenied</Code></Error>")
        return _StubResponse(404, "")
    result = _drive(responder)
    info = [f for f in result.findings
             if f.surface == "bucket_exposure" and f.severity == "info"]
    assert info


# ── OIDC config ─────────────────────────────────────────────────────────────

def test_oidc_config_flags_none_auth_method():
    cfg = {
        "issuer": "https://acme.example.com",
        "jwks_uri": "https://acme.example.com/jwks",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "response_types_supported": ["code"],
    }

    def responder(url):
        if "openid-configuration" in url:
            return _StubResponse(200, json.dumps(cfg), json_body=cfg)
        return _StubResponse(404, "")
    result = _drive(responder)
    none_findings = [
        f for f in result.findings
        if f.surface == "oidc_misconfig" and 'none' in f.evidence
    ]
    assert none_findings, "expected 'none' auth method finding"
    assert none_findings[0].severity == "high"


def test_oidc_config_flags_implicit_flow():
    cfg = {
        "issuer": "https://acme.example.com",
        "response_types_supported": ["code", "token", "id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }

    def responder(url):
        if "openid-configuration" in url:
            return _StubResponse(200, json.dumps(cfg), json_body=cfg)
        return _StubResponse(404, "")
    result = _drive(responder)
    implicit = [f for f in result.findings if "implicit flow" in f.evidence]
    assert implicit


def test_oidc_config_absent_no_findings():
    def responder(url):
        return _StubResponse(404, "")
    result = _drive(responder)
    assert not any(f.surface == "oidc_misconfig" for f in result.findings)


# ── Dangling CNAME ──────────────────────────────────────────────────────────

def test_dangling_cname_s3_takeover():
    def responder(url):
        if "subdomain.acme.example.com" in url:
            return _StubResponse(404,
                "<Error><Code>NoSuchBucket</Code></Error>"
            )
        return _StubResponse(404, "")
    result = _drive(responder, subdomains=["subdomain.acme.example.com"])
    takeover = [f for f in result.findings if f.surface == "dangling_cname"]
    assert takeover and takeover[0].provider == "aws_s3"
    assert takeover[0].severity == "critical"


def test_dangling_cname_heroku_unclaimed():
    def responder(url):
        if "abandoned.acme.example.com" in url:
            return _StubResponse(404, "There's nothing here yet.")
        return _StubResponse(404, "")
    result = _drive(responder, subdomains=["abandoned.acme.example.com"])
    heroku = [f for f in result.findings if f.provider == "heroku"]
    assert heroku


def test_dangling_cname_clean_returns_no_finding():
    def responder(url):
        return _StubResponse(200, "<html>welcome</html>")
    result = _drive(responder, subdomains=["live.acme.example.com"])
    assert not any(f.surface == "dangling_cname" for f in result.findings)


# ── Credential corpus sweep ─────────────────────────────────────────────────

def test_credential_sweep_picks_up_aws_key_in_env_body():
    body = "DB_PASS=x\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    result = _drive(
        lambda url: _StubResponse(404, ""),
        credential_corpus=[("file:.env", body)],
    )
    leaked = [f for f in result.findings if f.surface == "leaked_credential"]
    assert leaked and leaked[0].provider == "aws"
    assert "aws_access_key" in leaked[0].secret_kinds


def test_credential_sweep_ignores_test_keys():
    body = f"stripe = {_STRIPE_TEST}"
    result = _drive(
        lambda url: _StubResponse(404, ""),
        credential_corpus=[("file:config", body)],
    )
    assert not any(f.surface == "leaked_credential" for f in result.findings)


def test_credential_sweep_attributes_source():
    body = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    result = _drive(
        lambda url: _StubResponse(404, ""),
        credential_corpus=[("response:/api/leak", body)],
    )
    leaked = [f for f in result.findings if f.surface == "leaked_credential"]
    assert leaked and leaked[0].source == "response:/api/leak"


# ── Function host discovery via subdomains list ─────────────────────────────

def test_function_host_in_subdomains_flags_finding():
    def responder(url):
        # Don't take over, just return generic 200
        return _StubResponse(200, "<html></html>")
    result = _drive(
        responder,
        subdomains=["api.lambda-url.us-east-1.on.aws"],
    )
    fn = [f for f in result.findings if f.surface == "exposed_function"]
    assert fn and fn[0].provider == "aws_lambda"


# ── to_dict round trip ──────────────────────────────────────────────────────

def test_result_to_dict_includes_all_fields():
    result = cloud_probe.CloudProbeResult(
        findings=[cloud_probe.CloudFinding(
            url="https://x", surface="bucket_exposure", provider="aws_s3",
            severity="critical", verdict="confirmed",
            evidence="public bucket",
        )],
        bases_probed=10, subdomains_probed=5, credentials_swept=3,
    )
    d = result.to_dict()
    assert d["bases_probed"] == 10
    assert d["subdomains_probed"] == 5
    assert d["credentials_swept"] == 3
    assert d["findings"][0]["surface"] == "bucket_exposure"
