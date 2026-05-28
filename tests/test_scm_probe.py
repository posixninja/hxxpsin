"""Unit tests for src/scm_probe.py — path catalog, base normalization,
shape-aware confirmation, soft-404 rejection, secret-body cross-link.

Run:  python -m pytest tests/test_scm_probe.py -v
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import scm_probe  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


# ── Stub HTTP layer ─────────────────────────────────────────────────────────

class _StubResponse:
    def __init__(self, status: int, content: bytes):
        self.status_code = status
        self.content = content
        self.text = content.decode("utf-8", "replace")


class _StubAsyncClient:
    """Async-context-manager shaped stub that dispatches GETs through a
    test-supplied responder. Tests assign the responder via
    ``_StubAsyncClient.responder = ...`` before calling probe.run()."""
    responder = staticmethod(lambda url: _StubResponse(404, b""))

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
    """Replace httpx.AsyncClient in scm_probe's namespace with our stub."""
    monkeypatch.setattr(scm_probe.httpx, "AsyncClient", _StubAsyncClient)
    yield


def _drive(responder, target="https://t.example/", extra_bases=None):
    """Set the stub responder, run a fresh probe, and return the result."""
    _StubAsyncClient.responder = staticmethod(responder)
    probe = scm_probe.SCMProbe(out_dir="")
    return _run(probe.run(target, extra_bases=extra_bases))


# ── Path catalog ────────────────────────────────────────────────────────────

def test_catalog_includes_high_value_targets():
    paths = {p.path for p in scm_probe._PATHS}
    for required in (".git/HEAD", ".git/config", ".svn/entries",
                     ".env", ".env.local", "composer.lock",
                     "wp-config.php.bak", ".htpasswd",
                     "web.config", ".DS_Store"):
        assert required in paths, f"missing path {required}"


def test_catalog_severities_set_for_critical_leaks():
    by_path = {p.path: p for p in scm_probe._PATHS}
    assert by_path[".env"].severity == "critical"
    assert by_path[".git/HEAD"].severity == "critical"
    assert by_path["wp-config.php.bak"].severity == "critical"
    assert by_path[".htpasswd"].severity == "critical"


# ── Base normalization ──────────────────────────────────────────────────────

def test_normalize_bases_root_only():
    bases = scm_probe.SCMProbe._normalize_bases("https://t.example/", [])
    assert bases == ["https://t.example/"]


def test_normalize_bases_includes_subdirectories():
    bases = scm_probe.SCMProbe._normalize_bases(
        "https://t.example/",
        ["/admin/", "/api/", "/static/"],
    )
    assert "https://t.example/admin/" in bases
    assert "https://t.example/api/" in bases


def test_normalize_bases_strips_filenames_to_directories():
    bases = scm_probe.SCMProbe._normalize_bases(
        "https://t.example/",
        ["/admin/index.php"],
    )
    assert "https://t.example/admin/" in bases


def test_normalize_bases_rejects_cross_origin():
    bases = scm_probe.SCMProbe._normalize_bases(
        "https://t.example/",
        ["https://attacker.example/admin/"],
    )
    assert "https://attacker.example/admin/" not in bases


def test_normalize_bases_caps_at_max():
    extras = [f"/dir{i}/" for i in range(20)]
    bases = scm_probe.SCMProbe._normalize_bases("https://t.example/", extras)
    assert len(bases) <= 1 + scm_probe.SCMProbe._MAX_BASES


# ── Probe behavior ──────────────────────────────────────────────────────────

def test_probe_confirms_real_git_head():
    def responder(url):
        if "soft404" in url:
            return _StubResponse(404, b"<html>not found</html>")
        if url.endswith(".git/HEAD"):
            return _StubResponse(200, b"ref: refs/heads/main\n")
        return _StubResponse(404, b"")

    result = _drive(responder)
    git_findings = [f for f in result.findings if f.path == ".git/HEAD"]
    assert git_findings, (
        f"expected .git/HEAD finding, got {[f.path for f in result.findings]}"
    )
    assert git_findings[0].severity == "critical"


def test_probe_rejects_soft_404_spa_shell():
    """SPA shells return 200 with the same HTML for every URL — must NOT
    confirm any probe path because the body_match regex won't fit AND the
    length-based soft-404 calibration filters them."""
    spa_shell = b"<html><body><div id='root'></div></body></html>" * 4

    def responder(url):
        return _StubResponse(200, spa_shell)

    result = _drive(responder)
    assert result.findings == [], (
        f"soft-404 SPA shell yielded findings: "
        f"{[(f.path, f.severity) for f in result.findings]}"
    )


def test_probe_confirms_env_and_cross_links_secrets():
    def responder(url):
        if "soft404" in url:
            return _StubResponse(404, b"")
        if url.endswith(".env"):
            return _StubResponse(200,
                b"DB_HOST=db.internal\nDB_PASSWORD=secret123\n"
                b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        return _StubResponse(404, b"")

    result = _drive(responder)
    env_findings = [f for f in result.findings if f.path == ".env"]
    assert env_findings, "expected .env finding"
    f = env_findings[0]
    assert f.severity == "critical"
    assert "aws_access_key" in f.secret_kinds_in_body


def test_probe_rejects_env_path_with_html_body():
    """200 + HTML for .env (typical SPA misbehavior) — body_match regex
    requires KEY=value lines, must not confirm."""
    def responder(url):
        if "soft404" in url:
            return _StubResponse(404, b"")
        if url.endswith(".env"):
            return _StubResponse(200, b"<html>Welcome</html>")
        return _StubResponse(404, b"")

    result = _drive(responder)
    assert not any(f.path == ".env" for f in result.findings)


def test_probe_finds_wp_config_backup_with_db_creds():
    def responder(url):
        if "soft404" in url:
            return _StubResponse(404, b"")
        if url.endswith("wp-config.php.bak"):
            return _StubResponse(200,
                b"<?php\ndefine('DB_NAME', 'wp');\n"
                b"define('DB_PASSWORD', 'p@ss');\n"
                b"define('AUTH_KEY', 'longrandomstring');\n")
        return _StubResponse(404, b"")

    result = _drive(responder)
    wp = [f for f in result.findings if "wp-config" in f.path]
    assert wp and wp[0].severity == "critical"


def test_probe_with_subdirectory_base():
    def responder(url):
        if "soft404" in url:
            return _StubResponse(404, b"")
        if url == "https://t.example/admin/.env":
            return _StubResponse(200, b"DB_PASSWORD=root\n")
        return _StubResponse(404, b"")

    result = _drive(responder, extra_bases=["/admin/"])
    matched = [f for f in result.findings
                if "admin" in f.url and f.path == ".env"]
    assert matched, (
        f"expected admin/.env hit, got: {[f.url for f in result.findings]}"
    )


def test_probe_result_to_dict_round_trip():
    result = scm_probe.SCMProbeResult(
        paths_probed=10, bases_probed=2,
        findings=[scm_probe.SCMFinding(
            url="https://t/.env", kind="env", path=".env",
            severity="critical", confidence=0.95,
            evidence="env file exposed", note="critical",
            body_preview="DB=x",
            secret_kinds_in_body=["aws_access_key"],
        )],
    )
    d = result.to_dict()
    assert d["paths_probed"] == 10
    assert d["findings"][0]["secret_kinds_in_body"] == ["aws_access_key"]
