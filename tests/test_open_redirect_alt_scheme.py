"""Tests for alt-scheme support in src/open_redirect.py.

Verifies:
  1. Alt-scheme bypass classes are present in the payload matrix.
  2. _check_response confirms an alt-scheme URI reflected into Location.
  3. _check_response downgrades to "likely" when the response carries SOME
     non-http scheme that doesn't match our payload.

Run: python -m pytest tests/test_open_redirect_alt_scheme.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import open_redirect as orr  # noqa: E402


def _mk_target() -> orr._Target:
    finding = SimpleNamespace(
        url="https://target.example/redir",
        method="GET",
        body=None,
        headers={},
    )
    return orr._Target(
        url="https://target.example/redir",
        method="GET",
        surface="query",
        param="next",
        finding=finding,
    )


def _mk_response(location: str, status: int = 302):
    """Minimal httpx-like response stand-in for _check_response."""
    return SimpleNamespace(
        headers={"location": location},
        status_code=status,
        text="",
        content=b"",
    )


def test_alt_scheme_classes_registered():
    """Every alt-* class we promised is in the payload templates."""
    expected = {
        "alt-file-unix", "alt-file-win", "alt-file-smb",
        "alt-ftp", "alt-ftp-auth", "alt-sftp", "alt-telnet",
        "alt-gopher", "alt-dict", "alt-ldap", "alt-jar",
        "alt-netdoc", "alt-tftp", "alt-news", "alt-imap", "alt-ssh",
    }
    assert expected.issubset(orr._BYPASS_TEMPLATES.keys())


def test_alt_scheme_regex_matches_all_supported():
    for scheme in ("file", "ftp", "sftp", "telnet", "gopher", "dict",
                   "ldap", "jar", "netdoc", "tftp", "news", "nntp",
                   "imap", "smb", "ssh"):
        assert orr._ALT_SCHEME_RE.match(f"{scheme}://host/x")


def test_alt_scheme_regex_rejects_http():
    assert not orr._ALT_SCHEME_RE.match("https://x/")
    assert not orr._ALT_SCHEME_RE.match("http://x/")


def test_check_response_confirms_when_canary_in_alt_location():
    t = _mk_target()
    payload = f"gopher://{orr._CANARY}:70/_GET%20/"
    r = _mk_response(location=f"gopher://{orr._CANARY}:70/_GET%20/")
    hit = orr._check_response(t, payload, "alt-gopher", r)
    assert hit is not None
    assert hit.verdict == "confirmed"
    assert "gopher" in hit.evidence


def test_check_response_confirms_file_scheme_payload_match():
    """file:// payloads don't carry the canary host but still confirm via
    prefix match on the payload."""
    t = _mk_target()
    payload = "file:///etc/passwd"
    r = _mk_response(location="file:///etc/passwd")
    hit = orr._check_response(t, payload, "alt-file-unix", r)
    assert hit is not None
    assert hit.verdict == "confirmed"


def test_check_response_likely_when_alt_scheme_unrelated_to_payload():
    """Server returned SOME non-http scheme but not the one we sent — likely,
    not confirmed."""
    t = _mk_target()
    payload = "ftp://attacker/"
    r = _mk_response(location="mailto:admin@target.example")
    # mailto isn't in our alt list, so it won't match — sanity check.
    assert orr._check_response(t, payload, "alt-ftp", r) is None
    # gopher (which IS in the alt list) but with a server-side host unrelated
    # to our payload → likely, not confirmed.
    r2 = _mk_response(location="gopher://internal.svc/x")
    hit = orr._check_response(t, payload, "alt-ftp", r2)
    assert hit is not None
    assert hit.verdict == "likely"


def test_check_response_still_handles_javascript_uri():
    """Regression: alt-scheme additions must not break js: detection."""
    t = _mk_target()
    payload = "javascript:alert(1)"
    r = _mk_response(location="javascript:alert(1)")
    hit = orr._check_response(t, payload, "javascript-uri", r)
    assert hit is not None
    assert hit.verdict == "confirmed"
    assert "javascript" in hit.evidence
