"""
enricher.py — Mine captured response bodies for users, hosts, secrets, URLs.

The Collector and AccessReplay subsystems leave us with a pile of raw response
bodies (JSON, HTML, text). They contain enormous amounts of structured data we
were previously throwing away — emails, usernames, OAuth client IDs, internal
hostnames, leaked password hashes, unvisited URLs, file paths.

This module:
  1. Walks every JSON body recursively, matching key names against identity /
     credential / location heuristics.
  2. Regex-sweeps every string value AND every plaintext body for emails, JWTs,
     IPs, URLs, hashes, and AWS-style keys.
  3. Coalesces discovered identity fragments into per-user records using a
     simple union-find over shared identifiers (an entry mentioning
     `{username: admin, email: x@y}` and another mentioning
     `{email: x@y, phone: 555-...}` collapse into one user).
  4. Writes a per-entity folder layout under `<out>/enrichment/` so future
     probes can drop additional files into each folder (e.g. spray results,
     IDOR pivots, captured tokens).

Pipeline position: after access_replay (so freshly unlocked bodies are also
mined), before nuclei generation. Always-on: pure parsing, no network I/O.
"""

import hashlib
import json
import math
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

import image_analyzer


# ---------------------------------------------------------------------------
# Heuristic key sets (case-insensitive substring match against JSON key names)
# ---------------------------------------------------------------------------

_IDENTITY_KEYS = (
    "email", "mail", "username", "user_name", "userid", "user_id",
    "login", "author", "owner", "customer", "created_by", "updated_by",
    "creator", "modifier", "assignee", "reporter",
)
_USERNAME_KEYS = (
    "username", "user_name", "login", "author", "owner", "customer",
    "created_by", "updated_by", "creator", "modifier", "assignee",
    "reporter", "user", "handle", "screenname",
)
_EMAIL_KEYS = ("email", "e_mail", "mail", "emailaddress", "email_address")
_USER_ID_KEYS = (
    "uid", "user_id", "userid", "customer_id", "customerid", "account_id",
    "accountid", "sub", "subject", "_id", "owner_id", "ownerid",
)
_SECRET_KEYS = (
    # Exact tokens only — checked via whole-word matching so e.g. "auth"
    # alone does NOT match a key called "author".
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_token", "refresh_token",
    "private_key", "privatekey", "client_secret", "clientsecret",
    "authorization",  # NOT "auth" (would match "author")
    "x_api_key", "session_key", "sessionkey",
    "hash", "salt", "encryption_key", "signing_key",
)


# Token splitter: breaks `myFieldName_v2-foo` → ['my', 'field', 'name', 'v2', 'foo']
# so candidates can be matched as whole tokens (`"auth" in "author"` style false
# positives go away). Used by _key_matches_token below.
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_BREAK_RE = re.compile(r"([a-z])([A-Z])")


def _key_tokens(key: str) -> list[str]:
    s = _CAMEL_BREAK_RE.sub(r"\1_\2", key).lower()
    return [t for t in _TOKEN_SPLIT_RE.split(s) if t]


def _key_matches_token(key_lower: str, candidates) -> bool:
    """True if `key_lower` matches any candidate via whole-token semantics.
    Both the key and each candidate are normalised to underscore-joined token
    form before comparison. Single-word candidates must equal one whole token
    (so `"auth"` no longer matches `"author"`); multi-word candidates match
    when their underscore form appears as a substring of the key's canonical
    form (so `"created_by"` matches `createdBy` AND `created_by` AND `created-by`)."""
    if not key_lower:
        return False
    key_tokens = _key_tokens(key_lower)
    if not key_tokens:
        return False
    key_joined = "_".join(key_tokens)
    for c in candidates:
        c_tokens = _key_tokens(c)
        if not c_tokens:
            continue
        if len(c_tokens) == 1:
            if c_tokens[0] in key_tokens:
                return True
        else:
            if "_".join(c_tokens) in key_joined:
                return True
    return False
_CREDENTIAL_VALUE_KEYS = (
    "client_id", "clientid", "app_id", "appid", "tenant_id", "tenantid",
)
_PHONE_KEYS = ("phone", "tel", "telephone", "mobile", "cell", "contact_number")
_ADDRESS_KEYS = (
    "address", "street", "addr1", "addr2", "address_line1", "address_line2",
    "city", "state", "province", "zip", "zipcode", "postal", "postal_code",
    "country", "region",
)
_HOST_KEYS = (
    "host", "hostname", "domain", "server", "fqdn", "base_url", "baseurl",
    "redirect_uri", "redirecturi", "callback_url", "callbackurl",
    "endpoint", "url", "uri", "href",
)
_PATH_KEYS = ("path", "filepath", "file_path", "filename", "file_name")
_IMAGE_KEYS = (
    "image", "img", "avatar", "picture", "photo", "logo", "icon",
    "profile_picture", "profileimage", "profile_image", "profilepic",
    "cover", "thumbnail", "thumb", "headshot", "banner", "background_image",
)
_TOKEN_KEYS = ("token", "access_token", "auth_token", "session_token", "jwt")
_COOKIE_KEYS = ("cookie", "session", "sid", "ssid", "phpsessid", "jsessionid")

# Entity type heuristics — applied to UserRecord after coalescing.
# Order matters: first match wins.
_ADMIN_USERNAME_RE = re.compile(r"\b(admin|root|superuser|sysadmin|owner)\b", re.IGNORECASE)
_SERVICE_USERNAME_RE = re.compile(r"\b(bot|service|system|daemon|api|worker|cron|agent)\b", re.IGNORECASE)
_TEST_USERNAME_RE = re.compile(r"\b(test|demo|sample|example|dummy|fake|sandbox|temp|qa)\b", re.IGNORECASE)
_OAUTH_APP_TYPES = {"oauth_client_id", "oauth_client_secret", "google_oauth_client_id"}
# Image extension filter (used when guessing if a value is an image URL/path)
_IMAGE_EXT_RE = re.compile(r"\.(png|jpe?g|gif|webp|bmp|tiff?|svg|ico|heic|heif|avif)(\?|$)", re.IGNORECASE)

# Hash shape detectors (used to decide whether a `password` value is plaintext
# or a digest, so we can name the on-disk file correctly).
_HASH_PATTERNS = [
    ("md5",     re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("sha1",    re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("sha224",  re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("sha256",  re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("sha384",  re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("sha512",  re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("bcrypt",  re.compile(r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("argon2",  re.compile(r"^\$argon2[id]+\$")),
    ("scrypt",  re.compile(r"^\$scrypt\$")),
    ("ntlm",    re.compile(r"^[a-f0-9]{32}:[a-f0-9]{32}$", re.I)),  # LM:NTLM
    ("crypt",   re.compile(r"^\$[1-6]\$")),                          # $1$..$6$
    ("base64",  re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")),
]

# Built-in wordlist for cracking weak hashes during enrichment. Loaded from
# src/wordlists/common.txt (~700 entries: OWASP top weak passwords, vendor
# defaults, canonical seeded creds for popular vulnerable training apps,
# pop-culture / CTF favourites). Each base word is mutated at load time
# (capitalization, year suffixes, leetspeak, common suffixes) to multiply
# coverage to ~10K candidates without bloating the on-disk file.

def _load_wordlist_from_file() -> list[str]:
    path = Path(__file__).parent / "wordlists" / "common.txt"
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
        # `user:pass` style lines (common in SecLists) — also try the pass alone
        if ":" in line and " " not in line:
            _, pw = line.rsplit(":", 1)
            if pw and pw not in out:
                out.append(pw)
    return out


def _mutate_wordlist(base: list[str]) -> list[str]:
    """Apply common mutations to each base word so a wordlist of 700 entries
    expands to ~10K candidates. Cheap (< 100 ms total) and catches typical
    user-applied transformations."""
    mutated: set[str] = set(base)
    common_year_suffixes = ("", "1", "12", "123", "1234", "!", "@",
                             "2023", "2024", "2025", "2026")
    for w in base:
        if " " in w:  # passphrases — no mutation, would explode size
            continue
        # Capitalisation variants
        mutated.add(w.lower())
        mutated.add(w.upper())
        mutated.add(w.capitalize())
        # Leetspeak (single substitution most common: a→@, e→3, i→1, o→0, s→$)
        for orig, sub in (("a", "@"), ("e", "3"), ("i", "1"),
                           ("o", "0"), ("s", "$")):
            if orig in w.lower():
                mutated.add(w.lower().replace(orig, sub, 1))
        # Suffix variations
        for suf in common_year_suffixes:
            if suf:
                mutated.add(w + suf)
                mutated.add(w.capitalize() + suf)
    return sorted(mutated)


_CRACK_WORDLIST = _mutate_wordlist(_load_wordlist_from_file()) or [
    # Fallback if the bundled wordlist file is missing for any reason
    "admin", "admin123", "password", "Password1", "12345", "123456",
    "qwerty", "letmein", "welcome", "changeme", "root", "toor",
    "test", "guest", "demo", "ncc-1701", "iloveyou",
]

# ---------------------------------------------------------------------------
# Regex sweepers (run on every string value + plaintext bodies)
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>{}|\\^`\[\]]+", re.IGNORECASE)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b")
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----")
# Google-shaped client id (e.g. 1005568560502-...apps.googleusercontent.com)
_GOOGLE_CLIENT_RE = re.compile(r"\b\d{10,}-[a-z0-9]+\.apps\.googleusercontent\.com\b")
# Slack token shapes
_SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")

# Username noise filter — strings that look like product names / descriptions.
# Cuts most false positives without dropping legitimate usernames (which tend
# to be short, single-token, no spaces).
_USERNAME_NOISE_CHARS = set(' \t\n.,!?;:()[]{}<>"\'/\\`')
# Generic UI labels that get mistaken for usernames when a string-typed
# UI-label value is bound to a key like `name` or `author`.
_USERNAME_BLACKLIST = frozenset({
    "user", "users", "author", "owner", "customer", "customers", "admin user",
    "guest", "anonymous", "system", "default", "none", "null", "undefined",
    "submit", "cancel", "ok", "yes", "no", "add", "edit", "delete", "save",
    "send", "search", "filter", "sort", "next", "previous", "back", "home",
    "menu", "settings", "profile", "account", "help", "about", "logout",
    "login", "signin", "signup", "welcome", "name", "email", "password",
    "username", "label", "title", "subject", "body", "content", "message",
    "comment", "description", "type", "kind", "status", "true", "false",
})

# A token's value must look token-shaped, not random English. Real auth
# tokens are: JWTs (eyJ...), bearer-prefixed, hex-shaped, base64-shaped,
# or session-id-shaped (long no-space).
_TOKEN_VALUE_RE = re.compile(
    r"^(?:Bearer\s+\S+|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|"
    r"[A-Za-z0-9_\-+/=.]{16,})$"
)
# Cookies must look like name=value pairs (or a single long token-shaped
# string). Reject prose like "Open side menu".
_COOKIE_VALUE_RE = re.compile(
    r"^([A-Za-z0-9_-]+=[^;\s]+(;\s*[A-Za-z0-9_-]+=[^;\s]+)*|[A-Za-z0-9_\-+/=.]{20,})$"
)


@dataclass
class Provenance:
    url: str
    json_path: str = ""
    method: str = "GET"
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "json_path": self.json_path, "snippet": self.snippet,
        }


@dataclass
class CredentialRecord:
    """One credential value bound to a user, with full provenance.
    `cred_type` is the field-name hint (password, hash, salt, secret, token).
    `algo` is the value-shape hint (plaintext, md5, sha1, bcrypt, ...)."""
    cred_type: str               # password | hash | salt | secret | token | refresh_token | ...
    algo: str                    # plaintext | md5 | sha1 | sha256 | bcrypt | argon2 | base64 | unknown
    value: str
    source_url: str = ""
    source_json_path: str = ""
    cracked_to: str = ""         # plaintext if we cracked the hash via wordlist

    def to_dict(self) -> dict:
        return {
            "cred_type": self.cred_type, "algo": self.algo,
            "value": self.value, "source_url": self.source_url,
            "source_json_path": self.source_json_path,
            "cracked_to": self.cracked_to,
        }


@dataclass
class UserRecord:
    canonical_id: str
    entity_type: str = "user"          # user|admin|service|test_account|oauth_app|unknown
    emails: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    user_ids: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    addresses: set[str] = field(default_factory=set)
    linked_urls: set[str] = field(default_factory=set)
    image_urls: set[str] = field(default_factory=set)
    secret_refs: set[str] = field(default_factory=set)   # sha-prefixes into global secrets/
    auth_credentials: dict = field(default_factory=dict)  # tokens/cookies/passwords for auth.json
    credentials: list = field(default_factory=list)       # list[CredentialRecord] — typed creds
    provenance: list[Provenance] = field(default_factory=list)
    extra: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    @property
    def score(self) -> int:
        """Higher = more enriched. Used for ordering in reports."""
        return (3 * len(self.emails) + 2 * len(self.usernames) +
                2 * len(self.user_ids) + len(self.phones) + len(self.addresses) +
                2 * len(self.secret_refs) + len(self.linked_urls) +
                len(self.image_urls) + (5 if self.auth_credentials else 0))

    def classify_type(self) -> None:
        """Heuristic entity-type classification based on accumulated identity
        fields. Called once after coalescing is complete."""
        names_blob = " ".join(self.usernames | self.emails).lower()
        if _ADMIN_USERNAME_RE.search(names_blob):
            self.entity_type = "admin"
        elif _SERVICE_USERNAME_RE.search(names_blob):
            self.entity_type = "service"
        elif _TEST_USERNAME_RE.search(names_blob):
            self.entity_type = "test_account"
        else:
            self.entity_type = "user"

    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "entity_type": self.entity_type,
            "score": self.score,
            "emails": sorted(self.emails),
            "usernames": sorted(self.usernames),
            "user_ids": sorted(self.user_ids),
            "phones": sorted(self.phones),
            "addresses": sorted(self.addresses),
            "linked_urls": sorted(self.linked_urls),
            "image_urls": sorted(self.image_urls),
            "secret_refs": sorted(self.secret_refs),
            "has_credentials": bool(self.auth_credentials),
            "extra": {k: sorted(v) for k, v in self.extra.items()},
        }


@dataclass
class OAuthApp:
    """OAuth client (NOT a user). Identified by client_id, optionally with
    client_secret + authorized_redirect_uris."""
    client_id: str
    client_secret: str = ""
    redirect_uris: set[str] = field(default_factory=set)
    name: str = ""
    issuer: str = ""
    provenance: list[Provenance] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entity_type": "oauth_app",
            "client_id": self.client_id,
            "client_secret_present": bool(self.client_secret),
            "redirect_uris": sorted(self.redirect_uris),
            "name": self.name,
            "issuer": self.issuer,
        }


@dataclass
class HostRecord:
    hostname: str
    ips: set[str] = field(default_factory=set)
    discovered_paths: set[str] = field(default_factory=set)
    related_urls: set[str] = field(default_factory=set)
    provenance: list[Provenance] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ips": sorted(self.ips),
            "discovered_paths": sorted(self.discovered_paths),
            "related_urls": sorted(self.related_urls),
        }


@dataclass
class SecretRecord:
    sha_prefix: str
    value: str
    type_hint: str
    entropy: float
    provenance: list[Provenance] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sha_prefix": self.sha_prefix,
            "type_hint": self.type_hint,
            "entropy": round(self.entropy, 2),
            "value_length": len(self.value),
            "value_preview": self.value[:24] + "…" if len(self.value) > 24 else self.value,
        }


@dataclass
class EnrichmentResult:
    users: dict[str, UserRecord] = field(default_factory=dict)
    hosts: dict[str, HostRecord] = field(default_factory=dict)
    secrets: dict[str, SecretRecord] = field(default_factory=dict)
    oauth_apps: dict[str, OAuthApp] = field(default_factory=dict)
    images_analyzed: dict[str, "image_analyzer.ImageAnalysis"] = field(default_factory=dict)
    unvisited_urls: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    bodies_processed: int = 0
    bodies_skipped: int = 0
    out_dir: str = ""

    def password_summary(self) -> dict:
        """Aggregated count of plaintext + cracked + uncracked credentials.
        Used by the loud stderr line so the operator sees the crack rate."""
        plaintext_count = 0
        cracked_count = 0
        uncracked_count = 0
        plaintext_users: list[tuple[str, str]] = []  # (user_label, password)
        for user in self.users.values():
            label = (next(iter(sorted(user.usernames)), "")
                     or next(iter(sorted(user.emails)), "")
                     or user.canonical_id)
            for c in user.credentials:
                if c.algo == "plaintext":
                    plaintext_count += 1
                    plaintext_users.append((label, c.value))
                elif c.cracked_to:
                    cracked_count += 1
                    plaintext_users.append((label, c.cracked_to))
                else:
                    uncracked_count += 1
            # AutoAuth password not represented as a CredentialRecord
            if user.auth_credentials.get("password"):
                pw = user.auth_credentials["password"]
                if not any(p == pw for _, p in plaintext_users):
                    plaintext_count += 1
                    plaintext_users.append((label, pw))
        return {
            "plaintext_count": plaintext_count,
            "cracked_count": cracked_count,
            "uncracked_count": uncracked_count,
            "total_passwords_known": plaintext_count + cracked_count,
            "plaintext_pairs": plaintext_users,
        }

    def by_type(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for u in self.users.values():
            counts[u.entity_type] += 1
        if self.oauth_apps:
            counts["oauth_app"] = len(self.oauth_apps)
        return dict(counts)

    def summary(self) -> dict:
        pw = self.password_summary()
        return {
            "users": len(self.users),
            "users_by_type": self.by_type(),
            "oauth_apps": len(self.oauth_apps),
            "hosts": len(self.hosts),
            "secrets": len(self.secrets),
            "passwords_plaintext": pw["plaintext_count"],
            "passwords_cracked": pw["cracked_count"],
            "passwords_uncracked": pw["uncracked_count"],
            "images_analyzed": len(self.images_analyzed),
            "unvisited_urls": len(self.unvisited_urls),
            "paths": len(self.paths),
            "bodies_processed": self.bodies_processed,
            "bodies_skipped": self.bodies_skipped,
            "out_dir": self.out_dir,
        }


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------

class Enricher:
    # Bodies above this size aren't walked (avoids OOM on chatty SPAs).
    _MAX_BODY_BYTES = 2 * 1024 * 1024
    # Keep snippet excerpts short — for the per-user provenance file.
    _SNIPPET_BYTES = 240
    # Min entropy for a "looks like a secret" string (Shannon bits/char).
    _SECRET_MIN_ENTROPY = 3.5
    # Min length for a string to be considered a secret candidate.
    _SECRET_MIN_LEN = 16

    def __init__(self, out_dir: str, target_origin: str):
        self.out_root = Path(out_dir) / "enrichment"
        self.target_origin = target_origin
        self.target_host = (urlparse(target_origin).hostname or "").lower()
        self._visited_urls: set[str] = set()
        self._email_to_user: dict[str, str] = {}
        self._username_to_user: dict[str, str] = {}
        self._userid_to_user: dict[str, str] = {}
        # url → local path, populated from FileGrabber result for image analysis
        self._url_to_local: dict[str, str] = {}
        self.result = EnrichmentResult(out_dir=str(self.out_root))

    def run(self, collector, extra_bodies: Optional[list] = None,
            visited_urls: Optional[set] = None,
            file_grabber_result=None,
            auto_auth_session=None) -> EnrichmentResult:
        """Walk every captured body and any extra bodies (e.g. from
        access_replay). visited_urls is the set of URLs the crawler has
        already hit — anything we discover but isn't in this set goes to
        unvisited_urls. file_grabber_result lets us locate downloaded image
        bytes for EXIF/steg analysis. auto_auth_session, if present, seeds
        the user record for the harvested account with a complete auth.json."""
        if visited_urls:
            self._visited_urls.update(u.split("#", 1)[0] for u in visited_urls)
        if file_grabber_result and getattr(file_grabber_result, "grabbed", None):
            for g in file_grabber_result.grabbed:
                if hasattr(g, "url") and hasattr(g, "local_path"):
                    self._url_to_local[g.url] = g.local_path

        for r in collector.requests:
            self._visited_urls.add(r.url.split("#", 1)[0])
            body = getattr(r, "response_body", None)
            if not body:
                self.result.bodies_skipped += 1
                continue
            self._process_body(
                url=r.url, method=r.method, body=body,
                content_type=self._sniff_ct(r),
            )

        if extra_bodies:
            for entry in extra_bodies:
                # entry: dict with keys url, body, content_type, method
                self._process_body(
                    url=entry["url"],
                    method=entry.get("method", "GET"),
                    body=entry["body"],
                    content_type=entry.get("content_type", ""),
                )

        # Seed the AutoAuth user record with full auth.json contents
        if auto_auth_session is not None:
            self._seed_from_auto_auth(auto_auth_session)

        # Classify each user record now that coalescing is complete
        for u in self.result.users.values():
            u.classify_type()

        # Analyze any images we have local copies for
        self._analyze_images()

        self._write_to_disk()
        return self.result

    # ------------------------------------------------------------------
    # Body processing
    # ------------------------------------------------------------------

    @staticmethod
    def _sniff_ct(captured_req) -> str:
        meta = getattr(captured_req, "response_headers", None) or {}
        for k, v in meta.items():
            if k.lower() == "content-type":
                return v.split(";", 1)[0].strip().lower()
        return ""

    def _process_body(self, url: str, method: str, body: Any,
                      content_type: str) -> None:
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                self.result.bodies_skipped += 1
                return
        if not isinstance(body, str):
            self.result.bodies_skipped += 1
            return
        if len(body) > self._MAX_BODY_BYTES:
            self.result.bodies_skipped += 1
            return
        self.result.bodies_processed += 1

        # 1. Try to parse as JSON — most rewarding (key-aware extraction).
        parsed: Optional[Any] = None
        if "json" in content_type or body.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = None
        if parsed is not None:
            self._walk_json(parsed, url=url, method=method, json_path="$")

        # 2. Always run the plaintext regex sweep — it catches things JSON
        # walking misses (HTML pages, error messages, mixed-format bodies).
        self._regex_sweep(body, url=url, method=method)

    def _walk_json(self, node: Any, url: str, method: str, json_path: str) -> None:
        if isinstance(node, dict):
            # 1. Scalar pass — extract identity / secret / host / image fields
            for key, val in node.items():
                key_lower = str(key).lower()
                child_path = f"{json_path}.{key}"
                if isinstance(val, (dict, list)) or val is None:
                    continue
                str_val = str(val)
                if not str_val.strip():
                    continue
                self._classify_kv(
                    key_lower=key_lower, value=str_val,
                    url=url, method=method, json_path=child_path,
                )
                self._regex_sweep(str_val, url=url, method=method,
                                  json_path=child_path)
            # 2. Group identity + image fields within this dict, link them
            self._link_within_dict(node, url=url, method=method,
                                   json_path=json_path)
            # 3. Detect OAuth-app patterns (client_id + redirect_uris)
            self._detect_oauth_app(node, url=url, method=method,
                                   json_path=json_path)
            # 4. Recurse
            for key, val in node.items():
                if isinstance(val, (dict, list)):
                    self._walk_json(val, url=url, method=method,
                                    json_path=f"{json_path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk_json(item, url=url, method=method,
                                json_path=f"{json_path}[{i}]")

    def _link_within_dict(self, node: dict, url: str, method: str,
                          json_path: str) -> None:
        """Within a single JSON object, group identity fields + image fields +
        token/cookie fields and attach them to the same UserRecord. This is
        what lets `{username: admin, avatar: /img/admin.png}` create
        users/admin/images/admin.png."""
        identities: list[tuple[str, str]] = []  # (kind, value)
        images: list[str] = []
        tokens: list[tuple[str, str]] = []      # (kind, value)
        creds: list[tuple[str, str]] = []       # (cred_type_hint, value) — passwords/hashes
        for key, val in node.items():
            if not isinstance(val, (str, int, float)):
                continue
            v = str(val).strip()
            if not v:
                continue
            kl = str(key).lower()
            if _key_matches_token(kl, _EMAIL_KEYS) and "@" in v:
                identities.append(("email", v))
            elif _key_matches_token(kl, _USERNAME_KEYS) and self._is_plausible_username(v):
                identities.append(("username", v))
            elif _key_matches_token(kl, _USER_ID_KEYS) and v and len(v) <= 64:
                identities.append(("user_id", v))
            if _key_matches_token(kl, _IMAGE_KEYS):
                resolved = self._resolve_url(v, source=url)
                if resolved and (_IMAGE_EXT_RE.search(resolved) or
                                 v.lower().endswith(("png", "jpg", "jpeg",
                                                      "gif", "webp"))):
                    images.append(resolved)
            if _key_matches_token(kl, _TOKEN_KEYS) and self._is_plausible_token(v):
                tokens.append(("token", v))
            elif _key_matches_token(kl, _COOKIE_KEYS) and self._is_plausible_cookie(v):
                tokens.append(("cookie", v))
            # Per-user credentials. A password/hash colocated with an identity
            # belongs to THAT identity, not just the global secrets bucket.
            # (`_classify_kv` still records it globally; we additionally bind
            # it to the user record below.)
            if _key_matches_token(kl, _SECRET_KEYS) and not self._is_placeholder_secret(v):
                cred_type = self._secret_type_hint(kl, v)
                algo = self._detect_hash_algo(v)
                # Note the per-key json_path (parent json_path + this key)
                creds.append((cred_type, algo, v, f"{json_path}.{key}"))

        if not identities:
            return
        for kind, ident_val in identities:
            user = self._lookup_or_create(kind, ident_val)
            for img_url in images:
                user.image_urls.add(img_url)
            for cred_type, algo, cred_val, cred_json_path in creds:
                sha = hashlib.sha256(cred_val.encode()).hexdigest()[:16]
                user.secret_refs.add(sha)
                # Build a typed CredentialRecord with full provenance
                cracked = self._try_crack(cred_val, algo) if algo in (
                    "md5", "sha1", "sha256") else ""
                user.credentials.append(CredentialRecord(
                    cred_type=cred_type, algo=algo, value=cred_val,
                    source_url=url, source_json_path=cred_json_path,
                    cracked_to=cracked,
                ))
                # auth.json convenience fields
                if cred_type == "password":
                    if algo == "plaintext":
                        user.auth_credentials.setdefault("password", cred_val)
                    else:
                        user.auth_credentials.setdefault("password_hash", cred_val)
                        user.auth_credentials.setdefault("password_hash_algo", algo)
                        if cracked:
                            # We have the plaintext too — surface both
                            user.auth_credentials.setdefault("password", cracked)
                elif cred_type in ("hash", "salt"):
                    user.auth_credentials.setdefault(cred_type, cred_val)
            for tok_kind, tok_val in tokens:
                # Stash tokens for later auth.json synthesis. Don't overwrite
                # if we already have one (first capture wins per category).
                if tok_kind == "token" and "token" not in user.auth_credentials:
                    user.auth_credentials["token"] = tok_val
                elif tok_kind == "cookie":
                    cookies = user.auth_credentials.setdefault("cookies", {})
                    # Parse "name=value" pairs out of the cookie string;
                    # fall back to a single opaque entry if it doesn't parse.
                    parsed = self._parse_cookie_str(tok_val)
                    if parsed:
                        for k, v in parsed.items():
                            if len(cookies) < 10 and k not in cookies:
                                cookies[k] = v

    def _detect_oauth_app(self, node: dict, url: str, method: str,
                          json_path: str) -> None:
        """Recognise the OAuth-app shape: a dict with client_id (and usually
        either redirect_uris/authorized_redirects or client_secret). These
        are NOT users — they're applications. Recorded separately."""
        client_id: Optional[str] = None
        client_secret: str = ""
        redirect_uris: set[str] = set()
        name: str = ""
        issuer: str = ""
        for key, val in node.items():
            kl = str(key).lower()
            if kl in ("clientid", "client_id") and isinstance(val, (str, int)):
                client_id = str(val)
            elif kl in ("clientsecret", "client_secret") and isinstance(val, str):
                client_secret = val
            elif "redirect" in kl and isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, str) and v.startswith("http"):
                                redirect_uris.add(v)
                    elif isinstance(item, str) and item.startswith("http"):
                        redirect_uris.add(item)
            elif "name" in kl and not name and isinstance(val, str) and len(val) < 80:
                name = val
            elif "issuer" in kl and isinstance(val, str):
                issuer = val
        if not client_id:
            return
        # Need at least one corroborating field for it to be a legit OAuth app
        # (otherwise stray client_id values get over-claimed).
        if not (client_secret or redirect_uris):
            return
        sanitized = self._sanitize(client_id)
        app = self.result.oauth_apps.setdefault(
            sanitized, OAuthApp(client_id=client_id),
        )
        if client_secret:
            app.client_secret = client_secret
        app.redirect_uris.update(redirect_uris)
        if name and not app.name:
            app.name = name
        if issuer and not app.issuer:
            app.issuer = issuer
        if len(app.provenance) < 50:
            app.provenance.append(self._mk_prov(
                url=url, method=method, json_path=json_path,
                snippet=f"client_id={client_id[:40]}…",
            ))

    def _lookup_or_create(self, kind: str, value: str) -> UserRecord:
        """Return existing UserRecord matching identity, or create new one."""
        if kind == "email" and value.lower() in self._email_to_user:
            return self.result.users[self._email_to_user[value.lower()]]
        if kind == "user_id" and value in self._userid_to_user:
            return self.result.users[self._userid_to_user[value]]
        if kind == "username" and value in self._username_to_user:
            return self.result.users[self._username_to_user[value]]
        canonical = self._mint_canonical_id(
            email=value if kind == "email" else "",
            username=value if kind == "username" else "",
            user_id=value if kind == "user_id" else "",
        )
        if canonical not in self.result.users:
            self.result.users[canonical] = UserRecord(canonical_id=canonical)
        rec = self.result.users[canonical]
        if kind == "email":
            rec.emails.add(value.lower())
            self._email_to_user[value.lower()] = canonical
        elif kind == "username":
            rec.usernames.add(value)
            self._username_to_user[value] = canonical
        elif kind == "user_id":
            rec.user_ids.add(value)
            self._userid_to_user[value] = canonical
        return rec

    def _resolve_url(self, value: str, source: str) -> str:
        """Resolve possibly-relative value to absolute URL using source URL or
        target_origin as base. Returns "" if value isn't URL-shaped."""
        v = value.strip()
        if not v:
            return ""
        if v.startswith(("http://", "https://")):
            return v
        if v.startswith("//"):
            scheme = urlparse(source).scheme or "https"
            return f"{scheme}:{v}"
        if v.startswith("/"):
            return urljoin(source or self.target_origin, v)
        # Bare filename → assume same dir as source URL
        if "/" not in v and "." in v:
            return urljoin(source or self.target_origin, v)
        return ""

    def _seed_from_auto_auth(self, session) -> None:
        """If AutoAuth provisioned a real account, write its full credentials
        into that user's auth.json so the operator can re-authenticate."""
        creds = getattr(session, "credentials", None)
        if not creds:
            return
        username = getattr(creds, "username", "") or ""
        email = getattr(creds, "email", "") or ""
        password = getattr(creds, "password", "") or ""
        if not (username or email):
            return
        kind = "email" if email else "username"
        rec = self._lookup_or_create(kind, email or username)
        if password:
            rec.auth_credentials["password"] = password
        if email and not rec.emails:
            rec.emails.add(email.lower())
        if username and username not in rec.usernames:
            rec.usernames.add(username)
        token = getattr(session, "token", "")
        if token:
            rec.auth_credentials["token"] = token
        cookies = getattr(session, "cookies", None) or {}
        if cookies:
            rec.auth_credentials["cookies"] = dict(cookies)
        rec.auth_credentials["headers"] = session.to_auth_headers() if hasattr(session, "to_auth_headers") else {}
        rec.auth_credentials["source"] = "auto_auth"

    def _analyze_images(self) -> None:
        """Run image_analyzer over every locally-downloaded image referenced
        by any user OR present in the FileGrabber pool."""
        # Collect image URLs from users + every URL we have a local copy of
        # that has an image extension
        candidates: set[str] = set()
        for u in self.result.users.values():
            candidates.update(u.image_urls)
        for url, local in self._url_to_local.items():
            if _IMAGE_EXT_RE.search(url) or _IMAGE_EXT_RE.search(local):
                candidates.add(url)
        for url in candidates:
            local = self._url_to_local.get(url)
            if not local:
                continue
            try:
                analysis = image_analyzer.analyze(local)
            except Exception:
                continue
            self.result.images_analyzed[url] = analysis

    def _classify_kv(self, key_lower: str, value: str, url: str,
                     method: str, json_path: str) -> None:
        prov = self._mk_prov(url=url, method=method, json_path=json_path,
                             snippet=value[:self._SNIPPET_BYTES])
        # Image keys are handled in _link_within_dict so they can be tied to
        # the user identity in the same JSON object — skip here.
        if _key_matches_token(key_lower, _IMAGE_KEYS):
            return
        # Order matters — secret keys checked before identity keys so a field
        # named "user_password" is treated as secret first.
        if _key_matches_token(key_lower, _SECRET_KEYS):
            type_hint = self._secret_type_hint(key_lower, value)
            self._record_secret(value, type_hint=type_hint, prov=prov)
            return
        if _key_matches_token(key_lower, _CREDENTIAL_VALUE_KEYS):
            self._record_secret(value, type_hint=key_lower, prov=prov)
            return
        if _key_matches_token(key_lower, _EMAIL_KEYS):
            if _EMAIL_RE.fullmatch(value.strip()) or "@" in value:
                self._add_to_user(email=value.strip(), prov=prov, src_url=url)
            return
        if _key_matches_token(key_lower, _USERNAME_KEYS):
            uname = value.strip()
            if self._is_plausible_username(uname):
                self._add_to_user(username=uname, prov=prov, src_url=url)
            return
        if _key_matches_token(key_lower, _USER_ID_KEYS):
            uid = value.strip()
            if uid and len(uid) <= 64:
                self._add_to_user(user_id=uid, prov=prov, src_url=url)
            return
        if _key_matches_token(key_lower, _PHONE_KEYS):
            self._add_to_user(phone=value.strip(), prov=prov, src_url=url)
            return
        if _key_matches_token(key_lower, _ADDRESS_KEYS):
            self._add_to_user(address_part=value.strip(), prov=prov, src_url=url)
            return
        if _key_matches_token(key_lower, _HOST_KEYS):
            self._record_host_or_url(value, prov=prov)
            return
        if _key_matches_token(key_lower, _PATH_KEYS):
            v = value.strip()
            if v and "/" in v and len(v) < 256:
                self.result.paths.add(v)
            return

    def _regex_sweep(self, text: str, url: str, method: str,
                     json_path: str = "") -> None:
        prov_factory = lambda snippet="": self._mk_prov(
            url=url, method=method, json_path=json_path,
            snippet=snippet[:self._SNIPPET_BYTES],
        )
        for m in _EMAIL_RE.finditer(text):
            self._add_to_user(email=m.group(0), prov=prov_factory(m.group(0)),
                              src_url=url)
        for m in _JWT_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="jwt",
                                prov=prov_factory(m.group(0)[:60] + "…"))
        for m in _AWS_KEY_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="aws_access_key",
                                prov=prov_factory(m.group(0)))
        for m in _BEARER_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="bearer_header",
                                prov=prov_factory(m.group(0)[:60] + "…"))
        for m in _PRIVATE_KEY_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="private_key_pem",
                                prov=prov_factory("-----BEGIN ...-----"))
        for m in _GOOGLE_CLIENT_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="google_oauth_client_id",
                                prov=prov_factory(m.group(0)))
        for m in _SLACK_TOKEN_RE.finditer(text):
            self._record_secret(m.group(0), type_hint="slack_token",
                                prov=prov_factory(m.group(0)))
        for m in _IPV4_RE.finditer(text):
            ip = m.group(0)
            # Skip obvious non-routable noise (0.0.0.0, broadcast)
            if ip in ("0.0.0.0", "255.255.255.255"):
                continue
            self._record_host_or_url(ip, prov=prov_factory(ip))
        for m in _URL_RE.finditer(text):
            u = m.group(0).rstrip(".,);")
            self._record_host_or_url(u, prov=prov_factory(u[:120]))

    # ------------------------------------------------------------------
    # Records — coalescing + storage
    # ------------------------------------------------------------------

    def _add_to_user(self, prov: Provenance, src_url: str,
                     email: str = "", username: str = "",
                     user_id: str = "", phone: str = "",
                     address_part: str = "") -> None:
        # Find or create the canonical record. Identity index lookups in
        # priority order: email > user_id > username (most specific first).
        canonical: Optional[str] = None
        if email and email in self._email_to_user:
            canonical = self._email_to_user[email]
        elif user_id and user_id in self._userid_to_user:
            canonical = self._userid_to_user[user_id]
        elif username and username in self._username_to_user:
            canonical = self._username_to_user[username]

        if canonical is None:
            canonical = self._mint_canonical_id(email=email, username=username,
                                                user_id=user_id)
            if canonical not in self.result.users:
                self.result.users[canonical] = UserRecord(canonical_id=canonical)

        rec = self.result.users[canonical]
        if email:
            rec.emails.add(email.lower())
            self._email_to_user[email.lower()] = canonical
        if username:
            rec.usernames.add(username)
            self._username_to_user[username] = canonical
        if user_id:
            rec.user_ids.add(user_id)
            self._userid_to_user[user_id] = canonical
        if phone:
            rec.phones.add(phone)
        if address_part:
            rec.addresses.add(address_part)
        rec.linked_urls.add(src_url)
        # Cap provenance per record to prevent runaway memory
        if len(rec.provenance) < 200:
            rec.provenance.append(prov)

    @staticmethod
    def _mint_canonical_id(email: str = "", username: str = "",
                           user_id: str = "") -> str:
        if email:
            return Enricher._sanitize(email.lower())
        if username:
            return Enricher._sanitize(username)
        if user_id:
            return f"id_{Enricher._sanitize(user_id)}"
        return "anonymous_" + hashlib.sha256(b"x").hexdigest()[:8]

    @staticmethod
    def _sanitize(s: str, max_len: int = 60) -> str:
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "x"
        if len(clean) > max_len:
            tail = hashlib.sha256(s.encode()).hexdigest()[:8]
            clean = clean[:max_len - 9] + "_" + tail
        return clean

    @staticmethod
    def _is_plausible_username(s: str) -> bool:
        if not s or len(s) > 60:
            return False
        if any(c in _USERNAME_NOISE_CHARS for c in s):
            return False
        # Reject pure numbers (those are IDs, handled separately)
        if s.isdigit():
            return False
        # Reject UI-label false positives ("Author", "Customer", "Login", etc.)
        if s.lower() in _USERNAME_BLACKLIST:
            return False
        # Title-case single-word strings are usually labels, not usernames.
        # Real usernames are lowercase, snake_case, camelCase, or have digits.
        if (s[0].isupper() and s[1:].islower() and s.isalpha()
                and len(s) < 12):
            return False
        return True

    @staticmethod
    def _is_plausible_token(s: str) -> bool:
        if not s or len(s) < 16 or len(s) > 4096:
            return False
        if " " in s and not s.lower().startswith("bearer "):
            return False
        return bool(_TOKEN_VALUE_RE.match(s))

    # Precomputed hash → plaintext lookup for the bundled wordlist.
    # Built once at class import time (not per-instance).
    _CRACK_LOOKUP: dict[str, dict[str, str]] = {"md5": {}, "sha1": {}, "sha256": {}}

    @classmethod
    def _build_crack_lookup(cls) -> None:
        """Precompute hash→plaintext for the bundled wordlist. Idempotent."""
        if cls._CRACK_LOOKUP["md5"]:
            return
        for word in _CRACK_WORDLIST:
            wb = word.encode()
            cls._CRACK_LOOKUP["md5"][hashlib.md5(wb).hexdigest()] = word
            cls._CRACK_LOOKUP["sha1"][hashlib.sha1(wb).hexdigest()] = word
            cls._CRACK_LOOKUP["sha256"][hashlib.sha256(wb).hexdigest()] = word

    @classmethod
    def _try_crack(cls, value: str, algo: str) -> str:
        """Lookup `value` (a hex digest) against the precomputed wordlist.
        Returns the plaintext if found, else empty string."""
        if algo not in cls._CRACK_LOOKUP:
            return ""
        cls._build_crack_lookup()
        return cls._CRACK_LOOKUP[algo].get(value.lower(), "")

    @staticmethod
    def _detect_hash_algo(value: str) -> str:
        """Return the hash algorithm name if `value` matches a known shape.
        Returns 'plaintext' if it doesn't match any digest pattern."""
        v = value.strip()
        if not v:
            return "plaintext"
        for algo, pat in _HASH_PATTERNS:
            if pat.match(v):
                return algo
        return "plaintext"

    @staticmethod
    def _is_placeholder_secret(s: str) -> bool:
        """True if `s` is an obvious masked / placeholder credential value
        ('***', '----', 'redacted', 'hidden', etc.) that shouldn't be saved."""
        v = s.strip().lower()
        if not v:
            return True
        if v in ("none", "null", "undefined", "redacted", "hidden", "n/a"):
            return True
        # Strings that are entirely a single repeated mask character
        unique_chars = set(v)
        if len(unique_chars) == 1 and unique_chars.issubset({"*", "x", "-", "_", "."}):
            return True
        # Very short values aren't useful as credentials in their own right
        # (and would mostly be field labels or status codes)
        if len(v) < 4:
            return True
        return False

    @staticmethod
    def _parse_cookie_str(s: str) -> dict:
        """Parse 'name=value; name2=value2' into a dict. Returns {} if the
        input doesn't contain at least one well-formed pair."""
        out: dict[str, str] = {}
        for part in s.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip():
                out[kv[0].strip()] = kv[1].strip()
        return out

    @staticmethod
    def _is_plausible_cookie(s: str) -> bool:
        if not s or len(s) < 8 or len(s) > 8192:
            return False
        return bool(_COOKIE_VALUE_RE.match(s))

    def _record_host_or_url(self, value: str, prov: Provenance) -> None:
        v = value.strip()
        if not v:
            return
        # If it parses as a URL, also harvest the path + decide unvisited.
        if v.startswith(("http://", "https://")):
            try:
                parsed = urlparse(v)
            except Exception:
                return
            host = (parsed.hostname or "").lower()
            if host:
                self._add_host(host, related_url=v, prov=prov)
            # Track unvisited (different scheme/host counts as unvisited too)
            cleaned = v.split("#", 1)[0]
            if cleaned not in self._visited_urls:
                self.result.unvisited_urls.add(cleaned)
            if parsed.path and parsed.path != "/":
                self.result.paths.add(parsed.path)
            return
        # IPv4
        if _IPV4_RE.fullmatch(v):
            self._add_host(v, prov=prov, ip=v)
            return
        # Bare hostname — only accept if it looks like a domain (has a dot,
        # alphanumeric segments, < 253 chars).
        if "." in v and len(v) < 253 and re.fullmatch(r"[A-Za-z0-9.\-_]+", v):
            self._add_host(v.lower(), prov=prov)

    def _add_host(self, hostname: str, prov: Provenance,
                  related_url: str = "", ip: str = "") -> None:
        if hostname not in self.result.hosts:
            self.result.hosts[hostname] = HostRecord(hostname=hostname)
        host = self.result.hosts[hostname]
        if ip:
            host.ips.add(ip)
        if related_url:
            host.related_urls.add(related_url)
        if len(host.provenance) < 100:
            host.provenance.append(prov)

    def _record_secret(self, value: str, type_hint: str,
                       prov: Provenance) -> None:
        v = value.strip().strip("'\"")
        if not v:
            return
        # Filter trivial values that are clearly placeholders / known bad
        if v.lower() in ("undefined", "null", "true", "false", "0", "1", "x"):
            return
        # Entropy gate for generic secrets (skip e.g. type_hint=="password" if
        # the value is super short and low-entropy — likely a placeholder).
        ent = self._shannon_entropy(v)
        if (type_hint in ("password", "secret") and len(v) < 6
                and ent < self._SECRET_MIN_ENTROPY):
            return
        sha = hashlib.sha256(v.encode()).hexdigest()[:16]
        if sha not in self.result.secrets:
            self.result.secrets[sha] = SecretRecord(
                sha_prefix=sha, value=v, type_hint=type_hint, entropy=ent,
            )
        rec = self.result.secrets[sha]
        if len(rec.provenance) < 50:
            rec.provenance.append(prov)

    @staticmethod
    def _secret_type_hint(key_lower: str, value: str) -> str:
        if "password" in key_lower or "pwd" in key_lower:
            return "password"
        if "client_secret" in key_lower:
            return "oauth_client_secret"
        if "client_id" in key_lower:
            return "oauth_client_id"
        if "api_key" in key_lower or "apikey" in key_lower:
            return "api_key"
        if "private_key" in key_lower:
            return "private_key"
        if "refresh_token" in key_lower:
            return "refresh_token"
        if "access_token" in key_lower:
            return "access_token"
        if "hash" in key_lower:
            return "hash"
        if "salt" in key_lower:
            return "salt"
        if _JWT_RE.search(value):
            return "jwt"
        return "secret"

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _mk_prov(url: str, method: str, json_path: str, snippet: str) -> Provenance:
        return Provenance(url=url, method=method, json_path=json_path,
                          snippet=snippet)

    # ------------------------------------------------------------------
    # Disk writer
    # ------------------------------------------------------------------

    def _write_to_disk(self) -> None:
        if not self._has_findings():
            return
        self.out_root.mkdir(parents=True, exist_ok=True)

        # users/<id>/  (one folder per discovered identity, typed)
        if self.result.users:
            users_dir = self.out_root / "users"
            users_dir.mkdir(exist_ok=True)
            for user in self.result.users.values():
                self._write_user_folder(users_dir / user.canonical_id, user)

        # oauth_apps/<client_id>/  (NOT users — applications)
        if self.result.oauth_apps:
            apps_dir = self.out_root / "oauth_apps"
            apps_dir.mkdir(exist_ok=True)
            for app in self.result.oauth_apps.values():
                self._write_oauth_app_folder(
                    apps_dir / self._sanitize(app.client_id), app,
                )

        # hosts/<hostname>/
        if self.result.hosts:
            hosts_dir = self.out_root / "hosts"
            hosts_dir.mkdir(exist_ok=True)
            for host in self.result.hosts.values():
                self._write_host_folder(hosts_dir / self._sanitize(host.hostname), host)

        # secrets/<sha>/
        if self.result.secrets:
            secrets_dir = self.out_root / "secrets"
            secrets_dir.mkdir(exist_ok=True)
            for sec in self.result.secrets.values():
                self._write_secret_folder(secrets_dir / sec.sha_prefix, sec)

        # images/<sanitized-name>/  (every analyzed image, orphan or linked)
        if self.result.images_analyzed:
            images_dir = self.out_root / "images"
            images_dir.mkdir(exist_ok=True)
            for img_url, analysis in self.result.images_analyzed.items():
                folder_name = self._sanitize(Path(analysis.file_path).name) or "img"
                self._write_image_folder(
                    images_dir / folder_name, img_url, analysis,
                )

        # urls_unvisited/
        if self.result.unvisited_urls:
            uv_dir = self.out_root / "urls_unvisited"
            uv_dir.mkdir(exist_ok=True)
            (uv_dir / "unvisited.txt").write_text(
                "\n".join(sorted(self.result.unvisited_urls)) + "\n"
            )
            by_host_dir = uv_dir / "by_host"
            by_host_dir.mkdir(exist_ok=True)
            host_buckets: dict[str, list[str]] = defaultdict(list)
            for u in self.result.unvisited_urls:
                try:
                    host = (urlparse(u).hostname or "unknown").lower()
                except Exception:
                    host = "unknown"
                host_buckets[host].append(u)
            for host, urls in host_buckets.items():
                (by_host_dir / f"{self._sanitize(host)}.txt").write_text(
                    "\n".join(sorted(urls)) + "\n"
                )

        # paths/
        if self.result.paths:
            paths_dir = self.out_root / "paths"
            paths_dir.mkdir(exist_ok=True)
            (paths_dir / "paths.txt").write_text(
                "\n".join(sorted(self.result.paths)) + "\n"
            )

        # passwords.txt — aggregate of every plaintext + cracked credential
        # we know, across all users. This is the "show me everything you found"
        # file the operator opens first.
        pw_summary = self.result.password_summary()
        if pw_summary["plaintext_pairs"]:
            lines = [
                "# All known plaintext passwords harvested by this scan.",
                "# Sources: plaintext fields in response bodies, AutoAuth-",
                "# provisioned accounts, and hashes cracked against the bundled",
                "# wordlist + mutations.",
                "#",
                f"# Total: {pw_summary['plaintext_count']} plaintext + "
                f"{pw_summary['cracked_count']} cracked = "
                f"{pw_summary['total_passwords_known']} usable creds",
                f"# Uncracked hashes still on disk: {pw_summary['uncracked_count']}",
                "#",
                "# Format: <user_label>:<password>",
                "",
            ]
            for label, pw in sorted(pw_summary["plaintext_pairs"]):
                lines.append(f"{label}:{pw}")
            (self.out_root / "passwords.txt").write_text("\n".join(lines) + "\n")

        # summary + notes
        (self.out_root / "summary.json").write_text(
            json.dumps({
                "summary": self.result.summary(),
                "users_index": sorted(
                    [{"id": u.canonical_id, "score": u.score,
                      "emails": sorted(u.emails)[:3],
                      "usernames": sorted(u.usernames)[:3]}
                     for u in self.result.users.values()],
                    key=lambda x: -x["score"],
                ),
                "hosts_index": sorted(
                    [{"hostname": h.hostname, "ips": sorted(h.ips),
                      "related_url_count": len(h.related_urls)}
                     for h in self.result.hosts.values()],
                    key=lambda x: x["hostname"],
                ),
                "secrets_index": sorted(
                    [s.to_dict() for s in self.result.secrets.values()],
                    key=lambda x: -x["entropy"],
                )[:200],
            }, indent=2),
        )
        (self.out_root / "notes.md").write_text(self._render_notes())

    def _has_findings(self) -> bool:
        return bool(self.result.users or self.result.hosts
                    or self.result.secrets or self.result.unvisited_urls
                    or self.result.paths)

    def _write_user_folder(self, folder: Path, user: UserRecord) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "record.json").write_text(json.dumps(user.to_dict(), indent=2))
        (folder / "provenance.json").write_text(
            json.dumps([p.to_dict() for p in user.provenance], indent=2)
        )
        if user.linked_urls:
            (folder / "linked_urls.txt").write_text(
                "\n".join(sorted(user.linked_urls)) + "\n"
            )
        # auth.json — always written so every user folder has a uniform contract
        # for IDOR / cross-account testing. Populated when we have credentials,
        # stub-with-guidance when we don't.
        self._write_auth_json(folder / "auth.json", user)
        # secrets/ — per-user typed credentials. Each credential gets:
        #   <type>.<algo>.txt           (e.g. password.md5.txt, password.txt for plaintext)
        #   <type>.<algo>.source.json   (sidecar: source URL + JSON path + cracked plaintext)
        # When we cracked the hash, an extra `cracked.txt` file holds the plaintext.
        if user.credentials or user.auth_credentials.get("password"):
            secrets_dir = folder / "secrets"
            secrets_dir.mkdir(exist_ok=True)
            self._write_per_user_credentials(secrets_dir, user)
        # seen_in/<sanitized-source-url>.txt — snippets per source URL
        seen_in = folder / "seen_in"
        by_url: dict[str, list[Provenance]] = defaultdict(list)
        for p in user.provenance:
            by_url[p.url].append(p)
        if by_url:
            seen_in.mkdir(exist_ok=True)
            for src_url, provs in by_url.items():
                fname = self._sanitize(urlparse(src_url).path or src_url) or "root"
                (seen_in / f"{fname}.txt").write_text(
                    f"# {src_url}\n\n" + "\n\n---\n\n".join(
                        f"{p.json_path}\n{p.snippet}" for p in provs[:30]
                    ) + "\n"
                )
        # images/<basename> — copy + analyze every image associated with this
        # user. Falls back gracefully when we don't have a local copy.
        if user.image_urls:
            images = folder / "images"
            images.mkdir(exist_ok=True)
            for img_url in sorted(user.image_urls):
                local = self._url_to_local.get(img_url)
                analysis = self.result.images_analyzed.get(img_url)
                basename = Path(urlparse(img_url).path).name or "image"
                basename = self._sanitize(basename) or "image"
                if local and Path(local).exists():
                    try:
                        shutil.copy2(local, images / basename)
                    except Exception:
                        pass
                else:
                    (images / f"{basename}.url").write_text(img_url + "\n")
                if analysis:
                    (images / f"{basename}.metadata.json").write_text(
                        json.dumps(analysis.to_dict(), indent=2),
                    )

    def _write_auth_json(self, path: Path, user: UserRecord) -> None:
        """Synthesize an auth-headers JSON for this user, in the shape
        `--auth-headers` consumes (flat header dict + `_meta` block).

        Always written — when we have credentials the headers are populated;
        when we don't, we write a STUB containing identity hints and guidance
        on how to obtain creds. Uniform contract makes downstream IDOR /
        cross-account probes trivial: iterate `users/*/auth.json` and treat
        any with `_meta.auth_session_present == true` as drivers, the rest
        as targets to attempt cross-account access against.
        """
        creds = user.auth_credentials
        out: dict = {}
        # Prefer the precomputed headers from auto_auth if present
        if isinstance(creds.get("headers"), dict) and creds["headers"]:
            out.update(creds["headers"])
        if creds.get("token") and "Authorization" not in out:
            out["Authorization"] = f"Bearer {creds['token']}"
        if creds.get("cookies") and "Cookie" not in out:
            cookies = creds["cookies"]
            if isinstance(cookies, dict):
                out["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        username = next(iter(sorted(user.usernames)), "")
        email = next(iter(sorted(user.emails)), "")
        user_id = next(iter(sorted(user.user_ids)), "") if user.user_ids else ""
        auth_present = bool("Authorization" in out or "Cookie" in out)

        meta: dict = {
            "username": username,
            "email": email,
            "user_id": user_id,
            "entity_type": user.entity_type,
            "source": creds.get("source", "harvested_from_response"),
            "password": creds.get("password", ""),
            "password_hash": creds.get("password_hash", ""),
            "salt": creds.get("salt", ""),
            "hash": creds.get("hash", ""),
            "auth_session_present": auth_present,
        }

        # Stub guidance when we couldn't acquire a session for this user.
        # Tells the operator (and any future automation) what would be needed.
        if not auth_present:
            meta["status"] = "no_credentials_acquired"
            ways: list[str] = []
            if email or username:
                ways.append(
                    f"Log in via UI as {email or username} and copy the resulting "
                    f"Authorization/Cookie header into this file."
                )
            if creds.get("password_hash") or creds.get("hash"):
                ways.append(
                    "Crack the password hash in secrets/ (hashcat/john) and use "
                    "the plaintext to log in."
                )
            if user_id and not (email or username):
                ways.append(
                    f"User identified only by id={user_id}. Discover the email "
                    "or username (try /api/users/<id>, profile pages, GraphQL)."
                )
            if not ways:
                ways.append(
                    "Identity is partial — gather email/username before "
                    "attempting authentication."
                )
            meta["how_to_obtain"] = ways

        path.write_text(json.dumps({**out, "_meta": meta}, indent=2))

    def _write_per_user_credentials(self, secrets_dir: Path, user: UserRecord) -> None:
        """Write each typed CredentialRecord plus AutoAuth plaintext to disk.
        Filenames: `<type>.txt` for plaintext, `<type>_hash.<algo>.txt` for digests.
        Sidecar `<filename>.source.json` records provenance (URL + JSON path)."""
        # Group identical (type, algo, value) so duplicates from multiple URLs
        # collapse to one file but the sidecar lists every source.
        grouped: dict[tuple, list[CredentialRecord]] = defaultdict(list)
        for c in user.credentials:
            grouped[(c.cred_type, c.algo, c.value)].append(c)

        # Track which filenames we've used so multi-value-same-type doesn't collide
        used_names: set[str] = set()

        def _next_name(base: str) -> str:
            if base not in used_names:
                used_names.add(base)
                return base
            i = 2
            while True:
                cand = f"{base.rsplit('.', 1)[0]}_{i}.{base.rsplit('.', 1)[1]}"
                if cand not in used_names:
                    used_names.add(cand)
                    return cand
                i += 1

        for (cred_type, algo, value), records in grouped.items():
            # Filename: `password.txt` for plaintext, `password_hash.md5.txt` for hash
            if algo == "plaintext":
                fname = _next_name(f"{cred_type}.txt")
            else:
                fname = _next_name(f"{cred_type}_hash.{algo}.txt")
            (secrets_dir / fname).write_text(value + "\n")
            # Sidecar source file
            sidecar = {
                "value_first_8": value[:8],
                "value_length": len(value),
                "cred_type": cred_type,
                "algorithm": algo,
                "sources": [
                    {"url": r.source_url, "json_path": r.source_json_path}
                    for r in records
                ],
                "cracked_to": records[0].cracked_to,
            }
            (secrets_dir / f"{fname}.source.json").write_text(
                json.dumps(sidecar, indent=2)
            )
            # If we cracked the hash, write the plaintext too
            if records[0].cracked_to:
                cracked_name = _next_name(f"{cred_type}.cracked.txt")
                (secrets_dir / cracked_name).write_text(records[0].cracked_to + "\n")
                (secrets_dir / f"{cracked_name}.source.json").write_text(json.dumps({
                    "cracked_from": value,
                    "algorithm": algo,
                    "method": "built-in wordlist",
                }, indent=2))

        # AutoAuth plaintext password (and other auth_credentials values not
        # already represented as a CredentialRecord)
        if user.auth_credentials.get("password"):
            pw = user.auth_credentials["password"]
            already_written = any(
                c.cred_type == "password" and c.algo == "plaintext" and c.value == pw
                for c in user.credentials
            )
            if not already_written:
                fname = _next_name("password.txt")
                (secrets_dir / fname).write_text(pw + "\n")
                (secrets_dir / f"{fname}.source.json").write_text(json.dumps({
                    "value_first_8": pw[:8],
                    "value_length": len(pw),
                    "cred_type": "password",
                    "algorithm": "plaintext",
                    "sources": [{"url": "auto_auth provisioning",
                                  "json_path": "$.credentials.password"}],
                    "note": "harvested by AutoAuth during account registration",
                }, indent=2))

    def _write_oauth_app_folder(self, folder: Path, app: OAuthApp) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "record.json").write_text(json.dumps({
            **app.to_dict(),
            "client_id_full": app.client_id,
        }, indent=2))
        (folder / "provenance.json").write_text(
            json.dumps([p.to_dict() for p in app.provenance], indent=2)
        )
        if app.client_secret:
            (folder / "client_secret.txt").write_text(app.client_secret)
        if app.redirect_uris:
            (folder / "redirect_uris.txt").write_text(
                "\n".join(sorted(app.redirect_uris)) + "\n"
            )

    def _write_image_folder(self, folder: Path, url: str,
                            analysis: "image_analyzer.ImageAnalysis") -> None:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "metadata.json").write_text(
            json.dumps({"source_url": url, **analysis.to_dict()}, indent=2),
        )
        # Copy original bytes so the user has everything next to the metadata
        if analysis.file_path and Path(analysis.file_path).exists():
            try:
                dest = folder / Path(analysis.file_path).name
                if not dest.exists():
                    shutil.copy2(analysis.file_path, dest)
            except Exception:
                pass

    def _write_host_folder(self, folder: Path, host: HostRecord) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "record.json").write_text(json.dumps(host.to_dict(), indent=2))
        (folder / "provenance.json").write_text(
            json.dumps([p.to_dict() for p in host.provenance], indent=2)
        )
        if host.related_urls:
            (folder / "discovered_urls.txt").write_text(
                "\n".join(sorted(host.related_urls)) + "\n"
            )

    def _write_secret_folder(self, folder: Path, sec: SecretRecord) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "value.txt").write_text(sec.value)
        (folder / "metadata.json").write_text(json.dumps({
            **sec.to_dict(),
            "provenance": [p.to_dict() for p in sec.provenance],
        }, indent=2))

    def _render_notes(self) -> str:
        lines = ["# Enrichment summary", ""]
        s = self.result.summary()
        lines.append(f"- Bodies processed: {s['bodies_processed']} "
                     f"(skipped: {s['bodies_skipped']})")
        lines.append(f"- Users: {s['users']}  Hosts: {s['hosts']}  "
                     f"Secrets: {s['secrets']}")
        lines.append(f"- Unvisited URLs: {s['unvisited_urls']}  "
                     f"Paths: {s['paths']}")
        lines.append("")
        if self.result.users:
            lines.append("## Top users (by enrichment score)")
            top = sorted(self.result.users.values(), key=lambda u: -u.score)[:20]
            for u in top:
                emails = ", ".join(sorted(u.emails)[:3]) or "—"
                names = ", ".join(sorted(u.usernames)[:3]) or "—"
                lines.append(f"- **{u.canonical_id}** (score {u.score}) "
                             f"emails=`{emails}` usernames=`{names}`")
            lines.append("")
        if self.result.secrets:
            lines.append("## Secrets discovered")
            for sec in sorted(self.result.secrets.values(),
                              key=lambda x: -x.entropy)[:30]:
                lines.append(f"- `{sec.type_hint}` — entropy {sec.entropy:.1f} — "
                             f"{sec.value[:60]}{'…' if len(sec.value) > 60 else ''}")
            lines.append("")
        if self.result.hosts:
            lines.append(f"## Hosts ({len(self.result.hosts)})")
            for h in sorted(self.result.hosts.values(),
                            key=lambda x: x.hostname)[:40]:
                ips = f" [{', '.join(sorted(h.ips))}]" if h.ips else ""
                lines.append(f"- `{h.hostname}`{ips} — "
                             f"{len(h.related_urls)} URLs")
            lines.append("")
        return "\n".join(lines)
