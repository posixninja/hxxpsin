"""
auto_auth.py — Automatic account registration + login.

Provisions fresh credentials on the target by:
  1. Discovering register + login endpoints from classifier findings, JS routes,
     and a known-path wordlist.
  2. Trying multiple JSON body shapes (username/email/password variants) until
     one returns a success status.
  3. Extracting auth token from response body or cookies.

The harvested token is fed back into verifier + active_scanner via auth_headers,
so all downstream probes run authenticated.

Pipeline position: after classifier, before verifier.
Always-on (no flag) — registers a unique account each run.
"""

import asyncio
import html as html_module
import json
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx


# Common register endpoint paths
_REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/sign_up",
    "/api/register", "/api/signup", "/api/sign-up",
    "/api/auth/register", "/api/auth/signup",
    "/api/v1/register", "/api/v1/signup", "/api/v1/users",
    "/api/v2/register", "/api/v2/users",
    "/users/register", "/users/signup", "/users/v1/register", "/users/v2/register",
    "/auth/register", "/auth/signup",
    "/account/create", "/accounts", "/api/accounts",
    "/api/users", "/api/Users",
    "/identity/api/auth/signup",
    "/rest/user/register",
]

# Common login endpoint paths
_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/sign_in",
    "/api/login", "/api/signin",
    "/api/auth/login", "/api/auth/signin",
    "/api/v1/login", "/api/v1/auth/login",
    "/api/v2/login",
    "/users/login", "/users/v1/login", "/users/v2/login",
    "/auth/login", "/auth/signin", "/auth/token",
    "/oauth/token", "/api/oauth/token",
    "/api/sessions", "/sessions",
    "/identity/api/auth/login",
    "/rest/user/login",
]

# Path keywords that signal an auth endpoint (used to score JS-discovered routes)
_AUTH_KEYWORD_RE = re.compile(
    r"/(login|signin|signup|register|account/create|sessions?|auth/(login|signin|signup|register|token))($|/|\?)",
    re.IGNORECASE,
)

# Token field names to search in JSON response body (recursive)
_TOKEN_KEYS = (
    "token", "access_token", "auth_token", "jwt", "id_token",
    "bearerToken", "bearer_token", "sessionToken", "session_token",
    "authentication", "auth",
)

_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")

# Regexes for scraping HTML <form> + <input> shapes from candidate auth pages.
# We use regex (not an HTML parser) to avoid a new dep — scope is bounded.
_FORM_BLOCK_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b([^>]*?)/?>", re.IGNORECASE)
_ATTR_RE = re.compile(
    r'(\w[\w\-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',
    re.IGNORECASE,
)


def _parse_attrs(s: str) -> dict[str, str]:
    """Pull HTML attributes out of an element's opening-tag attribute string."""
    attrs: dict[str, str] = {}
    for m in _ATTR_RE.finditer(s):
        name = m.group(1).lower()
        value = m.group(2) or m.group(3) or m.group(4) or ""
        attrs[name] = html_module.unescape(value)
    return attrs


@dataclass
class _FormShape:
    """A registration or login form scraped from rendered HTML.
    Carries the real action URL + the actual field names the server expects,
    so we don't have to brute-force body shapes."""
    page_url: str
    action_url: str
    method: str
    enctype: str
    fields: dict[str, str]
    field_names: list[str]
    password_count: int
    is_register: bool

# Mailhog/Mailpit/Mailcatcher API ports — used to grab verification OTPs and links
_MAIL_API_PORTS = (8025, 1080, 8026, 8030)

# Patterns for extracting verification artifacts from email bodies
_OTP_RE = re.compile(r"\b(\d{4,8})\b")
_VERIFY_LINK_RE = re.compile(r"https?://[^\s<>\"']+(?:verify|confirm|activate|otp|token)[^\s<>\"']*", re.IGNORECASE)


@dataclass
class Credentials:
    username: str
    password: str
    email: str

    def to_dict(self) -> dict:
        return {"username": self.username, "password": self.password, "email": self.email}


@dataclass
class AuthSession:
    """Result of a successful register + login flow."""
    credentials: Credentials
    token: Optional[str] = None
    cookies: dict[str, str] = field(default_factory=dict)
    register_url: str = ""
    register_status: int = 0
    register_shape: str = ""
    login_url: str = ""
    login_status: int = 0
    login_shape: str = ""
    register_succeeded: bool = False
    login_succeeded: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def has_auth(self) -> bool:
        return bool(self.token or self.cookies)

    def to_auth_headers(self) -> dict[str, str]:
        """Convert harvested credentials into headers for downstream modules."""
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return headers

    def to_dict(self) -> dict:
        return {
            "credentials": self.credentials.to_dict(),
            "token": (self.token[:60] + "...") if self.token and len(self.token) > 60 else self.token,
            "cookies": list(self.cookies.keys()),
            "register": {
                "url": self.register_url, "status": self.register_status,
                "shape": self.register_shape, "succeeded": self.register_succeeded,
            },
            "login": {
                "url": self.login_url, "status": self.login_status,
                "shape": self.login_shape, "succeeded": self.login_succeeded,
            },
            "notes": self.notes,
        }


class AutoAuth:
    """
    Discovers register + login endpoints, provisions a fresh account, and
    harvests an auth token for downstream modules.
    """

    def __init__(self, target: str, timeout: float = 10.0,
                 email_domain: Optional[str] = None,
                 email: Optional[str] = None,
                 password: Optional[str] = None,
                 username: Optional[str] = None):
        """Initialise AutoAuth.

        - If `email`+`password` are both supplied, AutoAuth uses those creds
          directly and SKIPS registration (the operator already has an account).
          Login attempts run as normal.
        - Otherwise AutoAuth generates a random account and tries to register
          it. `email_domain` controls the random email's domain.
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        # `.test` is RFC 2606-reserved and rejected by many real-world signup
        # validators. Default to a registrable .com that's plausibly disposable
        # (still won't pass validators that actually verify MX, but passes the
        # syntax + TLD-blocklist checks that 95% of sites use). Operator can
        # override with --auth-email-domain to point at a real inbox they
        # control (e.g. mailinator subdomain or a domain they own).
        self._email_domain = (email_domain or "hxxpsin-pentest.com").strip().lstrip("@")
        # If operator supplied real creds, use them and skip registration.
        if email and password:
            local_part = email.split("@", 1)[0] if "@" in email else email
            self._creds = Credentials(
                username=username or local_part,
                password=password,
                email=email,
            )
            self._skip_register = True
        else:
            self._creds = self._gen_credentials(self._email_domain, username=username)
            self._skip_register = False

    @staticmethod
    def _gen_credentials(email_domain: str = "hxxpsin-pentest.com",
                         username: Optional[str] = None) -> Credentials:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return Credentials(
            username=username or f"hxxpsin_{suffix}",
            password=f"Test{suffix}!1A",
            email=f"hxxpsin_{suffix}@{email_domain}",
        )

    @staticmethod
    def _gen_phone() -> str:
        """Random 10-digit phone for apps that require unique phone (crAPI etc)."""
        return "1" + "".join(random.choices(string.digits, k=9))

    async def run(
        self,
        classifier_result=None,
        js_routes: Optional[list[str]] = None,
    ) -> AuthSession:
        """Discover endpoints, register, login, verify. Returns AuthSession."""
        session = AuthSession(credentials=self._creds)

        register_urls, login_urls = self._discover_endpoints(classifier_result, js_routes)

        # Don't auto-follow redirects — we need to inspect Location/Set-Cookie ourselves
        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=False,
            headers={"User-Agent": "hxxpsin/1.0", "Accept": "application/json"},
        ) as client:
            # ── HTML form discovery (precise) ──────────────────────────
            # Scrape rendered <form>s so we use the server's actual field names
            # and action URL, instead of brute-forcing 10 body shapes blindly.
            forms = await self._discover_forms(client, classifier_result, js_routes)
            for f in forms:
                tag = "register" if f.is_register else "login"
                session.notes.append(
                    f"discovered {tag} form: {f.method} {f.action_url} "
                    f"({f.password_count}pw, fields={f.field_names[:6]})"
                )

            # Promote discovered form actions to the front of the URL queues
            for f in forms:
                if f.is_register and f.action_url not in register_urls:
                    register_urls.insert(0, f.action_url)
                elif not f.is_register and f.action_url not in login_urls:
                    login_urls.insert(0, f.action_url)

            # ── Skip registration entirely when operator supplied creds ─────
            if self._skip_register:
                session.notes.append(
                    f"using operator-supplied credentials "
                    f"({self._creds.email or self._creds.username}) — "
                    f"skipping registration phase"
                )
            else:
                # ── Try each register form first (uses real field names) ────
                for f in [x for x in forms if x.is_register]:
                    r = await self._submit_form(client, f)
                    if r is None:
                        continue
                    if not _is_register_success(r, f.fields):
                        session.notes.append(f"register form {f.action_url} → {r.status_code} (rejected)")
                        continue
                    session.register_url = f.action_url
                    session.register_status = r.status_code
                    session.register_shape = f"html_form ({len(f.fields)}f)"
                    session.register_succeeded = True
                    reg_cookies = self._extract_auth_cookies_from_jar(client)
                    if reg_cookies:
                        session.cookies.update(reg_cookies)
                    session.notes.append(
                        f"registered via discovered form at {f.action_url} "
                        f"({len(reg_cookies)} cookie(s))"
                    )
                    break

                # ── Fallback: brute-force body shapes against known paths ───
                if not session.register_succeeded:
                    for url in register_urls:
                        ok, status, shape = await self._try_register(client, url)
                        if ok:
                            session.register_url = url
                            session.register_status = status
                            session.register_shape = shape
                            session.register_succeeded = True
                            # Pull any cookies set during register (some apps auto-login on register)
                            reg_cookies = self._extract_auth_cookies_from_jar(client)
                            if reg_cookies:
                                session.cookies.update(reg_cookies)
                                session.notes.append(f"registered at {url} ({shape}) — got {len(reg_cookies)} cookie(s)")
                            else:
                                session.notes.append(f"registered at {url} ({shape}) status={status}")
                            break
                        elif status:
                            session.notes.append(f"register {url} failed: status={status}")

                # ── Mailhog/Mailpit verification (if register succeeded) ────────
                # Some apps require email confirmation before login works.
                # Poll mailhog-like services for our credentials' email address.
                if session.register_succeeded:
                    otp, link = await self._check_mailbox(client)
                    if otp or link:
                        verified = await self._submit_email_verification(client, otp, link)
                        if verified:
                            session.notes.append(f"email-verified via mailhog ({verified})")

            # ── Try discovered login forms first ──────────────────────────
            for f in [x for x in forms if not x.is_register]:
                r = await self._submit_form(client, f)
                if r is None:
                    continue
                token = self._extract_token(r) if r.status_code in (200, 201) else None
                cookies = self._extract_auth_cookies(r)
                # 302/303 with auth cookie = legacy form login
                if r.status_code in (302, 303) and cookies:
                    location = r.headers.get("location", "").lower()
                    if "error" in location or "fail" in location:
                        cookies = {}
                if token or cookies:
                    jar_cookies = self._extract_auth_cookies_from_jar(client)
                    session.login_url = f.action_url
                    session.login_status = r.status_code
                    session.login_shape = f"html_form ({len(f.fields)}f)"
                    session.token = token
                    session.cookies = {**cookies, **jar_cookies}
                    session.login_succeeded = True
                    auth_kind = "token" if token else f"{len(session.cookies)} cookie(s)"
                    session.notes.append(
                        f"logged in via discovered form at {f.action_url} — {auth_kind}"
                    )
                    break

            # ── Fallback: brute-force body shapes against known login paths ──
            if not session.login_succeeded:
                for url in login_urls:
                    token, cookies, status, shape = await self._try_login(client, url)
                    # Only count login as succeeded if _try_login itself returned positive evidence
                    # (don't fall back on stale jar cookies from earlier requests)
                    if token or cookies:
                        # Merge with jar in case server set additional auth cookies via Set-Cookie
                        jar_cookies = self._extract_auth_cookies_from_jar(client)
                        session.login_url = url
                        session.login_status = status
                        session.login_shape = shape
                        session.token = token
                        session.cookies = {**cookies, **jar_cookies}
                        session.login_succeeded = True
                        auth_kind = "token" if token else f"{len(session.cookies)} cookie(s)"
                        session.notes.append(f"logged in at {url} ({shape}) — got {auth_kind}")
                        break
                    elif status:
                        session.notes.append(f"login {url} failed: status={status}")

            # ── Verify the harvested auth actually works ──────────────────
            if session.has_auth:
                verified = await self._verify_auth(client, session)
                if verified:
                    session.notes.append(f"verified: auth probe succeeded ({verified})")
                else:
                    session.notes.append("verified: auth probe found no signal — auth may be weak")

        return session

    async def _verify_auth(self, client: httpx.AsyncClient, session: AuthSession) -> Optional[str]:
        """Probe a /me / /profile / /account endpoint with the harvested auth.
        Returns evidence string if the response is auth-shaped, None otherwise."""
        headers = session.to_auth_headers()
        probe_paths = ["/api/me", "/me", "/api/v1/me", "/api/profile", "/profile",
                       "/api/account", "/account", "/api/users/me", "/users/me",
                       "/api/user", "/api/v1/user", "/api/v1/users/me",
                       "/identity/api/v2/user/dashboard",
                       "/rest/user/whoami", "/rest/admin/application-version"]
        for path in probe_paths:
            url = self.target + path
            try:
                r = await client.get(url, headers=headers)
                if r.status_code == 200 and len(r.content) > 20:
                    text = r.text[:1000].lower()
                    # Look for auth-context indicators in response
                    if any(sig in text for sig in (session.credentials.username.lower(),
                                                    session.credentials.email.lower(),
                                                    '"id"', '"role"', '"user"', '"email"', 'authenticated')):
                        return f"GET {path} → 200 with user-context body"
            except httpx.HTTPError:
                continue
        return None

    @staticmethod
    def _extract_auth_cookies_from_jar(client: httpx.AsyncClient) -> dict[str, str]:
        """Pull auth-shaped cookies from the client's accumulated cookie jar."""
        out: dict[str, str] = {}
        auth_re = re.compile(r"(token|jwt|session|auth|sid|sso|connect\.sid|jsessionid)", re.I)
        for cookie in client.cookies.jar:
            if auth_re.search(cookie.name):
                out[cookie.name] = cookie.value
        return out

    async def _check_mailbox(
        self, client: httpx.AsyncClient
    ) -> tuple[Optional[str], Optional[str]]:
        """Poll local mailhog/mailpit ports for an email to our address.
        Returns (otp_code, verification_link)."""
        host = urlparse(self.target).hostname or "localhost"
        for port in _MAIL_API_PORTS:
            mail_url = f"http://{host}:{port}/api/v2/messages"
            try:
                r = await client.get(mail_url, timeout=3.0)
                if r.status_code != 200:
                    continue
                data = r.json()
                items = data.get("items", []) if isinstance(data, dict) else data
                for msg in items[:20]:
                    body = self._extract_mail_body(msg)
                    if self._creds.email.lower() not in body.lower() and self._creds.email.lower() not in str(msg).lower():
                        continue
                    # OTP: 4-8 digits
                    otp_match = _OTP_RE.search(body)
                    otp = otp_match.group(1) if otp_match else None
                    # Verify link
                    link_match = _VERIFY_LINK_RE.search(body)
                    link = link_match.group(0) if link_match else None
                    if otp or link:
                        return otp, link
            except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                continue
        return None, None

    @staticmethod
    def _extract_mail_body(msg: dict) -> str:
        """Extract plain-text body from a mailhog/mailpit message dict (formats vary)."""
        if not isinstance(msg, dict):
            return ""
        # Mailhog format: {"Content": {"Body": "..."}}
        if "Content" in msg and isinstance(msg["Content"], dict):
            return msg["Content"].get("Body", "")
        # Mailpit format: {"Text": "..."} or {"HTML": "..."}
        return msg.get("Text", "") or msg.get("HTML", "") or msg.get("body", "")

    async def _submit_email_verification(
        self, client: httpx.AsyncClient,
        otp: Optional[str],
        link: Optional[str],
    ) -> Optional[str]:
        """Submit OTP to common verification endpoints, or follow the link."""
        # 1. Follow verification link if found
        if link:
            try:
                r = await client.get(link)
                if r.status_code in (200, 302, 303):
                    return f"link followed → {r.status_code}"
            except httpx.HTTPError:
                pass

        # 2. Try posting OTP to common verification endpoints
        if otp:
            verify_paths = [
                "/api/auth/verify-otp", "/api/v1/auth/verify",
                "/identity/api/auth/v3/check-otp",
                "/auth/verify", "/users/verify", "/users/v1/verify",
                "/api/verify-email", "/verify",
            ]
            shapes = [
                {"otp": otp, "email": self._creds.email},
                {"code": otp, "email": self._creds.email},
                {"token": otp, "email": self._creds.email},
                {"verification_code": otp, "email": self._creds.email},
            ]
            for path in verify_paths:
                url = self.target + path
                for body in shapes:
                    try:
                        r = await client.post(url, json=body)
                        if r.status_code in (200, 201, 204):
                            text = r.text[:300].lower()
                            if not any(e in text for e in ("error", "invalid", "expired", "not found")):
                                return f"OTP {otp} → POST {path} → {r.status_code}"
                    except httpx.HTTPError:
                        continue
        return None

    # ----------------------------------------------------------------------
    # HTML form discovery — scrape real forms before brute-forcing body shapes
    # ----------------------------------------------------------------------

    def _map_field_value(self, name: str, type_: str) -> Optional[str]:
        """Map an HTML input's name/type to a credential value.
        Returns None for unknown fields the caller should skip."""
        name_l = (name or "").lower()
        type_l = (type_ or "text").lower()
        c = self._creds
        if type_l == "password" or "pass" in name_l or "pwd" in name_l:
            return c.password
        if type_l == "email" or "email" in name_l or "mail" in name_l:
            return c.email
        if type_l == "tel" or any(s in name_l for s in ("phone", "mobile", "tel", "msisdn")):
            return self._gen_phone()
        if any(s in name_l for s in ("first", "given", "fname")):
            return "Hxxp"
        if any(s in name_l for s in ("last", "family", "surname", "lname")):
            return "Sin"
        if "captcha" in name_l:
            return ""  # leave blank — many test apps stub captcha
        if any(s in name_l for s in ("agree", "terms", "tos", "consent")):
            return "true"
        if "answer" in name_l or "security" in name_l:
            return c.username
        if any(s in name_l for s in ("user", "login", "handle", "account", "nick", "name", "identifier")):
            return c.username
        return None

    def _form_page_candidates(
        self,
        classifier_result,
        js_routes: Optional[list[str]],
    ) -> list[str]:
        """Pages likely to contain a register or login form. Capped to keep latency low."""
        seen: set[str] = set()
        urls: list[str] = []

        def add(u: str) -> None:
            if u not in seen:
                seen.add(u)
                urls.append(u)

        # Homepage often has the login form inline (or links the SPA shell)
        add(self.target + "/")

        # SPA route fragments — many JS apps render at /#/login or /login client-side
        for path in ("/login", "/signin", "/register", "/signup",
                     "/account/login", "/account/register",
                     "/users/sign_in", "/users/sign_up",
                     "/auth/login", "/auth/register",
                     "/#/login", "/#/register"):
            add(self.target + path)

        # Crawler-discovered URLs that look auth-shaped
        if classifier_result and hasattr(classifier_result, "request_findings"):
            for f in classifier_result.request_findings:
                if _AUTH_KEYWORD_RE.search(urlparse(f.url).path or ""):
                    add(f.url.split("?")[0])

        # JS-extracted routes
        if js_routes:
            for route in js_routes:
                full = urljoin(self.target + "/", route.lstrip("/"))
                if _AUTH_KEYWORD_RE.search(urlparse(full).path or ""):
                    add(full)

        return urls[:20]

    async def _discover_forms(
        self,
        client: httpx.AsyncClient,
        classifier_result,
        js_routes: Optional[list[str]],
    ) -> list[_FormShape]:
        """GET candidate pages, parse HTML <form>s with password inputs.
        Returns concrete submit-ready shapes (real action URL + correct field names)."""
        candidates = self._form_page_candidates(classifier_result, js_routes)
        forms: list[_FormShape] = []
        seen_actions: set[tuple[str, str]] = set()

        for page_url in candidates:
            try:
                r = await client.get(page_url, headers={"Accept": "text/html,*/*"})
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "").lower()
            if "html" not in ct:
                continue

            for fm in _FORM_BLOCK_RE.finditer(r.text):
                form_attrs = _parse_attrs(fm.group(1))
                inputs: list[tuple[str, str, str]] = []  # (name, type, default_value)
                for im in _INPUT_RE.finditer(fm.group(2)):
                    a = _parse_attrs(im.group(1))
                    name = a.get("name")
                    if not name:
                        continue
                    inputs.append((name, a.get("type", "text"), a.get("value", "")))

                pw_count = sum(1 for _, t, _ in inputs if t.lower() == "password")
                if pw_count < 1:
                    continue  # not an auth form

                action = form_attrs.get("action", "") or page_url
                action_url = urljoin(page_url, action)
                method = form_attrs.get("method", "POST").upper()
                enctype = form_attrs.get("enctype", "application/x-www-form-urlencoded").lower()

                fields: dict[str, str] = {}
                seen_pw = False
                for name, type_, default in inputs:
                    tl = type_.lower()
                    if tl == "submit" or tl == "button" or tl == "image":
                        continue
                    if tl == "hidden":
                        # Pass through hidden values verbatim — CSRF tokens, _method, etc.
                        if default:
                            fields[name] = default
                        continue
                    mapped = self._map_field_value(name, type_)
                    if mapped is None:
                        if default:
                            fields[name] = default
                        continue
                    # Two password fields → second one is "confirm"; both get the same value
                    if tl == "password" and seen_pw:
                        fields[name] = self._creds.password
                    else:
                        fields[name] = mapped
                    if tl == "password":
                        seen_pw = True

                action_l = action_url.lower()
                is_register = (
                    pw_count >= 2
                    or any(s in action_l for s in ("register", "signup", "sign-up", "sign_up", "create"))
                    or any(s in (page_url.lower()) for s in ("register", "signup", "sign-up"))
                )

                key = (action_url, method)
                if key in seen_actions:
                    continue
                seen_actions.add(key)
                forms.append(_FormShape(
                    page_url=page_url, action_url=action_url, method=method, enctype=enctype,
                    fields=fields, field_names=[n for n, _, _ in inputs],
                    password_count=pw_count, is_register=is_register,
                ))
        return forms

    async def _submit_form(
        self, client: httpx.AsyncClient, form: _FormShape,
    ) -> Optional[httpx.Response]:
        """Send a discovered form using its declared method + enctype."""
        body = dict(form.fields)
        try:
            if "json" in form.enctype:
                return await client.request(form.method, form.action_url, json=body)
            if "multipart" in form.enctype:
                files = {k: (None, v) for k, v in body.items()}
                return await client.request(form.method, form.action_url, files=files)
            # Default x-www-form-urlencoded
            return await client.request(form.method, form.action_url, data=body)
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

    # ----------------------------------------------------------------------
    # Endpoint discovery
    # ----------------------------------------------------------------------

    def _discover_endpoints(
        self,
        classifier_result,
        js_routes: Optional[list[str]],
    ) -> tuple[list[str], list[str]]:
        register: list[str] = []
        login: list[str] = []
        seen_reg: set[str] = set()
        seen_log: set[str] = set()

        def add(url: str) -> None:
            path = urlparse(url).path.lower()
            if any(rp in path for rp in ("/register", "/signup", "/sign-up", "/users/register",
                                          "/users/v1/register", "/users/v2/register", "/api/users",
                                          "/api/accounts", "/api/auth/signup", "/identity/api/auth/signup")):
                if url not in seen_reg:
                    seen_reg.add(url)
                    register.append(url)
            elif any(lp in path for lp in ("/login", "/signin", "/sign-in", "/sessions",
                                            "/auth/token", "/oauth/token")):
                if url not in seen_log:
                    seen_log.add(url)
                    login.append(url)

        # 1. Classifier findings
        if classifier_result and hasattr(classifier_result, "request_findings"):
            for f in classifier_result.request_findings:
                add(f.url)

        # 2. JS-discovered routes
        if js_routes:
            for route in js_routes:
                add(urljoin(self.target + "/", route.lstrip("/")))

        # 3. Probe known paths (always — these often aren't crawler-discovered)
        for path in _REGISTER_PATHS:
            url = self.target + path
            if url not in seen_reg:
                seen_reg.add(url)
                register.append(url)
        for path in _LOGIN_PATHS:
            url = self.target + path
            if url not in seen_log:
                seen_log.add(url)
                login.append(url)

        return register, login

    # ----------------------------------------------------------------------
    # Register attempts — try multiple body shapes
    # ----------------------------------------------------------------------

    def _register_shapes(self) -> list[tuple[str, dict]]:
        """Body shape variants. Each tuple: (label, body_dict)."""
        c = self._creds
        return [
            ("user_pass_email",       {"username": c.username, "password": c.password, "email": c.email}),
            ("email_pass",            {"email": c.email, "password": c.password}),
            ("user_pass",             {"username": c.username, "password": c.password}),
            ("name_email_pass",       {"name": c.username, "email": c.email, "password": c.password}),
            ("juiceshop",             {"email": c.email, "password": c.password, "passwordRepeat": c.password,
                                       "securityQuestion": {"id": 1, "question": "?", "answer": c.username},
                                       "securityAnswer": c.username}),
            ("crapi",                 {"name": c.username, "email": c.email, "number": self._gen_phone(),
                                       "password": c.password}),
            ("nested_user",           {"user": {"username": c.username, "email": c.email, "password": c.password}}),
            ("login_pass_email",      {"login": c.username, "password": c.password, "email": c.email}),
            ("first_last",            {"username": c.username, "password": c.password, "email": c.email,
                                       "first_name": "Hxxp", "last_name": "Sin"}),
            ("password_confirmation", {"username": c.username, "email": c.email,
                                       "password": c.password, "password_confirmation": c.password}),
        ]

    async def _try_register(self, client: httpx.AsyncClient, url: str) -> tuple[bool, int, str]:
        """Returns (ok, status, shape_label). Strict success requires:
          - 2xx response AND
          - response is JSON (not SPA HTML fallback) AND contains user-shaped fields, OR
          - 201 Created (regardless of body), OR
          - 302 redirect with auth-cookie set, OR
          - 409 Conflict (user exists, treat as success for our purpose)"""
        for shape_label, body in self._register_shapes():
            for encoding in ("json", "form"):
                try:
                    if encoding == "json":
                        r = await client.post(url, json=body)
                    else:
                        form = dict(body)
                        if "user" in form:
                            form.update(form.pop("user"))
                        if "password" in form:
                            form.setdefault("matchingPassword", form["password"])
                            form.setdefault("password_confirmation", form["password"])
                            form.setdefault("passwordRepeat", form["password"])
                        form.setdefault("agree", "agree")
                        form = {k: v for k, v in form.items() if not isinstance(v, (dict, list))}
                        r = await client.post(url, data=form)

                    if not _is_register_success(r, body):
                        continue
                    return True, r.status_code, f"{shape_label} ({encoding})"
                except (httpx.HTTPError, json.JSONDecodeError):
                    continue
        return False, 0, ""

    # ----------------------------------------------------------------------
    # Login attempts — try multiple body shapes
    # ----------------------------------------------------------------------

    def _login_shapes(self) -> list[tuple[str, dict]]:
        c = self._creds
        return [
            ("user_pass",       {"username": c.username, "password": c.password}),
            ("email_pass",      {"email": c.email, "password": c.password}),
            ("login_pass",      {"login": c.username, "password": c.password}),
            ("identifier_pass", {"identifier": c.email, "password": c.password}),
            ("nested_user",     {"user": {"username": c.username, "password": c.password}}),
            ("nested_user_email", {"user": {"email": c.email, "password": c.password}}),
            ("oauth_password",  {"grant_type": "password", "username": c.username,
                                  "password": c.password, "scope": "openid"}),
        ]

    async def _try_login(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[Optional[str], dict[str, str], int, str]:
        """Returns (token, cookies, status, shape_label).
        Tries JSON and form encoding, accepts both API tokens and session cookies."""
        for shape_label, body in self._login_shapes():
            for encoding in ("json", "form"):
                try:
                    flat_body = {k: v for k, v in body.items() if not isinstance(v, (dict, list))}
                    if "user" in body and isinstance(body["user"], dict):
                        flat_body.update(body["user"])
                    if encoding == "json":
                        r = await client.post(url, json=body)
                    else:
                        r = await client.post(url, data=flat_body or body)

                    if r.status_code in (200, 201):
                        token = self._extract_token(r)
                        cookies = self._extract_auth_cookies(r)
                        if token or cookies:
                            return token, cookies, r.status_code, f"{shape_label} ({encoding})"
                    # 302 redirect with Set-Cookie = legacy form-based auth success
                    if r.status_code in (302, 303):
                        location = r.headers.get("location", "").lower()
                        cookies = self._extract_auth_cookies(r)
                        # Don't follow redirects manually but check if it doesn't go to /login?error
                        if cookies and "error" not in location and "fail" not in location:
                            return None, cookies, r.status_code, f"{shape_label} ({encoding}, cookie-only)"
                except (httpx.HTTPError, json.JSONDecodeError):
                    continue
        return None, {}, 0, ""

    # ----------------------------------------------------------------------
    # Token extraction
    # ----------------------------------------------------------------------

    @staticmethod
    def _extract_token(r: httpx.Response) -> Optional[str]:
        """Recursively search response JSON for a token-shaped field."""
        # Authorization response header
        auth_hdr = r.headers.get("authorization", "")
        if auth_hdr.startswith("Bearer "):
            return auth_hdr.split(" ", 1)[1]

        # JSON body
        try:
            data = r.json()
        except (json.JSONDecodeError, ValueError):
            return None

        return _find_token_in_dict(data)

    @staticmethod
    def _extract_auth_cookies(r: httpx.Response) -> dict[str, str]:
        """Return cookies that look auth-related (token/jwt/session/auth in name)."""
        out: dict[str, str] = {}
        auth_re = re.compile(r"(token|jwt|session|auth|sid|sso|connect\.sid)", re.I)
        for k, v in r.cookies.items():
            if auth_re.search(k):
                out[k] = v
        return out


def _is_register_success(r: httpx.Response, sent_body: dict) -> bool:
    """Strict success heuristic for register responses."""
    # 201 Created — almost always real success
    if r.status_code == 201:
        return True
    # 409 Conflict — user already exists, treat as success
    if r.status_code == 409:
        return True
    # 302/303 with auth-cookie = legacy form-based register success
    if r.status_code in (302, 303):
        location = r.headers.get("location", "").lower()
        for cookie in r.cookies.items():
            if re.search(r"(token|jwt|session|auth|sid|sso|jsessionid)", cookie[0], re.I):
                if "error" not in location and "fail" not in location:
                    return True
        return False
    # 200 OK — only count if response is JSON-shaped with success indicators
    if r.status_code == 200:
        ct = r.headers.get("content-type", "").lower()
        if "json" not in ct:
            return False  # SPA HTML fallback — not a real API success
        try:
            data = r.json()
        except (json.JSONDecodeError, ValueError):
            return False
        text = json.dumps(data).lower()
        sent_email = sent_body.get("email", "").lower()
        sent_user = sent_body.get("username", "").lower() or sent_body.get("name", "").lower()
        # Strong positive: response echoes our email or username
        if sent_email and sent_email in text:
            return True
        if sent_user and sent_user in text:
            return True
        # Negative indicators — reject if any present
        negatives = ("error", "exception", '"missing"', '"required"', '"invalid"',
                     '"conflict"', "not found", "method not allowed",
                     "already exist", "duplicate", "forbidden", "denied")
        if any(n in text for n in negatives):
            return False
        # Generic positive: success/registered/created word + JSON 200 = trust it
        positives = ("success", "registered", "created", "welcome", "user", '"id"', '"id":')
        if any(p in text for p in positives):
            return True
    return False


def _find_token_in_dict(data, depth: int = 0) -> Optional[str]:
    """Recursively walk dict/list looking for a JWT-shaped or token-named string value."""
    if depth > 6:
        return None
    if isinstance(data, dict):
        # Direct token-named keys
        for k, v in data.items():
            if isinstance(v, str) and k.lower() in _TOKEN_KEYS:
                if _JWT_RE.match(v) or len(v) > 20:
                    return v
        # Recurse into nested dicts/lists
        for v in data.values():
            if isinstance(v, (dict, list)):
                t = _find_token_in_dict(v, depth + 1)
                if t:
                    return t
            elif isinstance(v, str) and _JWT_RE.match(v):
                return v
    elif isinstance(data, list):
        for item in data:
            t = _find_token_in_dict(item, depth + 1)
            if t:
                return t
    return None
