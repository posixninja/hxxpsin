"""
idor_probe.py — Two-account cross-tenant IDOR / BOLA exploiter.

The pre-existing `--auth-a` / `--auth-b` flags in main.py were never wired
to any module. The Verifier's IDOR probe only enumerated IDs within a single
auth session — it had no way to detect "user A can read user B's resources"
which is the canonical BOLA bug pattern (OWASP API #1).

This module:
  1. Provisions two distinct accounts (from explicit auth flags or via two
     AutoAuth runs)
  2. For every endpoint that contains a numeric ID, UUID, or email in the
     URL path or body, fetches the resource as account A then account B
  3. Marks BOLA confirmed when both responses are 2xx, the bodies differ,
     and at least one body contains user-identifying tokens (email,
     username, or numeric id) belonging to a specific account
  4. Also runs an ID-swap pass: fetch A's resource using A's credentials,
     then fetch the SAME URL using B's credentials. Same confirmation logic.

Pipeline position: after active-scan, before desync.
Always-on when both auth states are available; skipped otherwise.
"""

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

import codec


# Path patterns that suggest a per-tenant resource — these are the highest-value
# IDOR test targets because the URL itself names the resource owner.
_NUMERIC_ID_RE = re.compile(r"/(\d{1,8})(?:/|$|\?)")
_UUID_RE = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)", re.I)
_EMAIL_RE = re.compile(r"/([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})(?:/|$|\?)", re.I)

# Body fields that suggest the response is per-user data (so cross-account
# access proves BOLA). Used as the "identity token" check.
_USER_FIELD_RE = re.compile(
    r'"(?:email|mail|username|userPrincipalName|userId|user_id|userid|uid|sub|'
    r'id|name|nickname|login|owner|customer|account|tenantId|orgId)"'
    r'\s*:\s*"?([^",}\s]{1,80})',
    re.IGNORECASE,
)

# Auth-header names commonly used to carry a JWT or API token. We check all
# of these when decoding identity claims, since not every framework uses
# the standard `Authorization: Bearer ...` shape.
_AUTH_HEADER_NAMES = (
    "authorization", "x-auth-token", "x-access-token", "x-api-token",
    "x-id-token", "x-session-token", "x-jwt", "auth-token",
)


def _encoded_id_segments(url: str) -> list[tuple[str, str, str]]:
    """Find URL path segments whose contents decode to plausibly-mutatable
    identifiers (e.g. base64('user42') → 'dXNlcjQy'). Returns a list of
    (original_segment, scheme, decoded_text) tuples for the encoded-ID swap
    pass. Skips segments already handled by _NUMERIC_ID_RE / _UUID_RE /
    _EMAIL_RE."""
    path = urlparse(url).path
    out: list[tuple[str, str, str]] = []
    for seg in path.strip("/").split("/"):
        if not seg or len(seg) < 8:
            continue
        # Already handled by other passes
        if seg.isdigit():
            continue
        if _UUID_RE.search("/" + seg + "/"):
            continue
        if "@" in seg:
            continue

        ranked = codec.detect(seg)
        if not ranked or ranked[0][1] < 0.75:
            continue
        for scheme, _conf in ranked[:2]:
            if scheme == "jwt":
                continue  # JWTs in URL paths are rare; not worth the noise
            try:
                decoded = codec.decode(seg, scheme)
            except Exception:
                continue
            text = decoded.decode("utf-8", "replace") if isinstance(decoded, bytes) else decoded
            if not text or text == seg:
                continue
            if len(text) > 200 or not text.isprintable():
                continue
            out.append((seg, scheme, text))
            break
    return out


def _mutate_decoded_id(text: str) -> list[str]:
    """Generate a small set of ID-mutation candidates for `text` decoded
    from an encoded URL segment. Returns up to 5 distinct candidates."""
    cands: list[str] = []
    seen: set[str] = {text}
    if text.isdigit():
        n = int(text)
        # Interleave small deltas with canonical low IDs so the 5-candidate
        # cap doesn't crowd out the seeded-admin probes.
        for delta in (1, -1, 10):
            v = n + delta
            if v >= 0 and str(v) not in seen:
                cands.append(str(v))
                seen.add(str(v))
        for canon in ("1", "2", "0"):
            if canon not in seen:
                cands.append(canon)
                seen.add(canon)
    else:
        # Increment any trailing digits in the decoded text
        m = re.search(r"(\d+)$", text)
        if m:
            mutated = text[:m.start()] + str(int(m.group(1)) + 1)
            if mutated not in seen:
                cands.append(mutated)
                seen.add(mutated)
        # Substitute the last character — catches lexicographic ID schemes
        if text:
            sub = text[:-1] + ("A" if text[-1] != "A" else "B")
            if sub not in seen:
                cands.append(sub)
    return cands[:5]


@dataclass
class Account:
    """One harvested auth session — cookies + Authorization header + the
    identity tokens (email, username, id) used to recognize this account's
    own data in API responses."""
    label: str
    headers: dict[str, str] = field(default_factory=dict)
    email: str = ""
    username: str = ""
    user_id: str = ""

    @property
    def identity_tokens(self) -> list[str]:
        return [t.lower() for t in (self.email, self.username, self.user_id) if t]


@dataclass
class IDORFinding:
    method: str
    url: str
    test_kind: str           # "cross_account_read" | "id_swap"
    verdict: str             # "confirmed" | "likely"
    confidence: float        # 0.0–1.0
    evidence: str
    response_a: str = ""     # truncated
    response_b: str = ""     # truncated

    def to_dict(self) -> dict:
        return {
            "method": self.method, "url": self.url, "test_kind": self.test_kind,
            "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence,
            "response_a": self.response_a[:200], "response_b": self.response_b[:200],
        }


@dataclass
class IDORResult:
    endpoints_tested: int = 0
    accounts_provisioned: int = 0
    findings: list[IDORFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[IDORFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def likely(self) -> list[IDORFinding]:
        return [f for f in self.findings if f.verdict == "likely"]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "accounts_provisioned": self.accounts_provisioned,
            "confirmed": len(self.confirmed),
            "likely": len(self.likely),
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


class IDORProbe:
    """Cross-account IDOR / BOLA exploiter. Tests the three canonical patterns:
      1. cross_account_read — same URL fetched with two different auths returns
         different per-user data → no per-tenant authorization
      2. id_swap — account A logged in tries to fetch a resource ID that A's
         baseline shows belongs to B → access succeeded → BOLA
    """

    def __init__(
        self,
        timeout: float = 8.0,
        max_endpoints: int = 50,
    ):
        self.timeout = timeout
        self.max_endpoints = max_endpoints

    # ------------------------------------------------------------------
    # Account provisioning
    # ------------------------------------------------------------------

    # localStorage / sessionStorage key names that commonly hold an auth token.
    # Covers Auth0, Cognito, Firebase, MSAL, Clerk, Supabase, custom apps.
    _STORAGE_TOKEN_KEYS = (
        "token", "auth_token", "authtoken", "access_token", "accesstoken",
        "id_token", "idtoken", "jwt", "bearer", "bearertoken",
        "sessiontoken", "session_token", "apitoken", "api_token",
        "authorization",
    )

    @classmethod
    def load_account_from_storage_state(cls, path: str, label: str) -> Optional[Account]:
        """Load a Playwright storage_state JSON and extract auth headers.
        Tries localStorage AND sessionStorage; checks a broad list of key
        names so it works on any framework, not just one."""
        try:
            data = json.loads(open(path).read())
        except Exception:
            return None
        headers: dict[str, str] = {}
        cookies = data.get("cookies", [])
        if cookies:
            headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        for origin in data.get("origins", []):
            for storage_key in ("localStorage", "sessionStorage"):
                for entry in origin.get(storage_key, []):
                    name_lower = entry.get("name", "").lower().replace("-", "").replace("_", "")
                    value = entry.get("value", "")
                    if not value:
                        continue
                    # Match against token key names (also stripped of separators)
                    if any(k.replace("_", "") == name_lower for k in cls._STORAGE_TOKEN_KEYS):
                        # If it already includes a scheme prefix (e.g. "Bearer ..."), keep as-is
                        if value.lower().startswith(("bearer ", "token ")):
                            headers["Authorization"] = value
                        else:
                            headers["Authorization"] = f"Bearer {value}"
                        break
                if "Authorization" in headers:
                    break
            if "Authorization" in headers:
                break
        if not headers:
            return None
        return Account(label=label, headers=headers)

    @staticmethod
    def account_from_auto_auth(session, label: str) -> Optional[Account]:
        """Build an Account from an AutoAuth.AuthSession (already harvested)."""
        if not session or not session.has_auth:
            return None
        return Account(
            label=label,
            headers=session.to_auth_headers(),
            email=getattr(session.credentials, "email", ""),
            username=getattr(session.credentials, "username", ""),
        )

    # ------------------------------------------------------------------
    # Identity hydration — figure out what token(s) identify each account
    # in API responses (id, email, username) by hitting common /me endpoints
    # ------------------------------------------------------------------

    # Framework-agnostic /me-style endpoint candidates — REST, OAuth/OIDC,
    # GraphQL-over-REST, Spring, Django REST, Rails, FastAPI, Cognito, Auth0,
    # tRPC, and common SPA conventions. Order is by typical frequency.
    _ME_PROBE_PATHS = (
        "/api/me", "/me", "/api/v1/me", "/api/v2/me",
        "/api/profile", "/profile", "/api/account", "/account",
        "/api/users/me", "/users/me", "/api/v1/users/me",
        "/api/user", "/api/v1/user", "/api/current-user", "/api/currentuser",
        "/api/auth/user", "/api/auth/me", "/api/auth/profile",
        "/api/session", "/api/whoami", "/whoami",
        "/userinfo", "/oauth/userinfo", "/connect/userinfo",  # OIDC
        "/rest/user/whoami", "/rest/me", "/rest/user/me",     # Juice Shop & similar
        "/identity/api/v2/user/dashboard",                     # crAPI
        "/api/v2.0/users/current",                             # Harbor
        "/api/v3/user", "/api/v4/user",                        # GitLab-style
        "/user", "/users/current",
    )

    # GraphQL identity queries — many SPAs prefer this over REST /me
    _GRAPHQL_IDENTITY_QUERY = (
        '{"query":"query { viewer { id email username name } }"}',
        '{"query":"query { me { id email username name } }"}',
        '{"query":"query { currentUser { id email username name } }"}',
    )
    _GRAPHQL_PROBE_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")

    async def hydrate_identity(self, client: httpx.AsyncClient, target: str, account: Account) -> None:
        """Identify this account's email/username/id so we can recognize its
        data in API responses. Three strategies, fastest first:
          1. Decode any Bearer JWT in the headers — claims often have it
          2. Probe REST /me-style endpoints (framework-agnostic list)
          3. Try GraphQL identity queries (viewer / me / currentUser)
        """
        if account.identity_tokens:
            return

        # ── Strategy 1: JWT claim extraction (zero HTTP calls) ──────────
        self._extract_from_jwt(account)
        if account.identity_tokens:
            return

        # ── Strategy 2: REST /me probes ─────────────────────────────────
        for path in self._ME_PROBE_PATHS:
            url = target.rstrip("/") + path
            try:
                r = await client.get(url, headers=account.headers, timeout=self.timeout)
                if r.status_code != 200 or not r.content:
                    continue
                try:
                    data = r.json()
                except Exception:
                    continue
                self._extract_identity(data, account)
                if account.identity_tokens:
                    return
            except httpx.HTTPError:
                continue

        # ── Strategy 3: GraphQL identity queries ────────────────────────
        for gql_path in self._GRAPHQL_PROBE_PATHS:
            url = target.rstrip("/") + gql_path
            for query in self._GRAPHQL_IDENTITY_QUERY:
                try:
                    r = await client.post(
                        url, headers={**account.headers, "Content-Type": "application/json"},
                        content=query, timeout=self.timeout,
                    )
                    if r.status_code != 200:
                        continue
                    try:
                        data = r.json()
                    except Exception:
                        continue
                    # GraphQL responses nest under data.viewer / data.me / etc.
                    self._extract_identity(data, account)
                    if account.identity_tokens:
                        return
                except httpx.HTTPError:
                    continue

    @staticmethod
    def _extract_from_jwt(account: Account) -> None:
        """Decode any JWT we find in the account's headers and pull identity
        claims from the payload. Standard claims: sub, email, preferred_username,
        name. Many frameworks use non-standard auth headers (X-Auth-Token etc.),
        so we check all common variants."""
        # Find a token in any of the known auth-header positions
        token: Optional[str] = None
        # Build a case-insensitive lookup of the account's headers
        headers_lower = {k.lower(): v for k, v in account.headers.items()}
        for header_name in _AUTH_HEADER_NAMES:
            v = headers_lower.get(header_name)
            if not v:
                continue
            # "Bearer eyJ..." or just "eyJ..." — handle both
            candidate = v.split(None, 1)[1].strip() if v.lower().startswith("bearer ") else v.strip()
            # Basic JWT shape check: three dot-separated base64 segments
            if candidate.count(".") == 2 and candidate.startswith("eyJ"):
                token = candidate
                break
        if not token:
            return
        parts = token.split(".")
        if len(parts) != 3:
            return
        # Base64url-decode the payload (segment 1)
        payload_b64 = parts[1]
        # Pad to a multiple of 4
        padding = (-len(payload_b64)) % 4
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
            claims = json.loads(payload_bytes)
        except Exception:
            return
        if not isinstance(claims, dict):
            return
        # Standard JWT identity claims (RFC 7519 + OIDC)
        for key in ("email",):
            v = claims.get(key)
            if isinstance(v, str) and "@" in v:
                account.email = v
                break
        for key in ("preferred_username", "username", "name", "nickname", "login"):
            v = claims.get(key)
            if isinstance(v, str) and v and not account.username:
                account.username = v
                break
        for key in ("sub", "userId", "user_id", "uid", "id"):
            v = claims.get(key)
            if v not in (None, "") and not account.user_id:
                account.user_id = str(v)
                break
        # Some apps nest user data under "data" or "user"
        for nested_key in ("data", "user", "userinfo"):
            nested = claims.get(nested_key)
            if isinstance(nested, dict):
                IDORProbe._extract_identity(nested, account)

    @staticmethod
    def _extract_identity(data, account: Account, depth: int = 0) -> None:
        if depth > 4 or data is None:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                kl = k.lower()
                if isinstance(v, str) and v:
                    if kl in ("email",) and not account.email:
                        account.email = v
                    elif kl in ("username", "name", "login") and not account.username:
                        account.username = v
                    elif kl in ("id", "userid", "user_id") and not account.user_id:
                        account.user_id = str(v)
                elif isinstance(v, (int,)) and kl in ("id", "userid", "user_id") and not account.user_id:
                    account.user_id = str(v)
                elif isinstance(v, (dict, list)):
                    IDORProbe._extract_identity(v, account, depth + 1)
        elif isinstance(data, list):
            for item in data[:10]:
                IDORProbe._extract_identity(item, account, depth + 1)

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_per_tenant(finding) -> bool:
        """True if the URL or body suggests a per-user resource — these are
        the high-value BOLA test targets."""
        url = finding.url
        if _NUMERIC_ID_RE.search(url) or _UUID_RE.search(url) or _EMAIL_RE.search(url):
            return True
        # Body shape that names a resource owner
        if finding.body and re.search(r'"(?:userId|user_id|userid|owner|customer|email)"', finding.body, re.I):
            return True
        return False

    def _select_targets(self, classifier_findings) -> list:
        """Prioritize per-tenant-resource endpoints; cap at max_endpoints."""
        from classifier import Cat
        priority: list = []
        secondary: list = []
        for f in classifier_findings:
            if f.method == "DELETE":  # skip destructive verbs
                continue
            if self._looks_per_tenant(f):
                priority.append(f)
            elif any(c in f.categories for c in (Cat.IDOR, Cat.BFLA, Cat.ADMIN, Cat.AUTH)):
                secondary.append(f)
        priority.sort(key=lambda f: -getattr(f, "score", 0))
        secondary.sort(key=lambda f: -getattr(f, "score", 0))
        return (priority + secondary)[:self.max_endpoints]

    # ------------------------------------------------------------------
    # Probe orchestration
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        account_a: Optional[Account],
        account_b: Optional[Account],
        classifier_findings,
    ) -> IDORResult:
        result = IDORResult()
        if not (account_a and account_b):
            result.notes.append("skipped: need two distinct accounts (--auth-a/--auth-b or --auto-auth)")
            return result
        if account_a.headers == account_b.headers:
            result.notes.append("skipped: two accounts have identical auth headers (provisioning failed?)")
            return result
        result.accounts_provisioned = 2

        targets = self._select_targets(classifier_findings)
        result.endpoints_tested = len(targets)
        if not targets:
            result.notes.append("skipped: no per-tenant-resource endpoints found")
            return result

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout,
            headers={"User-Agent": "hxxpsin-idor/1.0", "Accept": "application/json"},
        ) as client:
            # Hydrate identity tokens for both accounts
            await self.hydrate_identity(client, target, account_a)
            await self.hydrate_identity(client, target, account_b)
            if account_a.identity_tokens:
                result.notes.append(f"account A identity: {account_a.identity_tokens}")
            if account_b.identity_tokens:
                result.notes.append(f"account B identity: {account_b.identity_tokens}")

            tasks = [self._test_endpoint(client, account_a, account_b, f) for f in targets]
            findings_lists = await asyncio.gather(*tasks, return_exceptions=True)

        for item in findings_lists:
            if isinstance(item, list):
                result.findings.extend(item)
        return result

    # Canonical "first user / admin" IDs to probe. Most seeded apps put
    # admin at id=1 and early users at 2-3. Generic, not app-specific.
    _CANONICAL_LOW_IDS = ("1", "2", "3")

    async def _test_endpoint(
        self, client: httpx.AsyncClient,
        a: Account, b: Account, finding,
    ) -> list[IDORFinding]:
        """Per endpoint: anon-baseline + cross-account-read, plus ID-swap
        variants when the URL has a numeric ID. Anon baseline lets us promote
        'likely' to 'confirmed' when an unauthed request gets 4xx but A still
        gets data — a textbook authorization bypass."""
        out: list[IDORFinding] = []
        method = finding.method.upper()
        if method not in ("GET", "POST", "PUT", "PATCH"):
            return out

        # Anon baseline — fetch with no auth headers. Used by _compare to
        # distinguish public-by-design from per-user-bypassed-auth.
        anon_acc = Account(label="anon", headers={})

        # ── Test 1: cross-account-read — same URL, two auths + anon ──────
        try:
            ra = await self._fetch(client, method, finding.url, a, finding.body)
            rb = await self._fetch(client, method, finding.url, b, finding.body)
            r_anon = await self._fetch(client, method, finding.url, anon_acc, finding.body)
            f1 = self._compare(method, finding.url, "cross_account_read", a, b, ra, rb, r_anon)
            if f1:
                out.append(f1)
        except Exception:
            pass

        # ── Test 2: ID-swap — use account A's HYDRATED user_id as origin
        # rather than parsing the URL. Falls back to URL parsing only if A
        # has no hydrated ID. Probes A's own ID, B's hydrated ID, and the
        # canonical low IDs (1/2/3) since those usually belong to admin /
        # early users in seeded apps.
        m = _NUMERIC_ID_RE.search(finding.url)
        if m:
            original_id = m.group(1)
            own_id = a.user_id or original_id     # prefer hydrated identity
            other_id = b.user_id                  # the explicit "victim" ID
            target_ids: list[str] = []
            for cand in [other_id, *self._CANONICAL_LOW_IDS,
                          str(int(own_id) + 1) if own_id.isdigit() else None]:
                if cand and cand != original_id and cand not in target_ids:
                    target_ids.append(cand)
            for target_id in target_ids[:5]:
                try:
                    swapped_url = finding.url.replace(
                        f"/{original_id}", f"/{target_id}", 1,
                    )
                    ra_orig = await self._fetch(client, method, finding.url, a, finding.body)
                    ra_swap = await self._fetch(client, method, swapped_url, a, finding.body)
                    r_anon = await self._fetch(client, method, swapped_url, anon_acc, finding.body)
                    f2 = self._compare(method, swapped_url, "id_swap", a, a, ra_orig, ra_swap, r_anon)
                    if f2:
                        f2.evidence = (
                            f"ID-swap: {a.label} fetched neighbor ID {target_id} "
                            f"(own ID was {own_id}). " + f2.evidence
                        )
                        out.append(f2)
                        break  # stop at first confirmed/likely id-swap
                except Exception:
                    continue

        # ── Test 3: encoded ID swap — base64/hex IDs in URL path ─────────
        # Plain numeric/UUID/email IDs are handled above. If the URL still
        # has a segment that codec.detect identifies as encoded, decode it,
        # mutate the decoded form, re-encode, and run the same A-vs-A swap.
        # Bounded to 2 distinct encoded segments × 3 mutations = 6 extra
        # requests per endpoint, only when an encoded segment is actually
        # present.
        for orig_seg, scheme, decoded_text in _encoded_id_segments(finding.url)[:2]:
            mutated = False
            for mutated_decoded in _mutate_decoded_id(decoded_text)[:3]:
                try:
                    re_encoded = codec.encode(mutated_decoded, scheme)
                except Exception:
                    continue
                if re_encoded == orig_seg:
                    continue
                swapped_url = finding.url.replace(orig_seg, re_encoded, 1)
                try:
                    ra_orig = await self._fetch(client, method, finding.url, a, finding.body)
                    ra_swap = await self._fetch(client, method, swapped_url, a, finding.body)
                    r_anon = await self._fetch(client, method, swapped_url, anon_acc, finding.body)
                    f3 = self._compare(method, swapped_url, "encoded_id_swap",
                                       a, a, ra_orig, ra_swap, r_anon)
                    if f3:
                        f3.evidence = (
                            f"Encoded ID swap ({scheme}): segment "
                            f"{orig_seg!r} decoded to {decoded_text!r}; "
                            f"mutated to {mutated_decoded!r}; "
                            f"re-encoded as {re_encoded!r}. " + f3.evidence
                        )
                        out.append(f3)
                        mutated = True
                        break
                except Exception:
                    continue
            if mutated:
                break

        return out

    async def _fetch(
        self, client: httpx.AsyncClient, method: str, url: str,
        account: Account, body: Optional[str],
    ) -> Optional[httpx.Response]:
        try:
            if method == "GET":
                return await client.get(url, headers=account.headers)
            elif method in ("POST", "PUT", "PATCH"):
                kwargs = {"headers": account.headers}
                if body:
                    try:
                        kwargs["json"] = json.loads(body)
                    except Exception:
                        kwargs["content"] = body
                else:
                    kwargs["json"] = {}
                return await client.request(method, url, **kwargs)
        except httpx.HTTPError:
            return None
        return None

    def _compare(
        self, method: str, url: str, test_kind: str,
        a: Account, b: Account,
        ra: Optional[httpx.Response], rb: Optional[httpx.Response],
        r_anon: Optional[httpx.Response] = None,
    ) -> Optional[IDORFinding]:
        """Decide if a pair of responses indicates BOLA. Three confirmation
        paths in priority order:
          1. anon baseline = 4xx AND A returned 2xx → access-control bypass
          2. body of A (or B) contains the OTHER account's identity tokens
          3. fallback heuristic: bodies differ → 'likely'."""
        if ra is None or rb is None:
            return None
        if not (200 <= ra.status_code < 300 and 200 <= rb.status_code < 300):
            return None
        body_a = (ra.text or "")[:5000]
        body_b = (rb.text or "")[:5000]
        if not body_a or not body_b:
            return None

        anon_status = r_anon.status_code if r_anon is not None else None
        anon_blocked = anon_status is not None and 400 <= anon_status < 500

        # PATH 1 — Access-control bypass via anon baseline.
        # If anon would be 401/403 but A successfully reads the resource, that
        # IS the IDOR — regardless of whether B's body matches A's. (Example:
        # /rest/basket/2 returns the same content for A as for B because B
        # legitimately owns it; A is bypassing access control to read it.)
        if anon_blocked:
            evidence = (
                f"Authorization bypass confirmed: anonymous request returned "
                f"{anon_status} but {a.label} (id={a.user_id or '?'}) successfully "
                f"fetched the resource. Body length {len(body_a)} bytes."
            )
            # If A's body matches what the legitimate owner B sees, we have
            # extra-strong evidence A is reading B's data via IDOR.
            if test_kind == "cross_account_read" and body_a == body_b:
                evidence += (
                    f" A's response is byte-identical to B's — A is reading "
                    f"B's resource (same content as the legitimate owner sees)."
                )
            return IDORFinding(
                method=method, url=url, test_kind=test_kind,
                verdict="confirmed", confidence=0.95,
                evidence=evidence,
                response_a=body_a[:200], response_b=body_b[:200],
            )

        # Bodies effectively identical AND anon not blocked → genuinely public
        if body_a == body_b:
            return None
        # Length-similarity heuristic: nearly identical lengths with only
        # trivial per-request noise → skip
        if abs(len(body_a) - len(body_b)) < 5 and self._diff_is_trivial(body_a, body_b):
            return None

        # PATH 2 — Identity-token leak: each body contains the OTHER account's
        # identity. Strongest BOLA signal short of access-control bypass.
        b_in_a = any(t and t in body_a.lower() for t in b.identity_tokens) if b.identity_tokens else False
        a_in_b = any(t and t in body_b.lower() for t in a.identity_tokens) if a.identity_tokens else False
        if b_in_a or a_in_b:
            evidence = f"BOLA confirmed: response body contains the OTHER account's identity tokens."
            if b_in_a:
                evidence += f" Account A's response leaks B's tokens: {[t for t in b.identity_tokens if t in body_a.lower()][:3]}"
            if a_in_b:
                evidence += f" Account B's response leaks A's tokens: {[t for t in a.identity_tokens if t in body_b.lower()][:3]}"
            return IDORFinding(
                method=method, url=url, test_kind=test_kind,
                verdict="confirmed", confidence=0.92,
                evidence=evidence,
                response_a=body_a[:200], response_b=body_b[:200],
            )

        # PATH 3 — Fallback: bodies differ but no anon-block + no token leak.
        # Tenant-scoped behaviour but unproven cross-account access.
        evidence = (
            f"Same URL returned distinct 2xx bodies for A vs B "
            f"(len {len(body_a)} vs {len(body_b)}). "
            f"Anon baseline: {anon_status if anon_status is not None else 'unknown'}. "
            "No identity-token confirmation — manual review needed."
        )
        return IDORFinding(
            method=method, url=url, test_kind=test_kind,
            verdict="likely", confidence=0.55,
            evidence=evidence,
            response_a=body_a[:200], response_b=body_b[:200],
        )

    @staticmethod
    def _diff_is_trivial(a: str, b: str) -> bool:
        """True if the two bodies differ only in obvious per-request noise
        (timestamps, request IDs). Heuristic: strip JWT-like and timestamp-like
        tokens and compare."""
        norm = lambda s: re.sub(r"\d{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "X", s)
        return norm(a) == norm(b)
