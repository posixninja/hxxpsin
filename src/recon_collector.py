"""
recon_collector.py — Stage 1 of the agentic solver pipeline.

Given a classifier Finding, this module sends a fixed, category-specific
set of probes and captures their raw responses. NO judgement is made here —
the output is purely factual: (label, request, response) triples that the
condenser stage will then summarize into evidence for/against the vuln.

Why deterministic: small LLMs hallucinate probe choices and judge their own
output. Pre-canned recipes (IDOR ID-swap, mass-assign field injection, SSRF
URL probes, etc.) send the *exact* requests a human pentester would send,
making the downstream stages judge a clean, predictable evidence set.

Categories covered:
  IDOR/BOLA      → numeric ID swap (+1, +10, +9999, malformed, anonymous)
  BFLA           → method/endpoint access toggle (anonymous, low-priv, high-priv)
  Admin/Internal → anonymous vs authenticated
  Mass Assign    → original body, body + privilege fields (role, isAdmin, plan)
  SSRF Surface   → URL-typed body params with 127.0.0.1, 169.254.169.254
  Injection      → quote/comment payloads in mutable params
  CORS           → Origin header reflection probe
  Open Redirect  → external-URL injection in obvious redirect params
  Race Condition → 5x parallel send of the same request
  (default)      → baseline + anonymous (always-safe minimum recon)

Hard safety bounds: every probe stays on the target host, never uses
write-amplifying methods we didn't see in the captured request, and caps
response capture at 8 KB per probe so the briefing prompt doesn't explode.
"""

import asyncio
import json
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

import codec

from classifier import Cat, Finding


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class ReconContext:
    """Optional scan-wide context threaded into recipes that need more than
    the bare Finding to plan probes (currently: OpenRedirectRecipe needs the
    OOB tunnel URL to mount real response-splitting tests instead of falling
    back to a fake canary)."""
    public_url: Optional[str] = None   # OOB tunnel public URL, e.g. https://abc.trycloudflare.com
    oob_token: Optional[str] = None    # short random token planted in callbacks


@dataclass
class ReconProbe:
    label: str                                 # human-readable, e.g. "anonymous", "id+1"
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    use_auth: bool = True                      # attach captured auth headers

    def to_dict(self) -> dict:
        return {"label": self.label, "method": self.method, "url": self.url,
                "headers": self.headers, "body": self.body,
                "use_auth": self.use_auth}


@dataclass
class ReconObservation:
    label: str
    method: str
    url: str
    request_body: Optional[str]
    request_headers_subset: dict[str, str]     # only interesting headers
    status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_truncated: bool = False
    response_size_bytes: int = 0
    elapsed_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "method": self.method, "url": self.url,
            "request_body": self.request_body,
            "request_headers": self.request_headers_subset,
            "status": self.status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "response_truncated": self.response_truncated,
            "response_size_bytes": self.response_size_bytes,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


@dataclass
class ReconBundle:
    finding_index: int
    finding_categories: list[str]
    recipe_name: str                           # which recipe produced these probes
    probes_sent: int = 0
    observations: list[ReconObservation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # recipe-emitted hints

    def to_dict(self) -> dict:
        return {
            "finding_index": self.finding_index,
            "finding_categories": self.finding_categories,
            "recipe_name": self.recipe_name,
            "probes_sent": self.probes_sent,
            "notes": self.notes,
            "observations": [o.to_dict() for o in self.observations],
        }


# ---------------------------------------------------------------------------
# Recipe interface
# ---------------------------------------------------------------------------

class ReconRecipe:
    name: str = "base"
    def applies(self, finding: Finding) -> bool:
        return False
    def probes(self, finding: Finding) -> list[ReconProbe]:
        return []
    def notes(self, finding: Finding) -> list[str]:
        return []


# ---------------------------------------------------------------------------
# Recipe: IDOR / BOLA — numeric ID swap in URL path
# ---------------------------------------------------------------------------

_NUMERIC_PATH_RE = re.compile(r"/(\d+)(?=/|$|\?)")


class IDORRecipe(ReconRecipe):
    name = "idor_url_id_swap"

    def applies(self, finding: Finding) -> bool:
        if not any(c in finding.categories for c in (Cat.IDOR, Cat.BFLA)):
            return False
        return bool(_NUMERIC_PATH_RE.search(urlparse(finding.url).path))

    def probes(self, finding: Finding) -> list[ReconProbe]:
        path = urlparse(finding.url).path
        ids_in_path = list(_NUMERIC_PATH_RE.finditer(path))
        if not ids_in_path:
            return []
        # Swap the LAST numeric segment (most often the object ID)
        last = ids_in_path[-1]
        original_id = int(last.group(1))
        # Generate adjacent and large variants; pick ones that don't collide
        candidates = [original_id + 1, original_id + 10, 9999, 0]
        seen = {original_id}
        swaps: list[int] = []
        for v in candidates:
            if v < 0 or v in seen:
                continue
            seen.add(v)
            swaps.append(v)

        def url_with_id(new_id) -> str:
            new_path = path[:last.start(1)] + str(new_id) + path[last.end(1):]
            parts = urlparse(finding.url)._replace(path=new_path)
            return urlunparse(parts)

        method = finding.method.upper()
        body = finding.body if method in ("POST", "PUT", "PATCH") else None

        out: list[ReconProbe] = [
            ReconProbe(label="baseline_auth", method=method, url=finding.url,
                       body=body, use_auth=True),
            ReconProbe(label="anonymous", method=method, url=finding.url,
                       body=body, use_auth=False),
        ]
        for v in swaps:
            out.append(ReconProbe(
                label=f"id_swap_to_{v}",
                method=method, url=url_with_id(v),
                body=body, use_auth=True,
            ))
        # Malformed ID — useful for distinguishing "not found" vs "forbidden"
        out.append(ReconProbe(
            label="id_swap_malformed",
            method=method, url=url_with_id("notanumber"),
            body=body, use_auth=True,
        ))
        return out

    def notes(self, finding: Finding) -> list[str]:
        return [
            "IDOR confirmation requires the response body to contain data "
            "belonging to a different user/resource than the authenticated "
            "principal — not merely a different HTTP status.",
            "Identical responses across baseline and ID-swap variants suggest "
            "the endpoint validates the ID before checking ownership (likely "
            "refuted); differing bodies that reveal another user's data "
            "suggest confirmed IDOR.",
        ]


# ---------------------------------------------------------------------------
# Recipe: Admin / Internal Exposure — anon vs authenticated comparison
# ---------------------------------------------------------------------------

class AdminRecipe(ReconRecipe):
    name = "admin_anon_vs_auth"

    def applies(self, finding: Finding) -> bool:
        return Cat.ADMIN in finding.categories

    def probes(self, finding: Finding) -> list[ReconProbe]:
        method = finding.method.upper()
        body = finding.body if method in ("POST", "PUT", "PATCH") else None
        return [
            ReconProbe(label="anonymous", method=method, url=finding.url,
                       body=body, use_auth=False),
            ReconProbe(label="authenticated", method=method, url=finding.url,
                       body=body, use_auth=True),
            # Test method confusion (HEAD often bypasses auth middleware)
            ReconProbe(label="head_anonymous", method="HEAD", url=finding.url,
                       body=None, use_auth=False),
        ]

    def notes(self, finding: Finding) -> list[str]:
        return [
            "Admin/internal exposure is confirmed when an unauthenticated "
            "request to the endpoint returns sensitive data (user lists, "
            "config blobs, internal-only flags). A 401/403 to the anonymous "
            "request is a refutation signal.",
        ]


# ---------------------------------------------------------------------------
# Recipe: Mass Assignment — append privilege fields to the captured body
# ---------------------------------------------------------------------------

_PRIV_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "isSuper": True,
    "plan": "enterprise",
    "verified": True,
    "emailVerified": True,
}


class MassAssignRecipe(ReconRecipe):
    name = "mass_assign_priv_fields"

    def applies(self, finding: Finding) -> bool:
        if Cat.MASS_ASSIGN not in finding.categories:
            return False
        return finding.method.upper() in ("POST", "PUT", "PATCH")

    def probes(self, finding: Finding) -> list[ReconProbe]:
        # Original captured body is the baseline. Without it, mass-assign
        # probing is too noisy — fall back to default recipe instead.
        if not finding.body:
            return []
        try:
            base_obj = json.loads(finding.body)
            if not isinstance(base_obj, dict):
                return []
        except Exception:
            return []

        method = finding.method.upper()
        headers = {"Content-Type": "application/json"}

        # Baseline (original body)
        probes = [
            ReconProbe(label="baseline_auth", method=method, url=finding.url,
                       headers=headers, body=finding.body, use_auth=True),
        ]
        # One probe per priv field — easier to tell which one stuck
        for field_name, field_value in _PRIV_FIELDS.items():
            if field_name in base_obj:
                continue  # don't overwrite legitimately-present fields
            mutated = dict(base_obj)
            mutated[field_name] = field_value
            probes.append(ReconProbe(
                label=f"inject_{field_name}",
                method=method, url=finding.url,
                headers=headers, body=json.dumps(mutated), use_auth=True,
            ))
        return probes

    def notes(self, finding: Finding) -> list[str]:
        return [
            "Mass-assignment confirmation requires the SERVER to echo back "
            "the injected privilege field with the value we sent — or for a "
            "subsequent authenticated read to show the user now has the "
            "elevated role. A 400/422 rejecting the field is a refutation.",
        ]


# ---------------------------------------------------------------------------
# Recipe: SSRF Surface — URL-typed param injection
# ---------------------------------------------------------------------------

_URL_PARAM_NAMES = {"url", "callback", "redirect", "redirect_uri", "next",
                    "target", "dest", "destination", "fetch", "image",
                    "image_url", "avatar", "webhook", "host"}

_SSRF_TEST_TARGETS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22/",
    # Alt-scheme pivots — a server-side URL fetcher built on curl, Java
    # URL, or python urllib often honors these. file/jar/netdoc → local-
    # file reads; gopher/dict/ldap → arbitrary TCP chatter to internal
    # services; ftp/sftp/telnet → legacy-protocol clients.
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "ftp://127.0.0.1/",
    "sftp://127.0.0.1:22/",
    "gopher://127.0.0.1:11211/_stats%0d%0a",
    "dict://127.0.0.1:11211/stats",
    "ldap://127.0.0.1/",
    "telnet://127.0.0.1:23/",
    "jar:https://127.0.0.1!/",
    "netdoc:///etc/passwd",
]


class SSRFRecipe(ReconRecipe):
    name = "ssrf_url_param_inject"

    def applies(self, finding: Finding) -> bool:
        return Cat.SSRF in finding.categories

    def probes(self, finding: Finding) -> list[ReconProbe]:
        # Find a URL-typed parameter in the query string or JSON body.
        target_param = None
        location = None
        parsed = urlparse(finding.url)
        for k in parse_qs(parsed.query).keys():
            if k.lower() in _URL_PARAM_NAMES:
                target_param = k; location = "query"; break

        body_obj = None
        if finding.body and target_param is None:
            try:
                body_obj = json.loads(finding.body)
                if isinstance(body_obj, dict):
                    for k in body_obj.keys():
                        if k.lower() in _URL_PARAM_NAMES:
                            target_param = k; location = "body"; break
            except Exception:
                body_obj = None

        if not target_param:
            return []  # default recipe will handle

        method = finding.method.upper()
        headers = {"Content-Type": "application/json"} if location == "body" else {}
        probes: list[ReconProbe] = []
        # Baseline as-is
        probes.append(ReconProbe(
            label="baseline_auth", method=method, url=finding.url,
            headers=headers,
            body=json.dumps(body_obj) if body_obj is not None else finding.body,
            use_auth=True,
        ))
        for payload in _SSRF_TEST_TARGETS:
            if location == "query":
                qs = parse_qs(parsed.query)
                qs[target_param] = [payload]
                new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                probes.append(ReconProbe(
                    label=f"ssrf_{payload[:30]}",
                    method=method, url=new_url, headers=headers,
                    body=finding.body, use_auth=True,
                ))
                # Double-URL-encoded variant: pre-encode the payload once,
                # then urlencode() applies a second pass automatically when
                # we serialize the querystring. Catches naive WAFs that scan
                # for raw `http://` / `file://` schemes but not their
                # already-encoded forms.
                try:
                    pre_encoded = codec.encode(payload, "url")
                except Exception:
                    pre_encoded = None
                if pre_encoded and pre_encoded != payload:
                    qs2 = parse_qs(parsed.query)
                    qs2[target_param] = [pre_encoded]
                    enc_url = urlunparse(parsed._replace(
                        query=urlencode(qs2, doseq=True)))
                    probes.append(ReconProbe(
                        label=f"ssrf_urlx2_{payload[:24]}",
                        method=method, url=enc_url, headers=headers,
                        body=finding.body, use_auth=True,
                    ))
            else:
                mutated = dict(body_obj)
                mutated[target_param] = payload
                probes.append(ReconProbe(
                    label=f"ssrf_{payload[:30]}",
                    method=method, url=finding.url, headers=headers,
                    body=json.dumps(mutated), use_auth=True,
                ))
        return probes

    def notes(self, finding: Finding) -> list[str]:
        return [
            "SSRF is confirmed when the response body contains content that "
            "could only have come from the requested internal address — "
            "e.g. an EC2 metadata document, a localhost service banner, "
            "/etc/passwd contents. A timeout, 400, or generic error is NOT "
            "confirmation by itself.",
        ]


# ---------------------------------------------------------------------------
# Recipe: Open Redirect — external URL injection in known params
# ---------------------------------------------------------------------------

_REDIR_TEST = "https://evil.example.com/"

# CRLF / response-splitting payloads — used ONLY when an OOB tunnel is up.
# Each payload value is inserted into the redirect query parameter; if the
# server reflects it into the Location header without stripping CR/LF, the
# injected header lands at the byte level and the operator can pick up the
# split via the tunnel's hit log OR via header inspection in the briefing.
#
# We deliberately do NOT emit these without a tunnel — the canary-only
# variant of "Set-Cookie: sid=evil" can still fire a header-injection
# detection in the briefing stage but without callback proof it's noisy
# and frequently mis-attributed. The user-facing rule: opt in to OOB via
# --oob or the recipe stays quiet.
_CRLF_LOCATION_TEMPLATES = [
    ("crlf_standard",      "%0d%0aLocation:%20{C}"),
    ("crlf_lf_only",       "%0aLocation:%20{C}"),
    ("crlf_double_enc",    "%250d%250aLocation:%20{C}"),
    ("crlf_set_cookie",    "%0d%0aSet-Cookie:%20sid={TOKEN}"),
    ("crlf_refresh",       "%0d%0aRefresh:%200;url={C}"),
]


class OpenRedirectRecipe(ReconRecipe):
    name = "open_redirect_param_inject"

    def applies(self, finding: Finding) -> bool:
        return Cat.REDIRECT in finding.categories

    def probes(self, finding: Finding) -> list[ReconProbe]:
        # Backwards-compatible entry point — no tunnel context available.
        return self._build_probes(finding, ctx=None)

    def probes_with_ctx(self, finding: Finding,
                         ctx: Optional[ReconContext]) -> list[ReconProbe]:
        return self._build_probes(finding, ctx=ctx)

    def _build_probes(self, finding: Finding,
                       ctx: Optional[ReconContext]) -> list[ReconProbe]:
        parsed = urlparse(finding.url)
        qs = parse_qs(parsed.query)
        target = None
        for k in qs:
            if k.lower() in _URL_PARAM_NAMES:
                target = k; break
        if not target:
            return []
        method = finding.method.upper()
        baseline = ReconProbe(
            label="baseline_auth", method=method, url=finding.url, use_auth=True,
        )

        # When an OOB tunnel is up, USE it as the redirect target so a
        # successful redirect produces real proof (a hit in tunnel_hits.json).
        # Otherwise fall back to the canary host, which only proves the
        # endpoint *would* redirect — never that it actually fired.
        if ctx and ctx.public_url:
            redir_target = ctx.public_url.rstrip("/") + "/redir"
            canary_host = urlparse(ctx.public_url).netloc
        else:
            redir_target = _REDIR_TEST
            canary_host = "evil.example.com"

        new_qs = dict(qs)
        new_qs[target] = [redir_target]
        evil_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
        probes_out = [
            baseline,
            ReconProbe(label=f"redirect_{target}_to_evil",
                       method=method, url=evil_url, use_auth=True),
        ]
        # Double-URL-encoded variant — pre-encode the redirect target so the
        # downstream filter (if it merely string-matches "://" or the evil
        # domain) doesn't recognize it. urlencode() re-encodes the % signs.
        try:
            pre_encoded = codec.encode(redir_target, "url")
        except Exception:
            pre_encoded = None
        if pre_encoded and pre_encoded != redir_target:
            enc_qs = dict(qs)
            enc_qs[target] = [pre_encoded]
            enc_url = urlunparse(parsed._replace(
                query=urlencode(enc_qs, doseq=True)))
            probes_out.append(ReconProbe(
                label=f"redirect_{target}_urlx2",
                method=method, url=enc_url, use_auth=True,
            ))

        # CRLF / response-splitting probes — opt-in: require an OOB tunnel
        # so we have real callback proof of the split. Without a tunnel we
        # deliberately skip these to avoid false-positive header-injection
        # noise the briefing can't confirm.
        if ctx and ctx.public_url:
            token = ctx.oob_token or "hxxpsin"
            for label, tmpl in _CRLF_LOCATION_TEMPLATES:
                payload = tmpl.format(
                    C=f"//{canary_host}/r/{token}",
                    TOKEN=f"crlf-{token}",
                )
                crlf_qs = dict(qs)
                # Append payload to ORIGINAL value so the server's reflection
                # into the Location header preserves a sensible prefix while
                # appending our injected header line.
                original_val = qs.get(target, [""])[0]
                crlf_qs[target] = [f"{original_val}{payload}"]
                # `quote_via=str` keeps our %XX sequences intact instead of
                # double-encoding them — urlencode() with default quote_plus
                # would mangle %0d into %250d.
                crlf_url = urlunparse(parsed._replace(
                    query=urlencode(crlf_qs, doseq=True, safe="%")))
                probes_out.append(ReconProbe(
                    label=f"redirect_{target}_{label}",
                    method=method, url=crlf_url, use_auth=True,
                ))

        return probes_out

    def notes(self, finding: Finding) -> list[str]:
        # Note: notes() doesn't currently receive ctx so we hint at both
        # outcomes — the briefing prompt will mention tunnel hits if any.
        return [
            "Open-redirect is confirmed by a 30x response whose Location "
            "header points to our external test URL. A relative-only Location "
            "(or no redirect at all) refutes it.",
            "If CRLF / response-splitting probes are present (labels "
            "starting with 'redirect_*_crlf_*'), check for: (a) multiple "
            "Location headers in the response, (b) an injected Set-Cookie "
            "with sid=crlf-* matching our token, (c) a Refresh header, or "
            "(d) a tunnel callback at /r/<token>. Any one of these confirms "
            "header injection.",
        ]


# ---------------------------------------------------------------------------
# Recipe: Injection — generic SQLi/XSS payload sniper (read-only)
# ---------------------------------------------------------------------------

_INJ_PAYLOADS = [
    ("sqli_quote", "'"),
    ("sqli_double_quote", "\""),
    ("sqli_comment", "' OR '1'='1' -- "),
    ("xss_basic", "<script>alert(1)</script>"),
    ("xss_attr_break", "\"><img src=x onerror=alert(1)>"),
    ("template_arith", "{{7*7}}"),
]


class InjectionRecipe(ReconRecipe):
    name = "injection_payload_sniper"

    def applies(self, finding: Finding) -> bool:
        if Cat.INJECTION not in finding.categories:
            return False
        return finding.method.upper() == "GET" or bool(finding.body)

    def probes(self, finding: Finding) -> list[ReconProbe]:
        # Find a string parameter to fuzz — prefer the first query param,
        # falling back to a JSON body key if no query params.
        parsed = urlparse(finding.url)
        qs = parse_qs(parsed.query)
        target = next(iter(qs.keys()), None)
        location = "query" if target else None

        body_obj = None
        if not target and finding.body:
            try:
                body_obj = json.loads(finding.body)
                if isinstance(body_obj, dict) and body_obj:
                    target = next(iter(body_obj.keys()))
                    location = "body"
            except Exception:
                pass

        if not target:
            return []

        method = finding.method.upper()
        headers = {"Content-Type": "application/json"} if location == "body" else {}
        probes = [
            ReconProbe(label="baseline_auth", method=method, url=finding.url,
                       headers=headers, body=finding.body, use_auth=True),
        ]
        for label, payload in _INJ_PAYLOADS:
            if location == "query":
                new_qs = dict(qs); new_qs[target] = [payload]
                new_url = urlunparse(parsed._replace(
                    query=urlencode(new_qs, doseq=True)))
                probes.append(ReconProbe(
                    label=label, method=method, url=new_url, headers=headers,
                    body=finding.body, use_auth=True,
                ))
                # Double-URL-encoded variant — catches WAFs that pattern-match
                # raw payload signatures but accept their pre-encoded form.
                try:
                    pre_encoded = codec.encode(payload, "url")
                except Exception:
                    pre_encoded = None
                if pre_encoded and pre_encoded != payload:
                    enc_qs = dict(qs); enc_qs[target] = [pre_encoded]
                    enc_url = urlunparse(parsed._replace(
                        query=urlencode(enc_qs, doseq=True)))
                    probes.append(ReconProbe(
                        label=f"{label}_urlx2", method=method, url=enc_url,
                        headers=headers, body=finding.body, use_auth=True,
                    ))
            else:
                mutated = dict(body_obj); mutated[target] = payload
                probes.append(ReconProbe(
                    label=label, method=method, url=finding.url, headers=headers,
                    body=json.dumps(mutated), use_auth=True,
                ))
        return probes

    def notes(self, finding: Finding) -> list[str]:
        return [
            "Injection is confirmed when the response contains SQL error "
            "fragments, payload reflection in HTML/JS context, template "
            "expansion ({{7*7}} → 49), or other evidence of payload "
            "interpretation. A consistent 400/500 across all payloads "
            "suggests a generic input validator and refutes the bug.",
        ]


# ---------------------------------------------------------------------------
# Recipe: CORS — Origin reflection probe
# ---------------------------------------------------------------------------

class CORSRecipe(ReconRecipe):
    name = "cors_origin_reflect"

    def applies(self, finding: Finding) -> bool:
        return Cat.CORS in finding.categories

    def probes(self, finding: Finding) -> list[ReconProbe]:
        method = finding.method.upper()
        body = finding.body if method in ("POST", "PUT", "PATCH") else None
        return [
            ReconProbe(label="no_origin", method=method, url=finding.url,
                       body=body, use_auth=True),
            ReconProbe(label="origin_evil",
                       method=method, url=finding.url, body=body,
                       headers={"Origin": "https://evil.example.com"},
                       use_auth=True),
            ReconProbe(label="origin_null",
                       method=method, url=finding.url, body=body,
                       headers={"Origin": "null"},
                       use_auth=True),
            ReconProbe(label="preflight_evil", method="OPTIONS", url=finding.url,
                       headers={
                           "Origin": "https://evil.example.com",
                           "Access-Control-Request-Method": method,
                       }, use_auth=False),
        ]

    def notes(self, finding: Finding) -> list[str]:
        return [
            "CORS misconfig is confirmed when the response reflects "
            "Access-Control-Allow-Origin: <our evil origin> together with "
            "Access-Control-Allow-Credentials: true. ACAO: * alone is loose "
            "but not credential-leaking. No ACAO header at all refutes the "
            "concern.",
        ]


# ---------------------------------------------------------------------------
# Recipe: Race condition — parallel send of identical request
# ---------------------------------------------------------------------------

class RaceRecipe(ReconRecipe):
    name = "race_parallel_send"

    def applies(self, finding: Finding) -> bool:
        if Cat.RACE not in finding.categories:
            return False
        return finding.method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    def probes(self, finding: Finding) -> list[ReconProbe]:
        method = finding.method.upper()
        body = finding.body
        # 5 identical probes sent in parallel (the executor handles
        # concurrency for race recipes specifically).
        return [
            ReconProbe(label=f"race_attempt_{i}",
                       method=method, url=finding.url, body=body,
                       use_auth=True)
            for i in range(5)
        ]

    def notes(self, finding: Finding) -> list[str]:
        return [
            "Race condition is confirmed when ≥2 parallel attempts succeed "
            "where business logic only allows 1 (e.g. coupon applied twice, "
            "balance debited twice, account verified twice). All-success "
            "without uniqueness violation is suspicious; mostly-failure is "
            "refuted.",
        ]


# ---------------------------------------------------------------------------
# Fallback recipe — minimum safe recon
# ---------------------------------------------------------------------------

class FallbackRecipe(ReconRecipe):
    name = "fallback_baseline_vs_anon"

    def applies(self, finding: Finding) -> bool:
        return True  # always

    def probes(self, finding: Finding) -> list[ReconProbe]:
        method = finding.method.upper()
        body = finding.body if method in ("POST", "PUT", "PATCH") else None
        return [
            ReconProbe(label="baseline_auth", method=method, url=finding.url,
                       body=body, use_auth=True),
            ReconProbe(label="anonymous", method=method, url=finding.url,
                       body=body, use_auth=False),
        ]

    def notes(self, finding: Finding) -> list[str]:
        return [
            "No category-specific recipe matched this finding. The condenser "
            "should treat this as minimum-evidence recon and recommend further "
            "probes rather than rendering a strong verdict.",
        ]


# Order matters — more specific recipes first; FallbackRecipe always last.
_RECIPES: list[ReconRecipe] = [
    IDORRecipe(),
    AdminRecipe(),
    MassAssignRecipe(),
    SSRFRecipe(),
    OpenRedirectRecipe(),
    InjectionRecipe(),
    CORSRecipe(),
    RaceRecipe(),
    FallbackRecipe(),
]


def pick_recipe(finding: Finding,
                ctx: Optional[ReconContext] = None) -> ReconRecipe:
    for r in _RECIPES:
        if r.applies(finding):
            probes = _recipe_probes(r, finding, ctx)
            if probes:
                return r
    return FallbackRecipe()


def _recipe_probes(recipe: ReconRecipe, finding: Finding,
                   ctx: Optional[ReconContext]) -> list[ReconProbe]:
    """Call probes_with_ctx if the recipe defines it AND ctx is non-None;
    otherwise call the plain probes(finding) method. Lets us add context-
    aware recipes one-by-one without touching the other 8 signatures."""
    if ctx is not None and hasattr(recipe, "probes_with_ctx"):
        return recipe.probes_with_ctx(finding, ctx)
    return recipe.probes(finding)


# ---------------------------------------------------------------------------
# Probe executor — sends a probe and records the observation
# ---------------------------------------------------------------------------

_RESPONSE_BODY_CAP = 8 * 1024
_INTERESTING_REQ_HEADERS = {"content-type", "origin", "referer",
                            "access-control-request-method"}
_INTERESTING_RESP_HEADERS = {"content-type", "content-length", "location",
                             "set-cookie", "access-control-allow-origin",
                             "access-control-allow-credentials",
                             "access-control-allow-methods", "etag",
                             "x-powered-by", "server"}


async def _execute_probe(probe: ReconProbe, target_host: str,
                         auth_headers: dict[str, str],
                         http_client: httpx.AsyncClient) -> ReconObservation:
    # Host-pinning — recipes are deterministic but defensive check in case
    # a recipe is buggy or someone edits one carelessly. Compare lower-cased
    # so a stray capitalization in a probe URL doesn't bypass the gate.
    host = urlparse(probe.url).netloc.lower()
    if host and host != target_host:
        return ReconObservation(
            label=probe.label, method=probe.method, url=probe.url,
            request_body=probe.body, request_headers_subset={},
            error=f"refused off-host probe (got {host!r}, expected {target_host!r})",
        )

    headers = dict(probe.headers or {})
    if probe.use_auth:
        for k, v in (auth_headers or {}).items():
            headers.setdefault(k, v)
    if probe.body and "content-type" not in {k.lower() for k in headers}:
        headers.setdefault("Content-Type", "application/json")

    req_headers_subset = {k: v for k, v in headers.items()
                          if k.lower() in _INTERESTING_REQ_HEADERS}

    t0 = time.monotonic()
    try:
        r = await http_client.request(
            probe.method, probe.url, headers=headers, content=probe.body,
        )
    except Exception as exc:
        return ReconObservation(
            label=probe.label, method=probe.method, url=probe.url,
            request_body=probe.body, request_headers_subset=req_headers_subset,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            error=f"{type(exc).__name__}: {exc}",
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    body = r.text or ""
    total_len = len(body)
    truncated = False
    if total_len > _RESPONSE_BODY_CAP:
        body = body[:_RESPONSE_BODY_CAP // 2] + "\n…[truncated]…\n" + body[-_RESPONSE_BODY_CAP // 2:]
        truncated = True

    resp_headers_subset = {k: v for k, v in dict(r.headers).items()
                           if k.lower() in _INTERESTING_RESP_HEADERS}

    return ReconObservation(
        label=probe.label,
        method=probe.method, url=probe.url,
        request_body=probe.body,
        request_headers_subset=req_headers_subset,
        status=r.status_code,
        response_headers=resp_headers_subset,
        response_body=body,
        response_truncated=truncated,
        response_size_bytes=total_len,
        elapsed_ms=elapsed_ms,
    )


async def collect_recon(
    finding: Finding, finding_index: int,
    target: str, auth_headers: dict[str, str],
    timeout: float = 12.0,
    ctx: Optional[ReconContext] = None,
) -> ReconBundle:
    """Run the matching recipe against `finding` and return a ReconBundle.
    Pure-data — no LLM calls in this stage. When `ctx` carries a public_url
    (OOB tunnel), context-aware recipes (currently only OpenRedirectRecipe)
    use it to mount real callback-confirmed probes."""
    recipe = pick_recipe(finding, ctx=ctx)
    probes = _recipe_probes(recipe, finding, ctx)
    notes = list(recipe.notes(finding))
    bundle = ReconBundle(
        finding_index=finding_index,
        finding_categories=list(finding.categories),
        recipe_name=recipe.name,
        notes=notes,
    )

    if not probes:
        # Shouldn't happen because FallbackRecipe always produces probes,
        # but guard anyway.
        return bundle

    target_host = urlparse(target).netloc.lower()

    async with httpx.AsyncClient(timeout=timeout, verify=False,
                                 follow_redirects=False, http2=True) as client:
        if isinstance(recipe, RaceRecipe):
            # Parallel send for race detection
            tasks = [_execute_probe(p, target_host, auth_headers, client)
                     for p in probes]
            bundle.observations = await asyncio.gather(*tasks)
        else:
            for p in probes:
                obs = await _execute_probe(p, target_host, auth_headers, client)
                bundle.observations.append(obs)

    bundle.probes_sent = len(bundle.observations)
    return bundle
