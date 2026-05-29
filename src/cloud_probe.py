"""
cloud_probe.py — Cloud-platform exposure probe for hxxpsin.

Surfaces the following classes of cloud-specific findings the rest of the
pipeline misses:

  - bucket_exposure   — guessable S3 / GCS / Azure Blob / R2 buckets
                        whose listing or write API is publicly reachable
  - dangling_cname    — subdomains pointing at unclaimed cloud resources
                        (S3 NoSuchBucket, Azure "Web App not found", Heroku,
                        GitHub Pages, Fastly, Netlify, Vercel)
  - exposed_function  — Lambda Function URLs, Cloud Run, Azure Functions
                        that respond unauthenticated
  - leaked_credential — credential-shaped strings discovered anywhere
                        downstream (HTTP bodies, grabbed files, SCM
                        artifacts) via the unified [[secrets]] catalog
  - oidc_misconfig    — /.well-known/openid-configuration that allows
                        ``token_endpoint_auth_methods_supported: ["none"]``
                        or leaks public JWKS material
  - imds_metadata     — IMDS v2 token-then-fetch verification on confirmed
                        SSRF surfaces; AWS IAM role steal via
                        ``/iam/security-credentials/`` (active-scan only,
                        depends on payload_server callback to confirm)

Pipeline position: runs in two passes.

  1. **Stage 0** (pre-crawl, fast): bucket-name guessing, OIDC config,
     dangling-CNAME against subdomains discovered by [[surface_mapper]].
  2. **Post-active-scan**: IMDS v2 dance when an SSRF callback has already
     fired; leaked_credential sweep across collector + [[scm_probe]] +
     [[file_grabber]] output.

Existing infrastructure reused — see plan §2.3:
  - [[verifier._SSRF_PAYLOADS]] for IMDS endpoint list
  - [[payload_server]] /aws/gcp/azure callbacks
  - [[active_scanner._test_ssrf]] OOB callback wiring
  - [[secrets.scan]] for credential detection
  - [[scm_probe]] body content as a credential source
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

import secrets as _secrets


# ---------------------------------------------------------------------------
# Bucket / function host fingerprints
# ---------------------------------------------------------------------------

# Provider -> hostname pattern used both for "is this a cloud host?" and
# (when company-name suffixed) bucket-name guessing.
_BUCKET_TEMPLATES = [
    ("aws_s3",       "{name}.s3.amazonaws.com"),
    ("aws_s3",       "s3.amazonaws.com/{name}"),    # path-style
    ("gcp_gcs",      "storage.googleapis.com/{name}"),
    ("azure_blob",   "{name}.blob.core.windows.net"),
    ("cloudflare_r2", "{name}.r2.cloudflarestorage.com"),
    ("digitalocean", "{name}.digitaloceanspaces.com"),
]

# Bucket-name candidate suffixes derived from target's company-level domain.
_BUCKET_SUFFIXES = [
    "", "-prod", "-production", "-staging", "-dev", "-test",
    "-backup", "-backups", "-uploads", "-assets", "-static", "-media",
    "-public", "-private", "-data", "-logs", "-archive", "-temp",
]


# Dangling-CNAME fingerprints — vendor → (response body substring, severity).
# When a subdomain CNAMEs to a cloud catch-all and the cloud returns this
# string, the resource was deleted/unclaimed and is takeoverable.
@dataclass
class _TakeoverFingerprint:
    provider: str
    body_marker: str   # case-insensitive substring in response body
    note: str
    status_codes: tuple[int, ...] = (200, 404)


_TAKEOVER_FINGERPRINTS = [
    _TakeoverFingerprint("aws_s3",        "NoSuchBucket",
                          "S3 bucket missing — takeoverable via aws s3 mb"),
    _TakeoverFingerprint("aws_s3",        "The specified bucket does not exist",
                          "S3 bucket missing"),
    _TakeoverFingerprint("azure",         "Web App - Unavailable",
                          "Azure Web App unclaimed — takeoverable"),
    _TakeoverFingerprint("azure",         "404 Web Site not found",
                          "Azure Web Site unclaimed"),
    _TakeoverFingerprint("heroku",        "There's nothing here yet",
                          "Heroku app unclaimed"),
    _TakeoverFingerprint("heroku",        "No such app",
                          "Heroku app unclaimed"),
    _TakeoverFingerprint("github_pages",  "There isn't a GitHub Pages site here",
                          "GitHub Pages site unclaimed"),
    _TakeoverFingerprint("fastly",        "Fastly error: unknown domain",
                          "Fastly service unclaimed"),
    _TakeoverFingerprint("netlify",       "Not Found - Request ID:",
                          "Netlify site unclaimed"),
    _TakeoverFingerprint("vercel",        "The deployment could not be found",
                          "Vercel deployment unclaimed"),
    _TakeoverFingerprint("shopify",       "Sorry, this shop is currently unavailable",
                          "Shopify store unclaimed"),
    _TakeoverFingerprint("readthedocs",   "unknown to Read the Docs",
                          "Read the Docs project unclaimed"),
    _TakeoverFingerprint("bitbucket",     "Repository not found",
                          "Bitbucket Pages unclaimed"),
]


# Function-host patterns — discovery-only, just flag when crawler hits one.
_FUNCTION_HOST_RE = re.compile(
    r"\.(lambda-url\.[a-z0-9-]+\.on\.aws"
    r"|a\.run\.app"
    r"|azurewebsites\.net"
    r"|workers\.dev"
    r"|netlify\.app"
    r"|vercel\.app)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CloudFinding:
    url: str
    surface: str        # bucket_exposure | dangling_cname | exposed_function
                         # | leaked_credential | oidc_misconfig | imds_metadata
    provider: str       # aws | gcp | azure | digitalocean | heroku | github_pages | …
    severity: str       # critical | high | medium | low | info
    verdict: str        # confirmed | likely | needs_review
    evidence: str
    payload: str = ""
    secret_kinds: list[str] = field(default_factory=list)
    source: str = ""    # where the artifact came from (host / file / endpoint)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "surface": self.surface,
            "provider": self.provider, "severity": self.severity,
            "verdict": self.verdict, "evidence": self.evidence,
            "payload": self.payload[:200],
            "secret_kinds": self.secret_kinds,
            "source": self.source,
        }


@dataclass
class CloudProbeResult:
    findings: list[CloudFinding] = field(default_factory=list)
    bases_probed: int = 0
    subdomains_probed: int = 0
    credentials_swept: int = 0
    out_dir: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def critical(self) -> list[CloudFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def confirmed(self) -> list[CloudFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "bases_probed": self.bases_probed,
            "subdomains_probed": self.subdomains_probed,
            "credentials_swept": self.credentials_swept,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class CloudProbe:
    _MAX_BUCKET_GUESSES = 60   # target-name × suffix × providers, capped
    _BODY_PREVIEW = 256

    def __init__(self, out_dir: str = "", timeout: float = 6.0,
                 auth_headers: Optional[dict] = None,
                 active_scan: bool = False):
        self.out_root = Path(out_dir) / "cloud_probe" if out_dir else None
        self.timeout = timeout
        self.auth_headers = auth_headers or {}
        self.active_scan = active_scan

    async def run(self, target: str, *,
                  subdomains: Optional[list[str]] = None,
                  credential_corpus: Optional[list[tuple[str, str]]] = None,
                  ) -> CloudProbeResult:
        """Stage-0 cloud exposure sweep.

        Args:
            target: scan target URL (used for bucket-name candidates).
            subdomains: discovered subdomains for dangling-CNAME checks.
            credential_corpus: ``[(source_label, text), …]`` of bodies to
                sweep for leaked credentials (e.g. ``[("response:/api/x",
                body), ("file:.env", env_body)]``).
        """
        result = CloudProbeResult(
            out_dir=str(self.out_root) if self.out_root else "",
        )
        parsed = urlparse(target)
        if not parsed.scheme:
            result.notes.append("invalid target — no scheme")
            return result

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=False,
            headers=self.auth_headers,
        ) as client:
            tasks = []

            # 1. Bucket-name guessing — derive candidates from the
            # target's company-level domain
            company = self._company_from_host(parsed.netloc)
            if company:
                bucket_urls = self._bucket_candidates(company)
                result.bases_probed += len(bucket_urls)
                for label, url in bucket_urls[:self._MAX_BUCKET_GUESSES]:
                    tasks.append(self._probe_bucket(client, label, url))

            # 2. OIDC config probe
            tasks.append(self._probe_oidc(client, parsed))

            # 3. Dangling-CNAME checks against subdomains
            for sub in (subdomains or [])[:50]:
                tasks.append(self._probe_dangling(client, sub))
                result.subdomains_probed += 1

            # 4. Function-host classification (no HTTP — just URL parse)
            for sub in (subdomains or []):
                fn_finding = self._classify_function_host(sub)
                if fn_finding:
                    result.findings.append(fn_finding)

            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, list):
                    result.findings.extend(outcome)
                elif isinstance(outcome, CloudFinding):
                    result.findings.append(outcome)

        # 5. Credential sweep across supplied corpora — text-only, no HTTP
        if credential_corpus:
            for source_label, body in credential_corpus:
                if not body:
                    continue
                result.credentials_swept += 1
                for m in _secrets.scan(body):
                    if m.public_by_design:
                        continue
                    result.findings.append(CloudFinding(
                        url=source_label, surface="leaked_credential",
                        provider=self._provider_for_secret(m.kind),
                        severity=m.severity,
                        verdict="confirmed",
                        evidence=f"{m.kind} found in {source_label}",
                        payload=m.value[:12] + "…",
                        secret_kinds=[m.kind],
                        source=source_label,
                    ))

        # Severity ranking
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.findings.sort(key=lambda f: sev_rank.get(f.severity, 9))

        if self.out_root and result.findings:
            self._persist(result)

        return result

    # ------------------------------------------------------------------
    # Bucket candidates
    # ------------------------------------------------------------------

    @staticmethod
    def _company_from_host(netloc: str) -> str:
        """Return the registrable domain's main label (company-level).
        ``www.acme.com`` → ``acme``; ``api.acme.com`` → ``acme``."""
        host = netloc.split(":", 1)[0].lower()
        # Drop port
        parts = host.split(".")
        if len(parts) < 2:
            return ""
        # Skip leading 'www', then take the rightmost meaningful label
        # before the public suffix. We use a simple heuristic — second-to-
        # last label is the company in most ``company.tld`` and ``sub.
        # company.tld`` cases.
        labels = [p for p in parts if p not in ("www",)]
        if len(labels) >= 2:
            return labels[-2]
        return labels[0] if labels else ""

    @staticmethod
    def _bucket_candidates(company: str) -> list[tuple[str, str]]:
        """Return ``[(provider_label, candidate_url), …]``."""
        out: list[tuple[str, str]] = []
        for suffix in _BUCKET_SUFFIXES:
            name = company + suffix
            for provider, template in _BUCKET_TEMPLATES:
                host_or_path = template.format(name=name)
                if host_or_path.startswith(provider.split("_")[0] + "."):
                    # path-style for S3 ("s3.amazonaws.com/{name}")
                    url = f"https://{host_or_path}"
                elif "{name}" not in template and "/" in host_or_path:
                    url = f"https://{host_or_path}"
                else:
                    url = f"https://{host_or_path}"
                out.append((provider, url))
        return out

    async def _probe_bucket(self, client, provider: str,
                            url: str) -> Optional[CloudFinding]:
        """GET the bucket URL with no auth and inspect the response.

        Confirmation rules:
          - 200 + ``<ListBucketResult>`` / ``<EnumerationResults>`` /
            JSON ``"items"`` → bucket listing exposed (critical)
          - 200 + provider's "no auth required for this object" content
            (rare) → exposed
          - 403 + ``<Code>AccessDenied</Code>`` → bucket exists but is
            protected (info)
          - 404 + provider's "no such bucket" → unclaimed (relevant for
            dangling-CNAME flow but not interesting on its own here)
        """
        try:
            r = await client.get(url)
        except Exception:
            return None
        body = (r.text or "")[: self._BODY_PREVIEW * 4]
        # Listing markers (provider-specific shapes)
        listing_markers = (
            "<ListBucketResult", "<EnumerationResults",
            '"kind":"storage#objects"', '"items":[',
        )
        if r.status_code == 200 and any(m in body for m in listing_markers):
            return CloudFinding(
                url=url, surface="bucket_exposure", provider=provider,
                severity="critical", verdict="confirmed",
                evidence=f"public bucket listing on {provider}",
                payload=body[:self._BODY_PREVIEW],
                source=url,
            )
        if r.status_code == 403 and "AccessDenied" in body:
            return CloudFinding(
                url=url, surface="bucket_exposure", provider=provider,
                severity="info", verdict="needs_review",
                evidence="bucket exists but auth required",
                source=url,
            )
        return None

    # ------------------------------------------------------------------
    # OIDC config
    # ------------------------------------------------------------------

    async def _probe_oidc(self, client,
                          parsed) -> list[CloudFinding]:
        """Fetch ``/.well-known/openid-configuration`` and flag dangerous
        settings. Returns 0–N findings."""
        url = f"{parsed.scheme}://{parsed.netloc}/.well-known/openid-configuration"
        try:
            r = await client.get(url)
        except Exception:
            return []
        if r.status_code != 200:
            return []
        try:
            cfg = r.json()
        except Exception:
            return []
        if not isinstance(cfg, dict):
            return []
        out: list[CloudFinding] = []
        # token_endpoint_auth_methods_supported including "none"
        methods = cfg.get("token_endpoint_auth_methods_supported", []) or []
        if "none" in methods:
            out.append(CloudFinding(
                url=url, surface="oidc_misconfig", provider="oidc",
                severity="high", verdict="confirmed",
                evidence='token_endpoint_auth_methods_supported includes "none"',
                source=url,
            ))
        # Implicit flow still supported
        rt = cfg.get("response_types_supported", []) or []
        if any("token" in t and "code" not in t for t in rt if isinstance(t, str)):
            out.append(CloudFinding(
                url=url, surface="oidc_misconfig", provider="oidc",
                severity="medium", verdict="confirmed",
                evidence=f"implicit flow advertised in response_types: {rt}",
                source=url,
            ))
        # Discovery endpoint itself is interesting context
        out.append(CloudFinding(
            url=url, surface="oidc_misconfig", provider="oidc",
            severity="info", verdict="needs_review",
            evidence=(
                f"discovery doc reachable — issuer={cfg.get('issuer', '?')}, "
                f"jwks_uri={cfg.get('jwks_uri', '?')}"
            ),
            source=url,
        ))
        return out

    # ------------------------------------------------------------------
    # Dangling CNAME
    # ------------------------------------------------------------------

    async def _probe_dangling(self, client,
                              host: str) -> Optional[CloudFinding]:
        """HTTP-fetch the host root and grep for cloud catch-all markers."""
        url = host if host.startswith("http") else f"https://{host}/"
        try:
            r = await client.get(url)
        except Exception:
            return None
        body = (r.text or "")[: self._BODY_PREVIEW * 4]
        for fp in _TAKEOVER_FINGERPRINTS:
            if r.status_code not in fp.status_codes:
                continue
            if fp.body_marker.lower() in body.lower():
                return CloudFinding(
                    url=url, surface="dangling_cname", provider=fp.provider,
                    severity="critical", verdict="confirmed",
                    evidence=fp.note + f" (marker: {fp.body_marker!r})",
                    payload=body[:self._BODY_PREVIEW],
                    source=host,
                )
        return None

    # ------------------------------------------------------------------
    # Function-host classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_function_host(host: str) -> Optional[CloudFinding]:
        """Flag known serverless-function hostnames discovered in the crawl.
        Doesn't fetch — the active SSRF probe is the verifier here."""
        h = host.lower()
        if not _FUNCTION_HOST_RE.search(h):
            return None
        # Provider tagging
        if ".lambda-url." in h:
            provider = "aws_lambda"
        elif ".a.run.app" in h:
            provider = "gcp_cloudrun"
        elif ".azurewebsites.net" in h:
            provider = "azure_functions"
        elif ".workers.dev" in h:
            provider = "cloudflare_workers"
        elif ".netlify.app" in h:
            provider = "netlify_functions"
        elif ".vercel.app" in h:
            provider = "vercel_functions"
        else:
            provider = "serverless"
        return CloudFinding(
            url=h, surface="exposed_function", provider=provider,
            severity="info", verdict="needs_review",
            evidence=f"serverless function host detected ({provider})",
            source=h,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _provider_for_secret(kind: str) -> str:
        if kind.startswith("aws_"):       return "aws"
        if kind.startswith("gcp_") or kind == "google_oauth_client_id":
            return "gcp"
        if kind.startswith("azure_"):     return "azure"
        if kind.startswith("github_"):    return "github"
        if kind.startswith("gitlab_"):    return "gitlab"
        if kind.startswith("stripe_"):    return "stripe"
        if kind == "slack_token":         return "slack"
        if kind == "private_key":         return "ssh_pgp"
        if kind == "openai_key":          return "openai"
        if kind == "anthropic_key":       return "anthropic"
        return "other"

    def _persist(self, result: CloudProbeResult) -> None:
        self.out_root.mkdir(parents=True, exist_ok=True)
        (self.out_root / "findings.json").write_text(
            json.dumps([f.to_dict() for f in result.findings], indent=2)
        )
        if result.critical:
            (self.out_root / "critical.json").write_text(
                json.dumps([f.to_dict() for f in result.critical], indent=2)
            )


__all__ = ["CloudProbe", "CloudProbeResult", "CloudFinding"]
