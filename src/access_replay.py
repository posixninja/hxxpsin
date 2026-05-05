"""
access_replay.py — Re-attempt previously forbidden (401/403) URLs with auth
bypass tokens discovered later in the pipeline.

Workflow:
  1. The crawler hit URLs that returned 401/403 (the Collector recorded those
     status codes via add_response_meta).
  2. Subsequent probes (JWTAnalyzer, AuthBypassProbe, IDORProbe) confirmed an
     auth bypass — a forged JWT, an SQLi-bypassed login, a victim account.
  3. This probe re-fetches each forbidden URL with each bypass header set and
     flags any URL where the status flips 4xx → 2xx. The unlocked body is
     saved to <out>/access_bypass/ for offline analysis.

Why a separate probe: the bypass and the forbidden-URL list are produced by
different subsystems running at different points. Having a single late stage
that joins them keeps each subsystem's responsibilities narrow and makes
"recon goldmine you couldn't read before" a first-class output.

Pipeline position: after JWT, AuthBypass, and IDOR probes have all run, before
nuclei generation and report writing.
"""

import asyncio
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx


# Per-body cap when saving unlocked content (1 MB is plenty for HTML/JSON;
# binary downloads should be re-grabbed via FileGrabber on the new URL list).
_MAX_BODY_BYTES = 1 * 1024 * 1024
# Total attempts cap so a noisy crawl × many bypass tokens doesn't explode.
_MAX_ATTEMPTS = 600
# Concurrency limit for the replay pass.
_CONCURRENCY = 12
# Statuses we treat as "unlocked".
_OK_STATUSES = frozenset({200, 201, 202, 204, 206})


@dataclass
class BypassToken:
    """One auth-bypass header set discovered by an upstream probe.
    `label` is shown in the report; `source` names which probe found it."""
    label: str
    source: str            # "jwt_forge" | "auth_bypass" | "idor_account_b" | "baseline"
    headers: dict[str, str] = field(default_factory=dict)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "source": self.source,
            "evidence": self.evidence,
            "header_keys": sorted(self.headers.keys()),
        }


@dataclass
class Unlocked:
    """One URL that flipped 4xx → 2xx with a discovered bypass."""
    url: str
    method: str
    original_status: int
    new_status: int
    bypass_label: str
    bypass_source: str
    bytes_recovered: int
    content_type: str
    body_path: str = ""        # absolute path to saved body, "" if not saved
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "original_status": self.original_status,
            "new_status": self.new_status,
            "bypass_label": self.bypass_label,
            "bypass_source": self.bypass_source,
            "bytes_recovered": self.bytes_recovered,
            "content_type": self.content_type,
            "body_path": self.body_path,
            "evidence": self.evidence,
        }


@dataclass
class AccessReplayResult:
    forbidden_urls_seen: int = 0
    bypass_tokens_tried: int = 0
    attempts: int = 0
    unlocked: list[Unlocked] = field(default_factory=list)
    total_bytes_recovered: int = 0
    notes: list[str] = field(default_factory=list)
    bypass_tokens: list[BypassToken] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "forbidden_urls_seen": self.forbidden_urls_seen,
            "bypass_tokens_tried": self.bypass_tokens_tried,
            "attempts": self.attempts,
            "unlocked_count": len(self.unlocked),
            "total_bytes_recovered": self.total_bytes_recovered,
            "unlocked": [u.to_dict() for u in self.unlocked],
            "tokens": [t.to_dict() for t in self.bypass_tokens],
            "notes": self.notes,
        }


class AccessReplayProbe:
    def __init__(self, out_dir: str, timeout: float = 8.0):
        self.out_dir = Path(out_dir) / "access_bypass"
        self.timeout = timeout

    async def run(
        self,
        collector,
        bypass_tokens: list[BypassToken],
    ) -> AccessReplayResult:
        result = AccessReplayResult(bypass_tokens=list(bypass_tokens))
        forbidden = self._collect_forbidden(collector)
        result.forbidden_urls_seen = len(forbidden)
        result.bypass_tokens_tried = len(bypass_tokens)

        if not forbidden:
            result.notes.append("no 401/403 responses recorded during crawl — nothing to replay")
            return result
        if not bypass_tokens:
            result.notes.append("no bypass tokens discovered — skipping replay")
            return result

        self.out_dir.mkdir(parents=True, exist_ok=True)
        sem = asyncio.Semaphore(_CONCURRENCY)
        attempts_left = _MAX_ATTEMPTS
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout,
        ) as client:
            tasks = []
            for url, info in forbidden.items():
                if attempts_left <= 0:
                    result.notes.append(f"attempt budget reached ({_MAX_ATTEMPTS}); some URLs not replayed")
                    break
                tasks.append(self._replay_url(
                    client, sem, url, info["status"], info["method"], bypass_tokens, result,
                ))
                attempts_left -= len(bypass_tokens)
            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    def _collect_forbidden(self, collector) -> dict:
        """Return {url: {status, method}} for every URL that returned 401/403.
        Dedupes by URL; if multiple methods hit the same URL, keeps the first."""
        out: dict[str, dict] = {}
        for r in collector.requests:
            status = getattr(r, "response_status", None)
            if status not in (401, 403):
                continue
            if r.url in out:
                continue
            out[r.url] = {"status": status, "method": r.method}
        return out

    async def _replay_url(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
        original_status: int,
        method: str,
        bypass_tokens: list[BypassToken],
        result: AccessReplayResult,
    ) -> None:
        """Try each bypass token against `url`. Stop at the first one that flips
        the status to 2xx. Save the body for that token only."""
        async with sem:
            for token in bypass_tokens:
                result.attempts += 1
                try:
                    r = await client.request(
                        method if method in ("GET", "HEAD") else "GET",
                        url, headers=token.headers,
                    )
                except Exception:
                    continue
                if r.status_code not in _OK_STATUSES:
                    continue
                # Status improvement confirmed — save the body and record the find.
                content = r.content[:_MAX_BODY_BYTES]
                body_path = self._save_body(url, r.status_code, content)
                ct = r.headers.get("content-type", "").split(";", 1)[0].strip()
                unlocked = Unlocked(
                    url=url,
                    method=method,
                    original_status=original_status,
                    new_status=r.status_code,
                    bypass_label=token.label,
                    bypass_source=token.source,
                    bytes_recovered=len(content),
                    content_type=ct,
                    body_path=body_path,
                    evidence=f"{original_status}→{r.status_code} via {token.source}:{token.label} "
                             f"({len(content)} bytes, {ct or 'no content-type'})",
                )
                result.unlocked.append(unlocked)
                result.total_bytes_recovered += len(content)
                return  # one bypass per URL is enough — don't keep trying

    def _save_body(self, url: str, status: int, content: bytes) -> str:
        """Save unlocked response body to <out>/access_bypass/<host><path-sha>_<status>.<ext>.
        Filename embeds a path-derived hash to avoid collisions but stays readable."""
        parsed = urlparse(url)
        host = (parsed.hostname or "host").replace(":", "_")
        sha = hashlib.sha256(url.encode()).hexdigest()[:10]
        # Best-effort suffix from the URL path's last segment
        last_seg = parsed.path.rsplit("/", 1)[-1] or "index"
        last_seg = "".join(c if c.isalnum() or c in "._-" else "_" for c in last_seg)[:60]
        fname = f"{host}_{sha}_{status}_{last_seg}"
        if "." not in last_seg:
            fname += ".bin"
        path = self.out_dir / fname
        try:
            path.write_bytes(content)
        except Exception:
            return ""
        return str(path)


# ---------------------------------------------------------------------------
# Bypass-token harvesting helpers — called by main.py after the relevant
# probes have run. Each returns a list[BypassToken].
# ---------------------------------------------------------------------------

def tokens_from_jwt_attack(jwt_result, baseline_headers: Optional[dict] = None) -> list[BypassToken]:
    """Pull crafted_token from each confirmed JWTFinding and wrap as Authorization."""
    tokens: list[BypassToken] = []
    if jwt_result is None:
        return tokens
    seen: set[str] = set()
    for f in jwt_result.confirmed:
        if not f.crafted_token or f.crafted_token in seen:
            continue
        seen.add(f.crafted_token)
        hdrs: dict[str, str] = {}
        if baseline_headers:
            # Carry over non-Authorization headers (Cookie, X-API-Key, etc.) so
            # the forged JWT is *added*, not used in isolation.
            hdrs = {k: v for k, v in baseline_headers.items() if k.lower() != "authorization"}
        hdrs["Authorization"] = f"Bearer {f.crafted_token}"
        tokens.append(BypassToken(
            label=f.attack_name,
            source="jwt_forge",
            headers=hdrs,
            evidence=f.evidence,
        ))
    return tokens


def tokens_from_auth_bypass(
    auth_bypass_result, baseline_headers: Optional[dict] = None,
) -> list[BypassToken]:
    """Auth-bypass via SQLi rarely produces a usable token directly (the
    bypass is for the *login* request itself). But if the response_snippet
    contains a JWT-shaped string, harvest it. Otherwise, this returns []."""
    import re as _re
    tokens: list[BypassToken] = []
    if auth_bypass_result is None:
        return tokens
    jwt_re = _re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
    seen: set[str] = set()
    for f in auth_bypass_result.confirmed:
        m = jwt_re.search(f.response_snippet or "")
        if not m or m.group(0) in seen:
            continue
        seen.add(m.group(0))
        hdrs: dict[str, str] = {}
        if baseline_headers:
            hdrs = {k: v for k, v in baseline_headers.items() if k.lower() != "authorization"}
        hdrs["Authorization"] = f"Bearer {m.group(0)}"
        tokens.append(BypassToken(
            label=f"sqli_login:{f.field}",
            source="auth_bypass",
            headers=hdrs,
            evidence=f"login bypass via {f.field}={f.payload!r} → token leaked in response",
        ))
    return tokens


def tokens_from_idor(idor_result, account_b) -> list[BypassToken]:
    """Account B's headers are an access-bypass: anything Account A couldn't
    read but Account B could is — by definition — a previously-forbidden URL
    that became readable with a different account's credentials."""
    tokens: list[BypassToken] = []
    if idor_result is None or account_b is None or not account_b.headers:
        return tokens
    if not idor_result.confirmed:
        # No confirmed cross-account hits — still worth trying account B as
        # a bypass for crawl-time 403s, but mark it speculative.
        speculative = True
    else:
        speculative = False
    label = "victim_account" if not speculative else "victim_account_speculative"
    tokens.append(BypassToken(
        label=label,
        source="idor_account_b",
        headers=dict(account_b.headers),
        evidence=f"account B ({account_b.username or account_b.email or 'anonymous'}) headers"
                 + (" (no IDOR confirmed — speculative replay)" if speculative else ""),
    ))
    return tokens
