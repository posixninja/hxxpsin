"""
file_grabber.py — Bulk-download discovered binary files for offline analysis.

The Playwright crawler skips binary URLs (PDFs, KDBX, archives, images) because
the browser can't render them and tries to download them as page navigations.
That's the right call for browser-side rendering, but those files are recon
goldmines: leaked PDFs, KeePass databases, .bak SQL dumps, source archives,
images with EXIF/steganography/SVG XSS payloads.

This module runs as a post-crawl pass over ALL discovered URLs (collector,
stackprint interesting_paths, crawl_skipped) and saves any URL with a
downloadable extension to `<out>/downloads/<sanitized-basename>` for the
operator to inspect later.

Pipeline position: after crawl + stackprint, before classify.
Always-on (no flag) — it's pure I/O, no exploitation.

Cross-framework: the filter is by file extension only, not URL path or app
identity, so it works against any web target.
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx


# Extensions worth saving locally for offline analysis. Pure file-extension
# filter — no app-specific paths — so this works against any target.
_DOWNLOAD_SUFFIXES = {
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf",
    # Archives
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz",
    # Backups / databases (huge IOC value)
    ".bak", ".old", ".sql", ".dump", ".db", ".sqlite", ".sqlite3",
    # Credentials / keys
    ".kdbx", ".pem", ".key", ".pfx", ".p12", ".crt", ".cer", ".csr", ".asc",
    # Logs / data exports
    ".log", ".csv", ".tsv",
    # Binaries
    ".exe", ".dmg", ".iso", ".img", ".apk", ".ipa",
    ".deb", ".rpm", ".jar", ".war", ".ear",
    # Images — EXIF metadata, steganography, SVG XSS payloads, leaked screenshots
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp",
    ".tiff", ".tif", ".ico", ".heic", ".heif", ".avif",
    # Audio/video — sometimes used for exfil or stego
    ".mp3", ".wav", ".mp4", ".mov", ".webm",
    # Markdown / leaked text (Juice Shop /ftp/ ships .md.bak files)
    ".md", ".markdown",
    # Other
    ".env", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml",
}


# Filename basename sanitizer — keep alnum + a few safe punctuation chars
_BASENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class GrabbedFile:
    url: str
    path: str          # local saved path
    bytes: int
    sha256: str
    content_type: str
    extension: str

    def to_dict(self) -> dict:
        return {
            "url": self.url, "path": self.path, "bytes": self.bytes,
            "sha256": self.sha256, "content_type": self.content_type,
            "extension": self.extension,
        }


@dataclass
class FileGrabResult:
    grabbed: list[GrabbedFile] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    candidates_seen: int = 0
    skipped_oversize: int = 0
    out_dir: str = ""

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "candidates_seen": self.candidates_seen,
            "total_grabbed": len(self.grabbed),
            "total_failed": len(self.failed),
            "skipped_oversize": self.skipped_oversize,
            "files": [g.to_dict() for g in self.grabbed],
            "failures": self.failed[:30],
        }

    @property
    def total_bytes(self) -> int:
        return sum(g.bytes for g in self.grabbed)

    def by_extension(self) -> dict[str, int]:
        """Count of grabs per extension — handy for the report header."""
        out: dict[str, int] = {}
        for g in self.grabbed:
            out[g.extension] = out.get(g.extension, 0) + 1
        return out


class FileGrabber:
    """Concurrent file downloader with per-file size cap, total-count cap,
    and content-type sanity check. Idempotent — duplicate URLs land in the
    same on-disk file (sha256-suffixed if collision)."""

    def __init__(
        self,
        out_dir: str,
        max_bytes_per_file: int = 10 * 1024 * 1024,   # 10 MB
        max_files: int = 200,
        concurrency: int = 8,
        timeout: float = 12.0,
    ):
        self.out_dir = Path(out_dir) / "downloads"
        self.max_bytes_per_file = max_bytes_per_file
        self.max_files = max_files
        self.concurrency = concurrency
        self.timeout = timeout

    async def run(
        self,
        urls,                          # iterable of str URLs
        auth_headers: Optional[dict] = None,
    ) -> FileGrabResult:
        result = FileGrabResult(out_dir=str(self.out_dir))
        # First, expand any directory-listing URLs into the files they expose.
        # Adds /ftp/eastere.gg, /uploads/leaked.bak, etc. without requiring
        # an extension whitelist.
        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "hxxpsin-grabber/1.0", **(auth_headers or {})},
        ) as discover_client:
            expanded = await self._expand_directory_listings(
                discover_client, list(urls),
            )
        candidates = self._filter(expanded)
        result.candidates_seen = len(candidates)
        if not candidates:
            return result

        self.out_dir.mkdir(parents=True, exist_ok=True)

        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "hxxpsin-grabber/1.0", **(auth_headers or {})},
        ) as client:
            async def grab(url: str):
                async with sem:
                    return await self._download(client, url)

            outcomes = await asyncio.gather(
                *[grab(u) for u in candidates[:self.max_files]],
                return_exceptions=True,
            )

        for outcome in outcomes:
            if isinstance(outcome, GrabbedFile):
                result.grabbed.append(outcome)
            elif isinstance(outcome, dict):
                if outcome.get("oversize"):
                    result.skipped_oversize += 1
                result.failed.append(outcome)

        return result

    # Match Apache "Index of /<path>" + Express directory plugin + nginx
    # autoindex listings. Captures every <a href="..."> linking a relative file.
    _DIR_LISTING_TITLE_RE = re.compile(
        r"(?i)(<title>\s*Index of\s|<h1>\s*Index of\s|<title>\s*listing directory\s)"
    )
    _HREF_RE = re.compile(r'href\s*=\s*["\']([^"\'#?]+)["\']', re.IGNORECASE)

    async def _expand_directory_listings(self, client: httpx.AsyncClient,
                                         urls: list[str]) -> list[str]:
        """For every URL whose response is a directory-listing HTML page,
        pull out the child file URLs and add them to the candidate list.
        Pure recon — doesn't recurse into sub-directory listings (keeps the
        budget bounded)."""
        expanded: list[str] = list(urls)
        seen: set[str] = set()
        # Only probe URLs whose path looks like a directory: trailing slash
        # OR ends in a typical directory-server-style path with no extension.
        candidates_to_probe: list[str] = []
        for u in urls:
            if not isinstance(u, str) or not u.startswith(("http://", "https://")):
                continue
            if u in seen:
                continue
            seen.add(u)
            path = urlparse(u).path or ""
            if path.endswith("/") or (path and "." not in Path(path).name):
                candidates_to_probe.append(u)
        for url in candidates_to_probe[:30]:  # cap probe count
            # Always probe with a trailing slash. Some directory plugins
            # (Express's serve-index) use the request URL as the href
            # prefix — so GET /ftp produces hrefs like 'ftp/eastere.gg',
            # while GET /ftp/ produces clean 'eastere.gg'. Forcing the
            # trailing slash gives us a uniform base for urljoin.
            probe_url = url if url.endswith("/") else url + "/"
            try:
                r = await client.get(probe_url)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "").lower()
            body = r.text[:200000]
            if "html" not in ct or not self._DIR_LISTING_TITLE_RE.search(body):
                continue
            base = probe_url
            # Defensive: even with the slash forced, some servers still emit
            # hrefs prefixed with the dir name. Strip the leading directory
            # segment from any href that duplicates it.
            base_path = urlparse(base).path
            base_dirname = base_path.rstrip("/").rsplit("/", 1)[-1]
            for m in self._HREF_RE.finditer(body):
                href = m.group(1).strip()
                if not href or href in (".", "..") or href.startswith(("?", "/", "#")):
                    continue
                if href.startswith(("http://", "https://")):
                    expanded.append(href)
                    continue
                # Strip duplicated directory prefix: base=/ftp/, href=ftp/file → file
                if base_dirname and href.startswith(base_dirname + "/"):
                    href = href[len(base_dirname) + 1:]
                expanded.append(urljoin(base, href))
        return expanded

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    # Path/extension deny-list — URLs we know aren't worth downloading because
    # they're either dynamic API surface (caught by other tools) or empty/
    # tracking artifacts. Downloading them only wastes our budget.
    _SKIP_PATH_PREFIXES = (
        "/api/", "/rest/", "/graphql", "/_next/data/", "/__nuxt/",
        "/oauth/", "/oidc/", "/.well-known/openid",
        "/health", "/ready", "/livez", "/metrics", "/actuator/",
    )
    _SKIP_EXT = frozenset({
        ".html", ".htm",  # SPA shells; the body is just the bootstrap, not a leaked doc
    })
    _SKIP_BASENAMES = frozenset({
        "favicon.ico",  # 1x1-style noise we already see everywhere
    })

    @staticmethod
    def _bypass_variants(url: str) -> list[str]:
        """Generate extension-blocklist bypass variants for a URL. Useful for
        files servers refuse to serve based on suffix (e.g. Juice Shop's
        /ftp/eastere.gg → 403, but /ftp/eastere.gg%2500.md → 200).
        Returns variants in priority order."""
        # Don't bypass URLs that already have a query / fragment / encoded NUL
        if "?" in url or "#" in url or "%2500" in url or "%00" in url:
            return []
        return [
            url + "%2500.md",     # URL-encoded NUL byte + harmless ext (canonical)
            url + "%2500.png",
            url + "%00.md",       # raw NUL
            url + ";.md",         # path-parameter trick
            url + ".bak",         # backup-suffix trick
            url + "?",            # trailing question mark (some routers strip)
        ]

    @staticmethod
    def _filter(urls) -> list[str]:
        """Dedup + light deny-list. Suffix is NOT used as a whitelist — any
        URL not on the deny-list gets a download attempt. The actual download
        path skips empty bodies and oversize content downstream."""
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            if not isinstance(u, str) or not u.startswith(("http://", "https://")):
                continue
            key = u.split("?", 1)[0].split("#", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            path = urlparse(u).path or ""
            path_l = path.lower()
            if not path or path == "/":
                continue
            if any(path_l.startswith(p) for p in FileGrabber._SKIP_PATH_PREFIXES):
                continue
            ext = Path(path).suffix.lower()
            if ext in FileGrabber._SKIP_EXT:
                continue
            basename = Path(path).name.lower()
            if basename in FileGrabber._SKIP_BASENAMES:
                continue
            out.append(u)
        return out

    # ------------------------------------------------------------------
    # Single download
    # ------------------------------------------------------------------

    async def _download(self, client: httpx.AsyncClient, url: str):
        # HEAD first to short-circuit oversize files. Some servers don't
        # support HEAD or don't set Content-Length, so we fall through to
        # a streamed GET with a hard byte cap.
        try:
            head = await client.head(url)
            cl = head.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > self.max_bytes_per_file:
                return {"url": url, "reason": f"oversize ({cl} bytes per HEAD)",
                        "oversize": True}
        except httpx.HTTPError:
            pass  # HEAD failed — proceed to GET

        # Try the original URL, then a small set of extension-bypass variants
        # if it 403/415s. Many file servers blocklist by extension but accept
        # the same path with: a trailing null-byte+harmless extension, query
        # suffix, or backup-style suffix.
        urls_to_try = [url] + self._bypass_variants(url)
        attempted: list[tuple[str, int]] = []
        content: bytes = b""
        content_type = ""
        actual_url = url
        for try_url in urls_to_try:
            try:
                buf = bytearray()
                async with client.stream("GET", try_url) as resp:
                    if resp.status_code != 200:
                        attempted.append((try_url, resp.status_code))
                        continue
                    content_type = resp.headers.get("content-type", "")
                    async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                        buf.extend(chunk)
                        if len(buf) > self.max_bytes_per_file:
                            return {"url": try_url,
                                    "reason": f"oversize (>{self.max_bytes_per_file} during stream)",
                                    "oversize": True}
                content = bytes(buf)
                actual_url = try_url
                break
            except httpx.HTTPError as e:
                attempted.append((try_url, -1))
                continue
            except Exception as e:
                return {"url": try_url, "reason": f"error: {type(e).__name__}: {e}"}

        if not content:
            last_status = attempted[-1][1] if attempted else "?"
            return {"url": url, "reason": f"all attempts failed (final status {last_status})",
                    "tried": [{"url": u, "status": s} for u, s in attempted]}

        # Build a safe local filename — preserve the ORIGINAL URL's basename
        # (not the bypass variant's), since that's what the operator will
        # recognise. eastere.gg stays "eastere.gg" even when fetched via
        # eastere.gg%2500.md.
        parsed = urlparse(url)
        basename = Path(parsed.path).name or "index"
        basename = _BASENAME_SANITIZE_RE.sub("_", basename)[:160]
        if not basename:
            basename = "file"
        local = self.out_dir / basename

        # Collision handling — if the file exists with different content,
        # append the sha256 prefix so we don't clobber.
        sha = hashlib.sha256(content).hexdigest()
        if local.exists():
            try:
                existing = local.read_bytes()
                if hashlib.sha256(existing).hexdigest() != sha:
                    local = self.out_dir / f"{local.stem}-{sha[:8]}{local.suffix}"
            except Exception:
                local = self.out_dir / f"{local.stem}-{sha[:8]}{local.suffix}"

        try:
            local.write_bytes(content)
        except Exception as e:
            return {"url": url, "reason": f"write_error: {type(e).__name__}: {e}"}

        return GrabbedFile(
            url=url, path=str(local), bytes=len(content), sha256=sha,
            content_type=content_type, extension=Path(basename).suffix.lower(),
        )
