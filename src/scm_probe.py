"""
scm_probe.py — Stage 0 probe for source-code management leaks and
configuration-file exposure (.git/.svn/.hg/.bzr/CVS/.DS_Store/.env/
lockfiles/wp-config backups).

Pipeline position: early — runs against the target root and every
top-level subdirectory discovered by the crawler. Findings are written
to ``out/scm_probe/`` and feed two downstream consumers:

  1. [[file_grabber]] — when ``.git/HEAD`` is confirmed, queue
     ``.git/objects/`` for offline ``git fsck`` recovery.
  2. [[secrets]] — every ``.env*`` body is scanned through the unified
     catalog; credential matches surface in the Reporter alongside the
     SCM finding.

Confirmation is shape-aware: status==200 alone is insufficient because
SPA shells and soft-404s return 200 with HTML. Each path carries a
``body_match`` regex/substring that the response body must satisfy.

The module reuses:
  - HTTP client pattern from [[sql_dump]] / [[ldap_dump]]
  - Soft-404 baseline approach from [[verifier]] (we record baseline len
    on a known-404 path and reject responses that match it).
  - Output layout convention from [[sql_dump]] / [[ldap_dump]].
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx


# ---------------------------------------------------------------------------
# Path catalog — each entry: path, kind, body_match (regex), severity, note
# ---------------------------------------------------------------------------

@dataclass
class _ProbePath:
    path: str
    kind: str               # git | svn | hg | bzr | cvs | ds_store | lockfile
                            # | env | apache | iis | wordpress | misc | phpinfo
    body_match: re.Pattern  # body MUST match for confirmation
    severity: str           # critical | high | medium | low | info
    note: str = ""


_PATHS: list[_ProbePath] = [
    # Git
    _ProbePath(".git/HEAD",        "git",
               re.compile(r"^ref:\s+refs/", re.MULTILINE),
               "critical", "Git HEAD reference exposed — repo fully recoverable"),
    _ProbePath(".git/config",      "git",
               re.compile(r"\[core\]"),
               "critical", "Git config exposed — may contain remote URLs with creds"),
    _ProbePath(".git/index",       "git",
               re.compile(rb"^DIRC", re.DOTALL),
               "critical", "Git index file exposed"),
    _ProbePath(".git/logs/HEAD",   "git",
               re.compile(r"[0-9a-f]{40}\s+[0-9a-f]{40}"),
               "high", "Git reflog exposed — commit history visible"),
    _ProbePath(".git/refs/heads/main", "git",
               re.compile(r"^[0-9a-f]{40}\s*$"),
               "high", "Git branch ref exposed"),
    _ProbePath(".git/refs/heads/master", "git",
               re.compile(r"^[0-9a-f]{40}\s*$"),
               "high", "Git branch ref exposed"),
    _ProbePath(".git/packed-refs", "git",
               re.compile(r"#\s+pack-refs|^[0-9a-f]{40}\s+refs/", re.MULTILINE),
               "high", "Git packed refs exposed"),

    # Subversion
    _ProbePath(".svn/entries",     "svn",
               re.compile(r"^\d+\s*$|file://|svn://"),
               "critical", "SVN entries file exposed"),
    _ProbePath(".svn/wc.db",       "svn",
               re.compile(rb"SQLite format", re.DOTALL),
               "critical", "SVN working-copy DB exposed"),

    # Mercurial
    _ProbePath(".hg/store/00manifest.i", "hg",
               re.compile(rb"\x00", re.DOTALL),
               "high", "Mercurial store manifest exposed"),
    _ProbePath(".hg/dirstate",     "hg",
               re.compile(rb".", re.DOTALL),
               "high", "Mercurial dirstate exposed"),
    _ProbePath(".hg/hgrc",         "hg",
               re.compile(r"\[paths\]|\[ui\]"),
               "high", "Mercurial config exposed"),

    # Bazaar
    _ProbePath(".bzr/branch/branch.conf", "bzr",
               re.compile(r"parent_location|push_location"),
               "high", "Bazaar branch config exposed"),

    # CVS
    _ProbePath("CVS/Entries",      "cvs",
               re.compile(r"^/", re.MULTILINE),
               "high", "CVS Entries exposed"),
    _ProbePath("CVS/Root",         "cvs",
               re.compile(r":pserver:|:ext:|:local:"),
               "high", "CVS Root exposed"),

    # .DS_Store — leaks directory listings
    _ProbePath(".DS_Store",        "ds_store",
               re.compile(rb"\x00\x00\x00\x01Bud1", re.DOTALL),
               "medium", "macOS .DS_Store exposed — directory contents leaked"),

    # Env files
    _ProbePath(".env",             "env",
               re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
               "critical", ".env file exposed"),
    _ProbePath(".env.local",       "env",
               re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
               "critical", ".env.local exposed"),
    _ProbePath(".env.production",  "env",
               re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
               "critical", ".env.production exposed"),
    _ProbePath(".env.backup",      "env",
               re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
               "critical", ".env.backup exposed"),
    _ProbePath(".env.example",     "env",
               re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE),
               "low", ".env.example exposed (sample only)"),

    # Lockfiles
    _ProbePath("composer.lock",    "lockfile",
               re.compile(r'"packages"\s*:'),
               "medium", "composer.lock exposed — dependency tree visible"),
    _ProbePath("composer.json",    "lockfile",
               re.compile(r'"require"\s*:|"name"\s*:'),
               "low", "composer.json exposed"),
    _ProbePath("package-lock.json", "lockfile",
               re.compile(r'"lockfileVersion"\s*:'),
               "low", "package-lock.json exposed"),
    _ProbePath("yarn.lock",        "lockfile",
               re.compile(r"# yarn lockfile|^\".+@", re.MULTILINE),
               "low", "yarn.lock exposed"),
    _ProbePath("pnpm-lock.yaml",   "lockfile",
               re.compile(r"^lockfileVersion:", re.MULTILINE),
               "low", "pnpm-lock.yaml exposed"),
    _ProbePath("Gemfile.lock",     "lockfile",
               re.compile(r"^GEM\b|^DEPENDENCIES\b", re.MULTILINE),
               "low", "Gemfile.lock exposed"),
    _ProbePath("Pipfile.lock",     "lockfile",
               re.compile(r'"_meta"\s*:'),
               "low", "Pipfile.lock exposed"),
    _ProbePath("poetry.lock",      "lockfile",
               re.compile(r"^\[\[package\]\]", re.MULTILINE),
               "low", "poetry.lock exposed"),

    # PHP info / debug
    _ProbePath("phpinfo.php",      "phpinfo",
               re.compile(r"PHP Version|phpinfo\(\)"),
               "high", "phpinfo() output exposed"),
    _ProbePath("info.php",         "phpinfo",
               re.compile(r"PHP Version|phpinfo\(\)"),
               "high", "phpinfo() output exposed"),
    _ProbePath("test.php",         "phpinfo",
               re.compile(r"PHP Version|phpinfo\(\)"),
               "high", "PHP test page exposed"),

    # Apache / IIS configuration
    _ProbePath(".htaccess",        "apache",
               re.compile(r"RewriteRule|<Directory|AuthType", re.IGNORECASE),
               "medium", ".htaccess exposed"),
    _ProbePath(".htpasswd",        "apache",
               re.compile(r"^[A-Za-z0-9_]+:", re.MULTILINE),
               "critical", ".htpasswd exposed — credentials hashed but readable"),
    _ProbePath("web.config",       "iis",
               re.compile(r"<configuration>"),
               "high", "IIS web.config exposed"),

    # WordPress backups
    _ProbePath("wp-config.php.bak", "wordpress",
               re.compile(r"DB_NAME|DB_PASSWORD|AUTH_KEY"),
               "critical", "WordPress config backup exposed — DB creds present"),
    _ProbePath("wp-config.php~",   "wordpress",
               re.compile(r"DB_NAME|DB_PASSWORD|AUTH_KEY"),
               "critical", "WordPress config backup exposed"),
    _ProbePath("wp-config.php.swp", "wordpress",
               re.compile(rb"b0VIM", re.DOTALL),
               "critical", "WordPress vim swap file exposed"),
    _ProbePath("wp-config.php.save", "wordpress",
               re.compile(r"DB_NAME|DB_PASSWORD"),
               "critical", "WordPress config save backup exposed"),

    # Deployment / IDE config
    _ProbePath("sftp-config.json", "misc",
               re.compile(r'"host"\s*:|"user"\s*:|"password"\s*:'),
               "high", "SFTP config exposed — SSH creds possible"),
    _ProbePath(".deployment-config.json", "misc",
               re.compile(r'"host"\s*:|"deploy"'),
               "high", "deployment config exposed"),
    _ProbePath(".idea/workspace.xml", "misc",
               re.compile(r"<project|<component", re.IGNORECASE),
               "low", "JetBrains IDE workspace exposed"),
    _ProbePath(".vscode/settings.json", "misc",
               re.compile(r"^\s*\{"),
               "low", "VSCode workspace settings exposed"),

    # Editor / VCS metadata
    _ProbePath(".gitignore",       "misc",
               re.compile(r"^\s*[^#\s]", re.MULTILINE),
               "info", ".gitignore exposed — confirms project structure"),
    _ProbePath(".editorconfig",    "misc",
               re.compile(r"\[\*|\bindent_style\b"),
               "info", ".editorconfig exposed"),
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SCMFinding:
    url: str
    kind: str
    path: str
    severity: str
    confidence: float
    evidence: str
    note: str = ""
    body_preview: str = ""
    secret_kinds_in_body: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "kind": self.kind,
            "path": self.path,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "note": self.note,
            "body_preview": self.body_preview[:200],
            "secret_kinds_in_body": self.secret_kinds_in_body,
        }


@dataclass
class SCMProbeResult:
    paths_probed: int = 0
    bases_probed: int = 0
    findings: list[SCMFinding] = field(default_factory=list)
    out_dir: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def critical(self) -> list[SCMFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "paths_probed": self.paths_probed,
            "bases_probed": self.bases_probed,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class SCMProbe:
    _CONCURRENCY = 8
    _MAX_BASES = 12      # cap subdir probes to keep loud-recon bounded
    _BODY_PREVIEW_BYTES = 512

    def __init__(self, out_dir: str = "", timeout: float = 8.0,
                 auth_headers: Optional[dict] = None):
        self.out_root = Path(out_dir) / "scm_probe" if out_dir else None
        self.timeout = timeout
        self.auth_headers = auth_headers or {}

    async def run(self, target: str,
                  extra_bases: Optional[list[str]] = None) -> SCMProbeResult:
        """Probe ``target`` (and ``extra_bases``) for every SCM/config path.

        ``extra_bases`` should be subpaths discovered via crawling
        (e.g. ``/admin/``, ``/api/``) — we probe each as a separate base
        in case the application is mounted under a subpath."""
        result = SCMProbeResult(
            out_dir=str(self.out_root) if self.out_root else "",
        )
        bases = self._normalize_bases(target, extra_bases or [])
        result.bases_probed = len(bases)
        if not bases:
            result.notes.append("no probe bases derived from target")
            return result

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=False,
            headers=self.auth_headers,
        ) as client:
            # Soft-404 calibration: hit a known-bogus path under each base.
            # If the soft-404 body itself matches a probe's body_match regex
            # (rare — only happens with overly-loose shapes), we skip that
            # probe for that base. We do NOT length-compare: real .git/HEAD
            # is ~21 bytes, real 404 pages vary, and length-matching false-
            # rejects legitimate hits. body_match is the truth.
            soft_404_bodies = await self._calibrate_soft_404(client, bases)

            tasks = []
            for base in bases:
                soft_body = soft_404_bodies.get(base, b"")
                for probe in _PATHS:
                    # Skip when the soft-404 body itself matches the probe's
                    # shape regex — that means the regex would over-match
                    # against this target. Conservative; usually a no-op.
                    if soft_body and self._matches_shape(soft_body, probe):
                        continue
                    tasks.append(self._probe_one(client, base, probe))
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, SCMFinding):
                    result.findings.append(outcome)
            result.paths_probed = len(tasks)

        # Sort: critical first, then by severity rank
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.findings.sort(key=lambda f: sev_rank.get(f.severity, 9))

        if self.out_root and result.findings:
            self._persist(result)

        return result

    @staticmethod
    def _normalize_bases(target: str, extras: list[str]) -> list[str]:
        """Return distinct origin+base URLs ending with ``/``."""
        parsed = urlparse(target)
        if not parsed.scheme:
            return []
        origin = f"{parsed.scheme}://{parsed.netloc}"
        bases: list[str] = [origin + "/"]
        seen = {origin + "/"}
        for extra in extras[:SCMProbe._MAX_BASES]:
            # Accept full URLs (same origin) OR path-only inputs
            if extra.startswith("http"):
                p = urlparse(extra)
                if p.netloc != parsed.netloc:
                    continue
                path = p.path
            else:
                path = extra
            if not path.endswith("/"):
                # Trim to nearest segment so we probe directories not files
                path = path.rsplit("/", 1)[0] + "/"
            url = urljoin(origin + "/", path.lstrip("/"))
            if url not in seen:
                seen.add(url)
                bases.append(url)
        return bases

    async def _calibrate_soft_404(self, client,
                                   bases: list[str]) -> dict[str, bytes]:
        """For each base, fetch a known-bogus path and record the response
        body so we can later check whether a probe's body_match regex
        also matches the soft-404 (which would mean it'd over-match)."""
        out: dict[str, bytes] = {}
        tasks = [client.get(b + "hxxpsin_soft404_canary_xyz") for b in bases]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for base, r in zip(bases, results):
            if isinstance(r, Exception):
                continue
            if r.status_code == 200:
                # Only record as soft-404 if status is 200 — SPA shells.
                # Real 404 responses can be ignored for shape comparison.
                out[base] = r.content or b""
        return out

    @staticmethod
    def _matches_shape(body: bytes, probe: _ProbePath) -> bool:
        """True if ``body`` matches probe.body_match. Handles bytes-pattern
        and str-pattern regexes transparently."""
        target = (
            body if isinstance(probe.body_match.pattern, bytes)
            else body.decode("utf-8", "replace")
        )
        return bool(probe.body_match.search(target))

    async def _probe_one(self, client, base: str,
                         probe: _ProbePath) -> Optional[SCMFinding]:
        url = urljoin(base, probe.path)
        try:
            r = await client.get(url)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        body = r.content
        if not body:
            return None
        if not self._matches_shape(body, probe):
            return None

        # Scan body for credential-shaped strings (env files / wp-config
        # backups / .htpasswd are the highest-yield carriers).
        secret_kinds: list[str] = []
        try:
            import secrets as _secrets
            text_body = body.decode("utf-8", "replace")
            for s in _secrets.scan(text_body):
                if not s.public_by_design and s.kind not in secret_kinds:
                    secret_kinds.append(s.kind)
        except Exception:
            pass

        confidence = 0.95 if probe.severity in ("critical", "high") else 0.8
        evidence = f"{probe.kind}: shape-matched response at {probe.path}"
        if secret_kinds:
            evidence += f" — body carries: {', '.join(secret_kinds[:5])}"

        preview = body[:self._BODY_PREVIEW_BYTES].decode(
            "utf-8", "replace",
        )
        return SCMFinding(
            url=url, kind=probe.kind, path=probe.path,
            severity=probe.severity, confidence=confidence,
            evidence=evidence, note=probe.note,
            body_preview=preview,
            secret_kinds_in_body=secret_kinds,
        )

    def _persist(self, result: SCMProbeResult) -> None:
        self.out_root.mkdir(parents=True, exist_ok=True)
        (self.out_root / "findings.json").write_text(
            json.dumps([f.to_dict() for f in result.findings], indent=2)
        )
        if result.critical:
            (self.out_root / "critical.json").write_text(
                json.dumps([f.to_dict() for f in result.critical], indent=2)
            )


__all__ = ["SCMProbe", "SCMProbeResult", "SCMFinding"]
