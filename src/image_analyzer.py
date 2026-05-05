"""
image_analyzer.py — EXIF metadata + lightweight steganography heuristics.

Runs over images that FileGrabber already saved to <out>/downloads/. For each
image:
  1. EXIF + IPTC + XMP metadata via the system `exiftool` binary (JSON output).
     Captures GPS coords, camera make/model, software, original timestamps,
     copyright, author, and any custom XMP fields the uploader embedded.
  2. Trailing-byte sweep — bytes appended after the image's EOF marker
     (PNG `IEND`, JPEG `FFD9`, GIF `;`). Stego tools and "polyglot" files
     hide payloads here.
  3. Magic-byte sweep on the trailing data — detects appended ZIP/PK,
     RAR, 7z, PDF, ELF, Mach-O, PE, KDBX, etc.
  4. ASCII strings extraction via the `strings` binary, filtered to lines
     >= 8 chars. Useful for spotting embedded credentials, comments, file
     paths, or hidden notes.

No Python library deps — shells out to `exiftool` and `strings` (both
ubiquitous on macOS/Linux). Gracefully no-ops if either is missing.

This is NOT a full steganalysis suite (no LSB statistical tests). It catches
the 90% of file-based steganography that uses the trivial "append payload
after EOF" trick — which is what most CTFs and many real-world dead-drops
actually use.
"""

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Image EOF markers — bytes after these are "trailing" and worth flagging.
_PNG_END = b"\x49\x45\x4e\x44\xae\x42\x60\x82"   # IEND chunk + CRC
_JPEG_END = b"\xff\xd9"                          # JPEG EOI marker
_GIF_END = b"\x3b"                               # GIF trailer
_BMP_NO_EOF = True                               # BMP has no trailer; size-bound only
_WEBP_RIFF_HEADER = b"RIFF"

# Magic bytes worth flagging when found embedded in an image
_EMBEDDED_MAGIC = {
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip_empty",
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x1f\x8b\x08": "gzip",
    b"BZh": "bzip2",
    b"%PDF-": "pdf",
    b"\x7fELF": "elf",
    b"\xcf\xfa\xed\xfe": "mach_o_64",
    b"MZ": "pe_executable",
    b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5": "kdbx_v2",  # KeePass v2
    b"\x9a\xa2\xd9\x03": "kdbx_v1",
    b"-----BEGIN": "pem_block",
    b"ssh-rsa ": "openssh_pubkey",
    b"ssh-ed25519 ": "openssh_ed25519_pubkey",
}

# Strings filter — only keep lines that look like they could be useful
_STRINGS_MIN_LEN = 8
_STRINGS_MAX_LINES = 500


@dataclass
class ImageAnalysis:
    file_path: str
    file_size: int = 0
    sha256: str = ""
    exif: dict = field(default_factory=dict)
    gps: dict = field(default_factory=dict)
    trailing_bytes: int = 0
    trailing_magic: list[str] = field(default_factory=list)
    embedded_offsets: list[dict] = field(default_factory=list)  # {magic, offset}
    interesting_strings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        return bool(self.trailing_magic or self.embedded_offsets
                    or self.gps or self.trailing_bytes > 64)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "exif": self.exif,
            "gps": self.gps,
            "trailing_bytes": self.trailing_bytes,
            "trailing_magic": self.trailing_magic,
            "embedded_offsets": self.embedded_offsets,
            "interesting_strings": self.interesting_strings,
            "notes": self.notes,
            "has_anomalies": self.has_anomalies,
        }


def analyze(file_path: str) -> ImageAnalysis:
    """Run EXIF + trailing-byte + strings analysis on one image. Returns an
    ImageAnalysis record. Best-effort: missing tools are reported in notes."""
    p = Path(file_path)
    a = ImageAnalysis(file_path=str(p))
    if not p.exists() or not p.is_file():
        a.notes.append("file missing")
        return a
    try:
        data = p.read_bytes()
    except Exception as exc:
        a.notes.append(f"read failed: {exc}")
        return a
    a.file_size = len(data)
    a.sha256 = hashlib.sha256(data).hexdigest()

    a.exif, a.gps = _extract_exif(p, a.notes)
    a.trailing_bytes, a.trailing_magic = _detect_trailing(data, a.notes)
    a.embedded_offsets = _scan_embedded_magic(data)
    a.interesting_strings = _extract_strings(p, a.notes)

    return a


# ---------------------------------------------------------------------------
# EXIF — shell out to exiftool for richest output (PIL would also work but
# adds a dependency; exiftool is already on most ops boxes).
# ---------------------------------------------------------------------------

def _extract_exif(path: Path, notes: list[str]) -> tuple[dict, dict]:
    if not shutil.which("exiftool"):
        notes.append("exiftool not installed — EXIF skipped")
        return {}, {}
    try:
        cp = subprocess.run(
            ["exiftool", "-j", "-n", "-q", str(path)],
            capture_output=True, timeout=8,
        )
        if cp.returncode != 0:
            notes.append(f"exiftool returned {cp.returncode}")
            return {}, {}
        out = cp.stdout.decode("utf-8", errors="replace")
        parsed = json.loads(out)
        if not parsed:
            return {}, {}
        raw = parsed[0]
    except Exception as exc:
        notes.append(f"exiftool failed: {type(exc).__name__}: {exc}")
        return {}, {}

    # Strip noisy housekeeping fields; keep operationally interesting ones
    drop_keys = {
        "SourceFile", "ExifToolVersion", "FileName", "Directory",
        "FilePermissions", "FileAccessDate", "FileInodeChangeDate",
        "FileModifyDate", "FileTypeExtension", "FileSize", "FileType",
        "MIMEType",
    }
    exif: dict = {}
    gps: dict = {}
    for k, v in raw.items():
        if k in drop_keys:
            continue
        if k.startswith("GPS") or k in ("Latitude", "Longitude", "Altitude"):
            gps[k] = v
        else:
            exif[k] = v
    return exif, gps


# ---------------------------------------------------------------------------
# Trailing-byte scan — payload appended past the image's EOF marker
# ---------------------------------------------------------------------------

def _detect_trailing(data: bytes, notes: list[str]) -> tuple[int, list[str]]:
    if data.startswith(b"\x89PNG"):
        idx = data.rfind(_PNG_END)
        if idx < 0:
            notes.append("PNG IEND not found — corrupt or non-standard PNG")
            return 0, []
        end = idx + len(_PNG_END)
    elif data.startswith(b"\xff\xd8"):
        idx = data.rfind(_JPEG_END)
        if idx < 0:
            notes.append("JPEG EOI not found — corrupt")
            return 0, []
        end = idx + len(_JPEG_END)
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        idx = data.rfind(_GIF_END)
        if idx < 0:
            return 0, []
        end = idx + 1
    elif data.startswith(b"BM"):
        # BMP encodes its own length in header — anything past header_size is suspect
        if len(data) < 6:
            return 0, []
        try:
            declared = int.from_bytes(data[2:6], "little")
            if declared and declared < len(data):
                end = declared
            else:
                return 0, []
        except Exception:
            return 0, []
    elif data.startswith(_WEBP_RIFF_HEADER):
        # WebP encodes length in header
        if len(data) < 8:
            return 0, []
        try:
            declared = int.from_bytes(data[4:8], "little") + 8  # RIFF chunk header
            if declared < len(data):
                end = declared
            else:
                return 0, []
        except Exception:
            return 0, []
    else:
        return 0, []

    trailing = data[end:]
    if not trailing:
        return 0, []
    magic = []
    for sig, label in _EMBEDDED_MAGIC.items():
        if trailing.startswith(sig):
            magic.append(label)
    return len(trailing), magic


# ---------------------------------------------------------------------------
# Magic byte sweep — find embedded payloads ANYWHERE in the file (not just
# trailing). Catches polyglots and embedded archives.
# ---------------------------------------------------------------------------

def _scan_embedded_magic(data: bytes) -> list[dict]:
    out: list[dict] = []
    # Skip the first 64 bytes (image header naturally contains some sigs)
    for sig, label in _EMBEDDED_MAGIC.items():
        idx = 64
        while True:
            found = data.find(sig, idx)
            if found < 0 or len(out) >= 50:
                break
            out.append({"magic": label, "offset": found, "sig_hex": sig.hex()})
            idx = found + len(sig)
    return out


# ---------------------------------------------------------------------------
# Strings extraction — printable ASCII runs >= 8 chars, filtered for noise
# ---------------------------------------------------------------------------

def _extract_strings(path: Path, notes: list[str]) -> list[str]:
    if not shutil.which("strings"):
        notes.append("`strings` binary not found — string extraction skipped")
        return []
    try:
        cp = subprocess.run(
            ["strings", "-n", str(_STRINGS_MIN_LEN), str(path)],
            capture_output=True, timeout=8,
        )
        if cp.returncode != 0:
            return []
        lines = cp.stdout.decode("utf-8", errors="replace").splitlines()
    except Exception as exc:
        notes.append(f"strings failed: {type(exc).__name__}: {exc}")
        return []

    # Filter to "interesting" strings — those with at least one of:
    # url-shaped, email-shaped, contains slash (path/comment),
    # contains keyword (password/secret/token/flag/key/admin)
    keywords = ("password", "secret", "token", "flag", "api_key", "apikey",
                "admin", "private", "ssh", "AKIA", "BEGIN ", "Bearer ",
                "http://", "https://", "@", "/", "\\", "..")
    seen: set[str] = set()
    keep: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line in seen:
            continue
        if any(kw in line for kw in keywords):
            seen.add(line)
            keep.append(line[:200])
            if len(keep) >= _STRINGS_MAX_LINES:
                break
    return keep
