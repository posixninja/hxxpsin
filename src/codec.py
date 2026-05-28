"""
codec.py — Unified payload encoding/decoding for hxxpsin.

Three audiences:
  - recon_collector recipes (deterministic probe expansion: try a payload raw
    AND url-double-encoded AND unicode-escaped in one shot)
  - nuclei_gen (bake encoded payload variants into generated YAML templates)
  - challenge_solver LLM tool (so Claude/Ollama can ask for variants when the
    raw form is filtered)

Five public primitives:
  encode(value, scheme)              — apply ONE scheme, return str
  decode(value, scheme)              — reverse ONE scheme, return str|bytes
  variants(value, schemes, chain)    — apply MANY schemes, return labeled list
  detect(value)                      — ranked guesses at what `value` is
  try_decode_all(value, max_depth)   — recursive decode through nested layers
  jwt_split(token)                   — delegates to jwt_attack._split_token
  list_schemes()                     — name list for the LLM tool schema

All schemes are stdlib-only. JWT helpers are imported from jwt_attack so the
HMAC/base64url logic stays in one place.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import string
from typing import Callable, Optional, Union
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from jwt_attack import _b64url_decode, _b64url_encode, _decode_part, _encode_part, _split_token


# ---------------------------------------------------------------------------
# Helpers — coerce input to either str or bytes consistently
# ---------------------------------------------------------------------------

def _as_bytes(value: Union[str, bytes]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def _as_str(value: Union[str, bytes]) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


# ---------------------------------------------------------------------------
# Scheme implementations — encoders
# ---------------------------------------------------------------------------

def _enc_url(v):           return quote(_as_str(v), safe="")
def _enc_url_double(v):    return quote(quote(_as_str(v), safe=""), safe="")
def _enc_url_plus(v):      return quote_plus(_as_str(v))
def _enc_base64(v):        return base64.b64encode(_as_bytes(v)).decode("ascii")
def _enc_base64url(v):     return _b64url_encode(_as_bytes(v))
def _enc_html_dec(v):      return "".join(f"&#{ord(c)};" for c in _as_str(v))
def _enc_html_hex(v):      return "".join(f"&#x{ord(c):x};" for c in _as_str(v))


def _enc_html_named(v):
    table = {"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;"}
    return "".join(table.get(c, c) for c in _as_str(v))


def _enc_unicode_esc(v):
    return "".join(f"\\u{ord(c):04x}" for c in _as_str(v))


def _enc_hex_backslash(v): return "".join(f"\\x{b:02x}" for b in _as_bytes(v))
def _enc_hex_0x(v):        return "0x" + _as_bytes(v).hex()
def _enc_utf7(v):          return _as_str(v).encode("utf-7").decode("ascii")
def _enc_utf16le(v):       return _as_str(v).encode("utf-16-le").hex()


def _enc_json_escape(v):
    # json.dumps wraps in quotes — strip them so the result can be embedded
    # inside an existing JSON string literal
    return json.dumps(_as_str(v))[1:-1]


def _enc_null_suffix(v):   return _as_str(v) + "\x00"
def _enc_null_prefix(v):   return "\x00" + _as_str(v)


def _enc_jwt_segment(v):
    # If input parses as a JSON object, encode it as a header/payload segment
    # (compact JSON → base64url). Otherwise treat the raw bytes as the segment
    # body to base64url.
    s = _as_str(v)
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return _encode_part(obj)
    except (json.JSONDecodeError, ValueError):
        pass
    return _b64url_encode(_as_bytes(v))


# ---------------------------------------------------------------------------
# Scheme implementations — decoders
# ---------------------------------------------------------------------------

def _dec_url(v):           return unquote(_as_str(v))
def _dec_url_double(v):    return unquote(unquote(_as_str(v)))
def _dec_url_plus(v):      return unquote_plus(_as_str(v))
def _dec_base64(v):        return base64.b64decode(_as_str(v) + "==", validate=False)
def _dec_base64url(v):     return _b64url_decode(_as_str(v))


def _dec_html_dec(v):
    return re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), _as_str(v))


def _dec_html_hex(v):
    return re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), _as_str(v))


def _dec_html_named(v):
    table = {"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"',
             "&#39;": "'", "&apos;": "'"}
    out = _as_str(v)
    for k, val in table.items():
        out = out.replace(k, val)
    return out


def _dec_unicode_esc(v):
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), _as_str(v))


def _dec_hex_backslash(v):
    s = _as_str(v)
    return bytes(int(m.group(1), 16) for m in re.finditer(r"\\x([0-9a-fA-F]{2})", s))


def _dec_hex_0x(v):
    s = _as_str(v)
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def _dec_utf7(v):          return _as_str(v).encode("ascii").decode("utf-7")


def _dec_utf16le(v):
    return bytes.fromhex(_as_str(v)).decode("utf-16-le")


def _dec_json_escape(v):
    return json.loads('"' + _as_str(v) + '"')


def _dec_null_suffix(v):
    s = _as_str(v)
    return s[:-1] if s.endswith("\x00") else s


def _dec_null_prefix(v):
    s = _as_str(v)
    return s[1:] if s.startswith("\x00") else s


def _dec_jwt_segment(v):
    # Try JSON-object decode (header/payload); fall back to raw bytes
    raw = _b64url_decode(_as_str(v))
    try:
        obj = json.loads(raw)
        if isinstance(obj, (dict, list)):
            return obj
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        pass
    return raw


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_SCHEMES: dict[str, tuple[Callable, Callable]] = {
    "url":              (_enc_url,            _dec_url),
    "url_double":       (_enc_url_double,     _dec_url_double),
    "url_plus":         (_enc_url_plus,       _dec_url_plus),
    "base64":           (_enc_base64,         _dec_base64),
    "base64url":        (_enc_base64url,      _dec_base64url),
    "html_dec":         (_enc_html_dec,       _dec_html_dec),
    "html_hex":         (_enc_html_hex,       _dec_html_hex),
    "html_named":       (_enc_html_named,     _dec_html_named),
    "unicode_esc":      (_enc_unicode_esc,    _dec_unicode_esc),
    "hex_backslash":    (_enc_hex_backslash,  _dec_hex_backslash),
    "hex_0x":           (_enc_hex_0x,         _dec_hex_0x),
    "utf7":             (_enc_utf7,           _dec_utf7),
    "utf16le":          (_enc_utf16le,        _dec_utf16le),
    "json_escape":      (_enc_json_escape,    _dec_json_escape),
    "null_byte_suffix": (_enc_null_suffix,    _dec_null_suffix),
    "null_byte_prefix": (_enc_null_prefix,    _dec_null_prefix),
    "jwt_segment":      (_enc_jwt_segment,    _dec_jwt_segment),
}


# Whitelist of safe chains for variants(chain=True). Combinatorial expansion
# is dangerous; the LLM tool should not be able to ask for hundreds of
# permutations in one call. These are the pairs that empirically catch
# real-world WAF bypasses.
_CHAIN_WHITELIST: list[tuple[str, str]] = [
    ("url", "url"),                # double-url via the chain mechanism
    ("url", "base64"),
    ("base64", "url"),
    ("html_dec", "url"),
    ("unicode_esc", "url"),
    ("null_byte_suffix", "url"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_schemes() -> list[str]:
    return list(_SCHEMES.keys())


def encode(value: Union[str, bytes], scheme: str) -> str:
    enc = _SCHEMES.get(scheme)
    if enc is None:
        raise ValueError(f"unknown scheme: {scheme!r}. "
                         f"Valid: {', '.join(_SCHEMES)}")
    return enc[0](value)


def decode(value: Union[str, bytes], scheme: str) -> Union[str, bytes]:
    enc = _SCHEMES.get(scheme)
    if enc is None:
        raise ValueError(f"unknown scheme: {scheme!r}. "
                         f"Valid: {', '.join(_SCHEMES)}")
    return enc[1](value)


def variants(value: Union[str, bytes],
             schemes: Optional[list[str]] = None,
             *, chain: bool = False) -> list[tuple[str, str]]:
    """Return [(label, encoded), ...] for each scheme. Skips schemes that
    error on this input (e.g. utf7 on already-encoded bytes)."""
    if schemes is None:
        # Default to the high-value web-filter-bypass set
        schemes = ["url", "url_double", "url_plus", "html_dec", "html_hex",
                   "unicode_esc", "hex_backslash", "json_escape",
                   "null_byte_suffix", "base64", "base64url"]
    out: list[tuple[str, str]] = []
    for s in schemes:
        try:
            out.append((s, encode(value, s)))
        except (ValueError, UnicodeError, binascii.Error):
            continue
    if chain:
        for a, b in _CHAIN_WHITELIST:
            if a not in schemes and b not in schemes:
                continue
            try:
                intermediate = encode(value, a)
                out.append((f"{a}_then_{b}", encode(intermediate, b)))
            except (ValueError, UnicodeError, binascii.Error):
                continue
    return out


# ── Detection ────────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_URL_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_DEC_RE = re.compile(r"&#\d+;")
_HTML_HEX_RE = re.compile(r"&#x[0-9a-fA-F]+;")
_HEX_BACKSLASH_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_HEX_0X_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")


def detect(value: str) -> list[tuple[str, float]]:
    """Return [(scheme, confidence), ...] ranked descending. Confidence is a
    rough 0–1 heuristic — high means "this almost certainly is X", low means
    "this could plausibly be X." Empty input returns []."""
    s = value or ""
    scored: list[tuple[str, float]] = []
    if not s:
        return scored

    # JWT — most specific, check first
    if _JWT_RE.match(s) and "." in s:
        try:
            head, body, _ = _split_token(s) or (None, None, None)
            if head and body:
                scored.append(("jwt", 0.99))
        except Exception:
            pass

    # URL percent-encoded
    pct_count = len(_URL_PCT_RE.findall(s))
    if pct_count:
        scored.append(("url", min(0.5 + 0.1 * pct_count, 0.95)))
        if pct_count >= 1 and "%25" in s:
            scored.append(("url_double", 0.85))

    # HTML entities
    if _HTML_DEC_RE.search(s):
        scored.append(("html_dec", 0.9))
    if _HTML_HEX_RE.search(s):
        scored.append(("html_hex", 0.9))

    # Unicode escapes
    if _UNICODE_ESC_RE.search(s):
        scored.append(("unicode_esc", 0.85))

    # Hex with \x markers
    if _HEX_BACKSLASH_RE.search(s):
        scored.append(("hex_backslash", 0.85))

    # 0x… literal
    if _HEX_0X_RE.match(s) and len(s) > 4:
        scored.append(("hex_0x", 0.8))

    # base64 / base64url — only score plausibly-encoded blobs
    if len(s) >= 4 and len(s) % 4 == 0 and _BASE64_RE.match(s):
        try:
            decoded = base64.b64decode(s, validate=True)
            ratio = sum(1 for b in decoded if 32 <= b < 127) / max(len(decoded), 1)
            scored.append(("base64", 0.6 + 0.3 * ratio))
        except (binascii.Error, ValueError):
            pass
    if (len(s) >= 4
            and _BASE64URL_RE.match(s)
            and ("-" in s or "_" in s or len(s) % 4 != 0)):
        try:
            _b64url_decode(s)
            scored.append(("base64url", 0.7))
        except (binascii.Error, ValueError):
            pass

    # JSON-string-escape — heuristic: contains \" or \\ but not a percent
    if ('\\"' in s or "\\\\" in s) and "%" not in s:
        scored.append(("json_escape", 0.4))

    scored.sort(key=lambda t: t[1], reverse=True)
    # Deduplicate by scheme, keeping the highest confidence
    seen: dict[str, float] = {}
    for name, conf in scored:
        if name not in seen or conf > seen[name]:
            seen[name] = conf
    return sorted(seen.items(), key=lambda t: t[1], reverse=True)


def try_decode_all(value: str, *, max_depth: int = 2) -> list[tuple[str, str]]:
    """Recursively decode `value`, returning every (scheme, decoded) pair
    discovered up to `max_depth` levels deep. Useful for peeling layered
    encodings the agent finds in captured tokens. JWTs are split into
    `jwt_header` + `jwt_payload` layers so the caller sees both claims."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _walk(s: str, depth: int):
        if depth > max_depth or not s or s in seen:
            return
        seen.add(s)
        for scheme, _conf in detect(s):
            # JWT is a compound encoding — no single _SCHEMES entry decodes
            # a full token. Peel the header and payload separately so each
            # claim becomes its own surfaced layer.
            if scheme == "jwt":
                split = _split_token(s)
                if split is None:
                    continue
                header, payload, _sig = split
                header_text = json.dumps(header, separators=(",", ":"))
                payload_text = json.dumps(payload, separators=(",", ":"))
                out.append(("jwt", header_text))
                out.append(("jwt_payload", payload_text))
                _walk(payload_text, depth + 1)
                continue
            try:
                decoded = decode(s, scheme)
            except Exception:
                continue
            text = decoded.decode("utf-8", "replace") if isinstance(decoded, bytes) else decoded
            if not text or text == s:
                continue
            out.append((scheme, text))
            _walk(text, depth + 1)

    _walk(value, 0)
    return out


def jwt_split(token: str) -> Optional[tuple[dict, dict, str]]:
    """Convenience re-export — split a JWT into (header, payload, signature)."""
    return _split_token(token)


# ---------------------------------------------------------------------------
# Dump helpers — tree-shaped output, hex+ASCII for binary layers,
# annotation pass for JWT claims / character-corpus matches / secrets.
# Operators and the TUI render these dicts however they want; LLM tools
# consume them as JSON.
# ---------------------------------------------------------------------------

# Secret detection delegates to the unified [[secrets]] module — single
# source of truth across enricher, js_deep_analyzer, classifier, and the
# annotate() call below.
import secrets as _secrets  # noqa: E402


# Notable single characters worth flagging when they appear in a decoded
# layer (filename masking, log injection, parser ambiguity). Kept as a
# minimal set — fuzz.character_corpus has the full taxonomy, but pulling
# it in here would invert the import direction.
_NOTABLE_CHARS: list[tuple[str, str]] = [
    ("null",        "\x00"),
    ("cr",          "\r"),
    ("lf",          "\n"),
    ("esc",         "\x1b"),
    ("rlo",         "‮"),
    ("lro",         "‭"),
    ("zwsp",        "​"),
    ("zwj",         "‍"),
    ("word_joiner", "⁠"),
    ("nbsp",        " "),
    ("bom",         "﻿"),
    ("ls",          " "),
    ("ps",          " "),
]


def hexdump(b: Union[bytes, str], *, width: int = 16,
            max_lines: Optional[int] = None) -> str:
    """Return a ``offset | hex | ASCII`` dump suitable for operator review.

    ``str`` input is encoded as UTF-8 with replacement for unrepresentable
    code units so the caller never has to coerce ahead of time."""
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    lines: list[str] = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hex_col = " ".join(f"{c:02x}" for c in chunk)
        # Pad the hex column so the ASCII pane lines up
        hex_col = hex_col.ljust(width * 3 - 1)
        ascii_col = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{i:08x}  {hex_col}  |{ascii_col}|")
        if max_lines and len(lines) >= max_lines:
            lines.append(f"… ({len(b) - (i + width)} more bytes elided)")
            break
    return "\n".join(lines)


def annotate(layer_value: str, *, scheme: str = "raw") -> list[str]:
    """Tag a decoded layer with findings the operator would want to see at
    a glance: JWT claims, character-corpus matches, secret-shaped regex
    hits, encoding hints.

    The returned list is order-stable: scheme-level annotations first,
    then JWT details, then character flags, then secret hits."""
    out: list[str] = []
    s = layer_value or ""

    # Scheme-level annotation passes through detect() so the caller sees
    # what *this* layer looks like (e.g., a decoded base64 layer might
    # itself be a JWT).
    if scheme != "raw":
        out.append(f"scheme: {scheme}")

    # JWT-shaped layer — pull alg + kid + key claims
    if _JWT_RE.match(s) and "." in s:
        split = _split_token(s)
        if split:
            header, payload, _sig = split
            alg = header.get("alg")
            kid = header.get("kid")
            if alg:
                out.append(f"jwt: alg={alg}")
            if kid:
                out.append(f"jwt: kid={kid}")
            for claim in ("iss", "sub", "aud", "role", "scope", "admin"):
                if claim in payload:
                    out.append(f"jwt: {claim}={payload[claim]}")

    # Character corpus markers — RLO / NBSP / null / etc.
    for label, ch in _NOTABLE_CHARS:
        if ch in s:
            out.append(f"char: {label}")

    # Secret-shaped regex matches — delegate to the unified catalog.
    # Don't leak the full secret into the annotation; show the first 8
    # characters so the operator can grep back to the leak site.
    for match in _secrets.scan(s):
        preview = match.value[:8]
        out.append(f"secret: {match.kind} (starts {preview!r})")

    return out


def decode_tree(value: str, *, max_depth: int = 2) -> dict:
    """Return a tree-shaped decoding of ``value``.

    Each node is::

        {
            "scheme": str,         # "raw" for the root, then one per layer
            "value": str,          # decoded text at this layer
            "annotations": list[str],
            "children": [<node>, …]
        }

    Children are produced by re-applying every detect()-suggested scheme
    that yields a non-trivial decode (text != input, non-empty). Depth is
    bounded by ``max_depth`` to prevent runaway recursion on
    self-referential encodings."""
    if not value:
        return {"scheme": "raw", "value": "",
                "annotations": [], "children": []}

    def _walk(s: str, scheme: str, depth: int, seen: set[str]) -> dict:
        node = {
            "scheme": scheme,
            "value": s,
            "annotations": annotate(s, scheme=scheme),
            "children": [],
        }
        if depth >= max_depth or s in seen:
            return node
        next_seen = seen | {s}
        for child_scheme, _conf in detect(s):
            if child_scheme == "jwt":
                split = _split_token(s)
                if split is None:
                    continue
                header, payload, _sig = split
                header_text = json.dumps(header, separators=(",", ":"))
                payload_text = json.dumps(payload, separators=(",", ":"))
                node["children"].append({
                    "scheme": "jwt_header",
                    "value": header_text,
                    "annotations": annotate(header_text, scheme="jwt_header"),
                    "children": [],
                })
                node["children"].append(
                    _walk(payload_text, "jwt_payload",
                          depth + 1, next_seen)
                )
                continue
            try:
                decoded = decode(s, child_scheme)
            except Exception:
                continue
            text = (decoded.decode("utf-8", "replace")
                    if isinstance(decoded, bytes) else decoded)
            if not text or text == s:
                continue
            node["children"].append(
                _walk(text, child_scheme, depth + 1, next_seen)
            )
        return node

    return _walk(value, "raw", 0, set())


def dump(value: str, *, max_depth: int = 2,
         hex_width: int = 16) -> dict:
    """One-call convenience: tree + per-layer hex dump + annotations.

    Returns::

        {
            "tree":        <decode_tree output>,
            "hex":         {layer_path: hexdump_str, …},
            "annotations": {layer_path: [tags, …], …}
        }

    ``layer_path`` is a slash-separated trail of scheme labels from root
    to the node, e.g. ``"raw/jwt_header"`` or ``"raw/base64/url"``."""
    tree = decode_tree(value, max_depth=max_depth)
    hex_map: dict[str, str] = {}
    ann_map: dict[str, list[str]] = {}

    def _visit(node: dict, path: str) -> None:
        ann_map[path] = node["annotations"]
        hex_map[path] = hexdump(node["value"], width=hex_width, max_lines=8)
        for child in node["children"]:
            _visit(child, f"{path}/{child['scheme']}")

    _visit(tree, "raw")
    return {"tree": tree, "hex": hex_map, "annotations": ann_map}


__all__ = [
    "encode", "decode", "variants", "detect", "try_decode_all",
    "jwt_split", "list_schemes",
    "hexdump", "annotate", "decode_tree", "dump",
]
