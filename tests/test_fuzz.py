"""Unit tests for src/fuzz.py — binary mutation, boundary values, polyglots.

Run:  python -m pytest tests/test_fuzz.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import fuzz  # noqa: E402


# ── Determinism ─────────────────────────────────────────────────────────────

def test_mutate_bytes_deterministic_with_seed():
    a = fuzz.mutate_bytes(b"AAAA", count=8, seed=42)
    b = fuzz.mutate_bytes(b"AAAA", count=8, seed=42)
    assert a == b, "same seed must produce identical mutations"


def test_mutate_bytes_count_and_distinct():
    out = fuzz.mutate_bytes(b"AAAAAAAA", count=8, seed=42)
    assert len(out) == 8
    blobs = [v for _, v in out]
    assert len(set(blobs)) == 8, f"expected 8 distinct mutations, got {len(set(blobs))}"


def test_mutate_bytes_unseeded_still_returns_count():
    out = fuzz.mutate_bytes(b"hello world", count=5)
    assert len(out) == 5


# ── Boundary values ─────────────────────────────────────────────────────────

def test_boundary_values_includes_empty_single_and_pow2():
    out = fuzz.boundary_values(max_pow=16)
    blobs = {label: data for label, data in out}
    assert blobs["empty"] == b""
    assert len(blobs["single"]) == 1
    assert len(blobs["pow2_16"]) == 2 ** 16


def test_boundary_values_includes_off_by_one():
    out = fuzz.boundary_values(max_pow=8)
    labels = {label for label, _ in out}
    assert "pow2_minus1_8" in labels and "pow2_plus1_8" in labels


# ── Polyglot ────────────────────────────────────────────────────────────────

def test_polyglot_starts_with_png_magic_and_contains_payload():
    blob = fuzz.magic_byte_polyglot("png", b"<?php ?>")
    assert blob.startswith(b"\x89PNG\r\n\x1a\n"), \
        f"expected PNG magic, got {blob[:8]!r}"
    assert b"<?php ?>" in blob, "payload not present verbatim"


def test_magic_bytes_table_png_header():
    table = fuzz.magic_bytes_table()
    assert table["png"][:8] == bytes.fromhex("89504e470d0a1a0a")
    # Aliases for jpeg/jpg point to the same header
    assert table["jpg"] == table["jpeg"]
    for k in ("png", "gif", "jpeg", "pdf", "zip"):
        assert k in table, f"missing magic for {k}"


def test_polyglot_unknown_ext_raises():
    with pytest.raises(ValueError, match="unknown extension"):
        fuzz.magic_byte_polyglot("xyzzy", b"x")


# ── Character corpus / encoded corpus ───────────────────────────────────────

def test_character_categories_includes_expected():
    cats = fuzz.character_categories()
    for required in ("control", "utf8_overlong", "normalization",
                     "invisible", "newline", "shell_meta", "sql_meta",
                     "html_meta", "template", "numeric"):
        assert required in cats, f"missing category {required}"


def test_character_corpus_control_contains_null_and_crlf():
    items = dict(fuzz.character_corpus("control"))
    assert items["null"] == "\x00"
    assert items["lf"] == "\n"
    assert items["cr"] == "\r"


def test_character_corpus_normalization_fullwidth_collapses_under_nfkc():
    import unicodedata
    items = dict(fuzz.character_corpus("normalization"))
    assert unicodedata.normalize("NFKC", items["fullwidth_lt"]) == "<"
    assert unicodedata.normalize("NFKC", items["fullwidth_slash"]) == "/"
    assert unicodedata.normalize("NFKC", items["ligature_ffi"]) == "ffi"


def test_character_corpus_invisible_includes_rlo_and_nbsp():
    items = dict(fuzz.character_corpus("invisible"))
    assert items["rlo"] == "‮"
    assert items["nbsp"] == " "


def test_character_corpus_all_prefixes_labels_by_category():
    out = fuzz.character_corpus()
    # Every label should be "category/name"
    for label, _ in out:
        assert "/" in label, f"label {label!r} not category-prefixed"
    # The union covers every category
    cats_in_labels = {label.split("/", 1)[0] for label, _ in out}
    assert cats_in_labels == set(fuzz.character_categories())


def test_character_corpus_unknown_category_raises():
    with pytest.raises(ValueError, match="unknown category"):
        fuzz.character_corpus("not-a-real-category")


def test_encoded_corpus_includes_raw_and_encoded_variants():
    out = fuzz.encoded_corpus(
        categories=["sql_meta"], schemes=["url", "base64"], include_raw=True,
    )
    by_char_scheme = {(c, s): v for c, s, v in out}
    # single_quote → raw, url, base64 all present
    assert by_char_scheme[("sql_meta/single_quote", "raw")] == "'"
    assert by_char_scheme[("sql_meta/single_quote", "url")] == "%27"
    assert by_char_scheme[("sql_meta/single_quote", "base64")] == "Jw=="


def test_encoded_corpus_omits_raw_when_requested():
    out = fuzz.encoded_corpus(
        categories=["sql_meta"], schemes=["url"], include_raw=False,
    )
    schemes_seen = {s for _, s, _ in out}
    assert "raw" not in schemes_seen
    assert "url" in schemes_seen


def test_encoded_corpus_default_size_is_nontrivial():
    # Full cross-product with default schemes should produce hundreds of
    # variants — confirms the function isn't silently truncating to one
    # category.
    out = fuzz.encoded_corpus()
    assert len(out) > 200, f"unexpectedly small corpus: {len(out)}"


def test_encoded_corpus_swallows_encoding_errors():
    # utf16le shouldn't crash on overlong/surrogate input; encoded_corpus
    # silently skips schemes that throw.
    out = fuzz.encoded_corpus(
        categories=["utf8_overlong"], schemes=["url", "utf16le"],
        include_raw=False,
    )
    # We don't assert the size — only that we got something and didn't crash
    assert isinstance(out, list)


# ── Malformed multipart / JSON / XML ────────────────────────────────────────

def test_malformed_multipart_includes_expected_variants():
    out = fuzz.malformed_multipart()
    labels = {label for label, _ in out}
    for required in ("baseline", "missing_final_boundary", "doubled_crlf",
                     "lf_only", "trailing_garbage"):
        assert required in labels, f"missing variant {required}"


def test_malformed_json_includes_proto_pollution():
    out = fuzz.malformed_json()
    blobs = {label: data for label, data in out}
    assert "__proto__" in blobs["nested_proto"]
    assert "constructor" in blobs["nested_constructor"]


def test_malformed_xml_includes_xxe():
    out = fuzz.malformed_xml()
    blobs = {label: data for label, data in out}
    assert "file:///etc/passwd" in blobs["xxe_file"]
    assert "billion_laughs" in {label for label, _ in out}


# ── Upload variants ─────────────────────────────────────────────────────────

def test_upload_variants_double_extension_and_null_byte():
    out = fuzz.upload_variants("shell.php", b"<?php", "png")
    by_label = {label: (fname, body) for label, fname, body in out}

    assert by_label["double_extension"][0] == "shell.png.php"

    null_fname = by_label["null_byte_truncation"][0]
    assert "\x00" in null_fname
    assert null_fname.startswith("shell.php\x00")
    assert null_fname.endswith(".png")


def test_upload_variants_polyglot_has_png_header():
    out = fuzz.upload_variants("shell.php", b"<?php", "png")
    by_label = {label: (fname, body) for label, fname, body in out}
    poly_body = by_label["polyglot"][1]
    assert poly_body.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"<?php" in poly_body
