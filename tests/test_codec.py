"""Unit tests for src/codec.py — encoding/decoding/variants/detect.

Run:  python -m pytest tests/test_codec.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import codec  # noqa: E402


# ── 1. Round-trip property across the textual schemes ───────────────────────

@pytest.mark.parametrize("value", ["", "admin", "héllo", "' OR 1=1--"])
@pytest.mark.parametrize("scheme", [
    "url", "url_double", "url_plus", "base64", "base64url",
    "hex_backslash", "json_escape",
])
def test_roundtrip_textual_schemes(value, scheme):
    encoded = codec.encode(value, scheme)
    decoded = codec.decode(encoded, scheme)
    text = decoded.decode("utf-8", "replace") if isinstance(decoded, bytes) else decoded
    assert text == value, f"{scheme}: round-trip lost data ({value!r} → {encoded!r} → {text!r})"


# ── 2-4. Known vectors ──────────────────────────────────────────────────────

def test_known_vector_base64():
    assert codec.encode("admin", "base64") == "YWRtaW4="


def test_known_vector_html_dec():
    assert codec.encode("a<b>", "html_dec") == "&#97;&#60;&#98;&#62;"


def test_known_vector_jwt_segment_decode():
    decoded = codec.decode("eyJhbGciOiJub25lIn0", "jwt_segment")
    assert isinstance(decoded, dict) and decoded["alg"] == "none"


def test_jwt_segment_encode_from_json():
    seg = codec.encode('{"alg":"none"}', "jwt_segment")
    assert seg == "eyJhbGciOiJub25lIn0"


# ── 5. Detection ranking ────────────────────────────────────────────────────

def test_detect_jwt_first():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.x"
    ranked = codec.detect(token)
    assert ranked, "expected at least one detection result"
    assert ranked[0][0] == "jwt"


def test_detect_base64_first():
    ranked = codec.detect("YWRtaW4=")
    assert ranked[0][0] == "base64"


def test_detect_url_first():
    ranked = codec.detect("%3Cscript%3E")
    assert ranked[0][0] == "url"


# ── 6. Nested decode ────────────────────────────────────────────────────────

def test_try_decode_all_nested():
    # "dXNlcj0lNDA=" → base64 → "user=%40" → url → "user=@"
    results = codec.try_decode_all("dXNlcj0lNDA=")
    schemes = [s for s, _ in results]
    values = [v for _, v in results]
    assert "base64" in schemes, f"expected base64 in {schemes}"
    assert any(v == "user=%40" for v in values), f"missing base64 layer in {values}"
    assert any(v == "user=@" for v in values), f"missing url layer in {values}"


# ── 7. Variants distinctness ────────────────────────────────────────────────

def test_variants_distinct():
    out = codec.variants("' OR 1=1--", ["url", "url_double", "unicode_esc"])
    assert len(out) == 3
    encoded = [v for _, v in out]
    assert len(set(encoded)) == 3, f"expected 3 distinct, got {encoded}"


def test_variants_chain_optin():
    no_chain = codec.variants("ab", ["url"], chain=False)
    with_chain = codec.variants("ab", ["url"], chain=True)
    assert len(with_chain) > len(no_chain)


# ── 8. Error handling ──────────────────────────────────────────────────────

def test_unknown_scheme_raises():
    with pytest.raises(ValueError, match="unknown scheme"):
        codec.encode("x", "bogus_scheme_name")


def test_list_schemes_includes_essentials():
    names = set(codec.list_schemes())
    for required in ["url", "url_double", "base64", "base64url",
                     "html_dec", "html_hex", "unicode_esc",
                     "hex_backslash", "json_escape", "jwt_segment"]:
        assert required in names, f"missing scheme {required!r}"


# ── 9. Additional spot-checks (boundary behavior) ──────────────────────────

def test_null_byte_suffix_roundtrip():
    assert codec.encode("foo", "null_byte_suffix") == "foo\x00"
    assert codec.decode("foo\x00", "null_byte_suffix") == "foo"


def test_html_named_only_affects_html_specials():
    assert codec.encode("<a>&'\"", "html_named") == "&lt;a&gt;&amp;&#39;&quot;"
    assert codec.encode("plain text", "html_named") == "plain text"


# ── 10. Dump helpers — hexdump / annotate / decode_tree / dump ─────────────

def test_hexdump_offset_and_ascii_columns():
    out = codec.hexdump(b"Hello!")
    assert out.startswith("00000000 ")
    assert "|Hello!" in out
    # Hex column has correct bytes
    assert "48 65 6c 6c 6f 21" in out


def test_hexdump_str_input_encodes_utf8():
    out = codec.hexdump("héllo")
    # h=68, é=c3 a9, l=6c, l=6c, o=6f
    assert "68 c3 a9 6c 6c 6f" in out


def test_hexdump_non_printable_uses_dots_in_ascii_pane():
    out = codec.hexdump(b"\x00\x01\x02\x7fABC")
    assert "|....ABC|" in out


def test_hexdump_max_lines_truncates():
    out = codec.hexdump(b"A" * 200, width=16, max_lines=3)
    lines = out.split("\n")
    assert len(lines) == 4  # 3 lines + the "more bytes elided" marker
    assert "more bytes elided" in lines[-1]


def test_annotate_jwt_surfaces_alg_kid_role():
    # alg=none, kid=admin, payload sub=admin role=admin
    jwt = ("eyJhbGciOiJub25lIiwia2lkIjoiYWRtaW4ifQ"
           ".eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.")
    tags = codec.annotate(jwt)
    assert "jwt: alg=none" in tags
    assert "jwt: kid=admin" in tags
    assert "jwt: role=admin" in tags
    assert "jwt: sub=admin" in tags


def test_annotate_detects_aws_and_github_secrets():
    text = "config: aws=AKIAIOSFODNN7EXAMPLE\nghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    tags = codec.annotate(text)
    aws_tag = next((t for t in tags if "aws_access_key" in t), None)
    gh_tag = next((t for t in tags if "github_pat" in t), None)
    assert aws_tag and "AKIAIOSF" in aws_tag
    assert gh_tag and "ghp_aBcD" in gh_tag


def test_annotate_flags_rlo_and_null_chars():
    tags = codec.annotate("safe‮malicious\x00")
    assert "char: rlo" in tags
    assert "char: null" in tags


def test_annotate_scheme_prefix_on_non_raw_layer():
    tags = codec.annotate("plain text", scheme="base64")
    assert "scheme: base64" in tags


def test_annotate_clean_input_returns_empty():
    assert codec.annotate("just plain ascii text") == []


def test_decode_tree_jwt_splits_into_header_and_payload():
    jwt = ("eyJhbGciOiJIUzI1NiJ9"
           ".eyJzdWIiOiJhbGljZSJ9.signature")
    tree = codec.decode_tree(jwt)
    assert tree["scheme"] == "raw"
    child_schemes = [c["scheme"] for c in tree["children"]]
    assert "jwt_header" in child_schemes
    assert "jwt_payload" in child_schemes
    # Header content
    header_node = next(c for c in tree["children"] if c["scheme"] == "jwt_header")
    assert "HS256" in header_node["value"]


def test_decode_tree_nested_encoding_walks_children():
    # base64("user=%40") → decoded url → "user=@"
    tree = codec.decode_tree("dXNlcj0lNDA=")
    # Root annotation should include some scheme detection
    schemes_found: list[str] = []
    def _collect(node):
        schemes_found.append(node["scheme"])
        for c in node["children"]:
            _collect(c)
    _collect(tree)
    assert "base64" in schemes_found


def test_decode_tree_max_depth_caps_recursion():
    # max_depth=0 means root only, no children
    tree = codec.decode_tree("eyJhbGciOiJIUzI1NiJ9.eyJ4Ijp7fX0.s", max_depth=0)
    assert tree["children"] == []


def test_dump_returns_tree_hex_annotations():
    out = codec.dump("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.x")
    assert "tree" in out and "hex" in out and "annotations" in out
    # Paths should be slash-separated from "raw"
    assert "raw" in out["annotations"]
    # JWT header should appear as a path
    paths = list(out["annotations"].keys())
    assert any(p.endswith("/jwt_header") for p in paths)
    # Hex dump is keyed by the same paths
    assert set(out["hex"].keys()) == set(out["annotations"].keys())


def test_dump_secret_in_decoded_layer_surfaces_in_annotations():
    # base64 of an OpenAI-style key
    import base64
    sk = "sk-" + "A" * 20 + "T3BlbkFJ" + "B" * 20
    encoded = base64.b64encode(sk.encode()).decode()
    out = codec.dump(encoded)
    # At least one layer should carry a secret annotation
    any_secret = any(
        any("secret:" in a for a in tags)
        for tags in out["annotations"].values()
    )
    assert any_secret, f"expected secret detection in: {out['annotations']}"
