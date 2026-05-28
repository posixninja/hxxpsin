"""Tests for the codec wiring in idor_probe — encoded-ID detection and
mutation candidate generation.

Run:  python -m pytest tests/test_idor_encoded_swap.py -v
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import codec  # noqa: E402
import idor_probe  # noqa: E402


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_encoded_id_segments_finds_base64_user_id():
    seg = _b64("user42")
    url = f"https://api.example.com/users/{seg}/profile"
    out = idor_probe._encoded_id_segments(url)
    assert out, f"expected encoded segment from {seg!r} in {url!r}"
    original, scheme, decoded = out[0]
    assert original == seg
    assert scheme == "base64"
    assert decoded == "user42"


def test_encoded_id_segments_skips_numeric_and_uuid():
    # Plain numeric IDs and UUIDs are handled by the existing passes
    url1 = "https://api.example.com/users/42/profile"
    url2 = "https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile"
    assert idor_probe._encoded_id_segments(url1) == []
    assert idor_probe._encoded_id_segments(url2) == []


def test_encoded_id_segments_skips_minified_garbage():
    # Short random-looking segments should not be flagged as encoded IDs
    url = "https://api.example.com/v1/abc/def"
    out = idor_probe._encoded_id_segments(url)
    assert out == []


def test_mutate_decoded_id_numeric():
    out = idor_probe._mutate_decoded_id("42")
    # Should include +1, -1, +10, +100, +1000 and the canonical low IDs
    assert "43" in out
    assert "41" in out
    assert any(c in out for c in ("1", "2", "0"))
    assert len(out) <= 5
    assert "42" not in out  # never propose the original


def test_mutate_decoded_id_trailing_digit():
    out = idor_probe._mutate_decoded_id("user42")
    assert "user43" in out, f"expected trailing-digit increment in {out}"


def test_mutate_decoded_id_no_digits():
    out = idor_probe._mutate_decoded_id("abc")
    # No digit pattern — should still propose at least one mutation
    # (substitution of last char)
    assert out
    assert "abc" not in out


def test_end_to_end_encode_mutate_decode():
    # Build a URL with base64 user id → run the segment scanner → mutate →
    # re-encode → verify the result is decodable back to the mutated value
    seg = _b64("user42")
    url = f"https://api.example.com/users/{seg}/profile"

    found = idor_probe._encoded_id_segments(url)
    assert found
    original, scheme, decoded = found[0]

    mutations = idor_probe._mutate_decoded_id(decoded)
    assert mutations

    re_encoded = codec.encode(mutations[0], scheme)
    # Re-encoded value should decode back to the mutation, not the original
    round_tripped = codec.decode(re_encoded, scheme)
    if isinstance(round_tripped, bytes):
        round_tripped = round_tripped.decode("utf-8", "replace")
    assert round_tripped == mutations[0]
    assert round_tripped != decoded
