"""Tests for the codec wiring in ws_probe — encoded channel-ID mutation
and the passive frame-payload decoder.

Run:  python -m pytest tests/test_ws_probe_codec.py -v
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import codec  # noqa: E402
import ws_probe  # noqa: E402


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# ── _mutate_id encoded path ────────────────────────────────────────────────

def test_mutate_id_plain_integer_unchanged():
    assert ws_probe._mutate_id(42) == "43"
    assert ws_probe._mutate_id("42") == "43"


def test_mutate_id_base64_encoded_integer_round_trips():
    encoded = _b64("100")
    mutated = ws_probe._mutate_id(encoded)
    # Should still decode as base64 and decode to 101
    decoded = codec.decode(mutated, "base64")
    if isinstance(decoded, bytes):
        decoded = decoded.decode("utf-8", "replace")
    assert decoded == "101", f"expected '101' after mutate, got {decoded!r}"


def test_mutate_id_base64_string_id_round_trips():
    encoded = _b64("room-1")
    mutated = ws_probe._mutate_id(encoded)
    decoded = codec.decode(mutated, "base64")
    if isinstance(decoded, bytes):
        decoded = decoded.decode("utf-8", "replace")
    assert decoded == "room-2", f"expected 'room-2' after mutate, got {decoded!r}"


def test_mutate_id_falls_back_to_dash_suffix_for_short_strings():
    # Short non-encodable strings hit the legacy "-2" fallback
    assert ws_probe._mutate_id("abc") == "abc-2"


# ── _scan_frames_for_encoded_payloads ──────────────────────────────────────

def test_scan_finds_jwt_in_sent_frame():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    sent = [{"raw": json.dumps({"type": "auth", "token": token})}]
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", sent, [],
    )
    assert findings, "expected JWT to be surfaced from sent frame"
    f = findings[0]
    assert f["category"] == "websocket_encoded_payload"
    assert "sent" in f["evidence"]
    assert "jwt" in f["evidence"] or "JWT" in f["evidence"]


def test_scan_finds_base64_url_in_received_frame():
    encoded_url = _b64("https://internal-api.corp.local/admin-panel")
    received = [{"raw": json.dumps({"redirect": encoded_url})}]
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", [], received,
    )
    assert findings
    assert any("internal-api.corp.local" in f["evidence"] for f in findings)
    assert any(f["severity"] in ("medium", "high") for f in findings)


def test_scan_ignores_short_garbage():
    # Frames too short to be encoded payloads should not produce findings
    sent = [{"raw": "ping"}, {"raw": "ack"}, {"raw": "{}"}]
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", sent, [],
    )
    assert findings == []


def test_scan_dedupes_same_decoded_value():
    encoded_url = _b64("https://api.corp.local/secret")
    # Same encoded value appears in multiple frames
    frames = [{"raw": json.dumps({"x": encoded_url})} for _ in range(4)]
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", frames, [],
    )
    # Should produce at most ONE finding for the same (direction, scheme,
    # decoded_prefix) combination
    assert len(findings) == 1


def test_scan_severity_high_for_secret_keywords():
    encoded = _b64('{"api_key":"sk_live_real_key"}')
    sent = [{"raw": json.dumps({"payload": encoded})}]
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", sent, [],
    )
    assert findings
    assert any(f["severity"] == "high" for f in findings), \
        f"expected high severity for api_key, got {[f['severity'] for f in findings]}"


def test_scan_skips_routine_url_encoding():
    # A frame that just URL-encodes a UTF-8 string is NOT an obfuscated
    # payload — passive scan should stay quiet
    sent = [{"raw": "%E4%B8%AD%E6%96%87"}]  # URL-encoded "中文"
    findings = ws_probe._scan_frames_for_encoded_payloads(
        "wss://corp.local/ws", sent, [],
    )
    assert findings == []
