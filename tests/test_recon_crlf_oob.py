"""Tests for the OOB-tunnel-aware CRLF probes in OpenRedirectRecipe.

Verifies the deliberate-choice rule:
  - no ReconContext / no public_url  → existing canary-only behavior, NO CRLF
  - ReconContext(public_url=...)     → CRLF probes emitted, all pointing at
                                       the operator-provided tunnel

Run:  python -m pytest tests/test_recon_crlf_oob.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from classifier import Cat, Finding  # noqa: E402
import recon_collector as rc  # noqa: E402


def _finding():
    return Finding(method="GET",
                   url="https://api.example.com/login?redirect=/dashboard",
                   score=10, categories=[Cat.REDIRECT], evidence=[])


# ── No-context path (legacy / pre-tunnel runs) ─────────────────────────────

def test_no_ctx_emits_canary_only_no_crlf():
    probes = rc.OpenRedirectRecipe().probes(_finding())
    labels = [p.label for p in probes]
    # Canary-based variants present
    assert "baseline_auth" in labels
    assert "redirect_redirect_to_evil" in labels
    assert "redirect_redirect_urlx2" in labels
    # NO crlf probes when no tunnel
    assert not any("crlf" in l for l in labels), \
        f"expected no CRLF probes without tunnel, got {labels}"


def test_ctx_without_public_url_skips_crlf():
    ctx = rc.ReconContext(public_url=None, oob_token="abc123")
    probes = rc.OpenRedirectRecipe().probes_with_ctx(_finding(), ctx)
    labels = [p.label for p in probes]
    assert not any("crlf" in l for l in labels)


# ── With-tunnel path ───────────────────────────────────────────────────────

def test_ctx_with_public_url_emits_crlf_probes():
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com",
                          oob_token="t0k3n")
    probes = rc.OpenRedirectRecipe().probes_with_ctx(_finding(), ctx)
    labels = [p.label for p in probes]

    # All 5 CRLF variants should be present
    for variant in ("crlf_standard", "crlf_lf_only", "crlf_double_enc",
                    "crlf_set_cookie", "crlf_refresh"):
        assert any(variant in l for l in labels), \
            f"missing {variant} in {labels}"

    # The basic redirect target should now point at the TUNNEL, not the
    # hardcoded canary
    evil_probe = [p for p in probes if p.label.endswith("_to_evil")][0]
    qs = parse_qs(urlparse(evil_probe.url).query)
    assert "trycloudflare.com" in qs["redirect"][0], \
        f"expected tunnel URL in redirect target, got {qs['redirect']}"


def test_crlf_payloads_target_tunnel_host():
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com",
                          oob_token="t0k3n")
    probes = rc.OpenRedirectRecipe().probes_with_ctx(_finding(), ctx)

    standard = [p for p in probes if "crlf_standard" in p.label][0]
    # The CRLF payload should reference our tunnel host inside the injected
    # Location header (URL-encoded form survives because we use safe="%")
    assert "trycloudflare.com" in standard.url
    # The %0d%0a sequence must be preserved (not double-encoded back to %250d)
    assert "%0d%0a" in standard.url.lower(), \
        f"expected raw %0d%0a in {standard.url}"


def test_crlf_set_cookie_includes_token():
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com",
                          oob_token="t0k3n")
    probes = rc.OpenRedirectRecipe().probes_with_ctx(_finding(), ctx)
    sc_probe = [p for p in probes if "crlf_set_cookie" in p.label][0]
    # Token should be embedded so we can correlate tunnel hits to this probe
    assert "t0k3n" in sc_probe.url, \
        f"expected oob_token 't0k3n' embedded in {sc_probe.url}"


def test_no_target_param_returns_empty():
    f = Finding(method="GET", url="https://api.example.com/no/param/here",
                score=5, categories=[Cat.REDIRECT], evidence=[])
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com")
    probes = rc.OpenRedirectRecipe().probes_with_ctx(f, ctx)
    assert probes == []


# ── Plumbing path: collect_recon picks the ctx-aware probe set ────────────

def test_pick_recipe_uses_ctx_aware_probes_for_redirect():
    f = _finding()
    # Without ctx: 3 probes (baseline + evil + urlx2)
    recipe_no_ctx = rc.pick_recipe(f, ctx=None)
    no_ctx_probes = rc._recipe_probes(recipe_no_ctx, f, ctx=None)

    # With ctx: 3 + 5 CRLF = 8 probes
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com", oob_token="x")
    recipe_with_ctx = rc.pick_recipe(f, ctx=ctx)
    with_ctx_probes = rc._recipe_probes(recipe_with_ctx, f, ctx=ctx)

    assert len(with_ctx_probes) > len(no_ctx_probes)
    assert len(with_ctx_probes) - len(no_ctx_probes) == 5, \
        f"expected 5 extra CRLF probes, got {len(with_ctx_probes) - len(no_ctx_probes)}"


def test_other_recipes_unaffected_by_ctx():
    # SSRFRecipe does NOT define probes_with_ctx — it should still work via
    # the plain probes(finding) path even when ctx is passed.
    f = Finding(method="GET",
                url="https://api.example.com/fetch?url=https://orig.example/",
                score=10, categories=[Cat.SSRF], evidence=[])
    ctx = rc.ReconContext(public_url="https://abc.trycloudflare.com")
    probes = rc._recipe_probes(rc.SSRFRecipe(), f, ctx)
    assert probes, "SSRFRecipe should still emit probes regardless of ctx"
    assert all("crlf" not in p.label for p in probes)
