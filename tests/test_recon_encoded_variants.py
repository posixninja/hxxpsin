"""Tests for codec.variants wiring in recon_collector recipes.

Verifies that SSRFRecipe, InjectionRecipe, and OpenRedirectRecipe emit
double-URL-encoded probe variants in addition to the raw ones.

Run:  python -m pytest tests/test_recon_encoded_variants.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from classifier import Cat, Finding  # noqa: E402
import recon_collector as rc  # noqa: E402


def _finding(url, categories, *, method="GET", body=None):
    return Finding(method=method, url=url, score=10,
                   categories=list(categories), evidence=[], body=body)


def test_ssrf_recipe_emits_double_encoded_variant():
    f = _finding("https://api.example.com/fetch?url=https://orig.example/",
                 [Cat.SSRF])
    probes = rc.SSRFRecipe().probes(f)
    labels = [p.label for p in probes]
    # Raw 127.0.0.1 probe AND its double-encoded variant should both be present
    assert any(l.startswith("ssrf_http://127") for l in labels), f"missing raw probe in {labels}"
    assert any(l.startswith("ssrf_urlx2_") for l in labels), f"missing urlx2 variant in {labels}"

    # Confirm the urlx2 probe URL contains the double-encoded localhost target
    urlx2 = [p for p in probes if p.label.startswith("ssrf_urlx2_")][0]
    qs = parse_qs(urlparse(urlx2.url).query)
    target_val = qs.get("url", [""])[0]
    assert "%3A" in target_val or "%2F" in target_val, \
        f"expected URL-encoded marker in {target_val!r}"


def test_injection_recipe_emits_double_encoded_variants():
    f = _finding("https://api.example.com/search?q=hello", [Cat.INJECTION])
    probes = rc.InjectionRecipe().probes(f)
    labels = [p.label for p in probes]
    # Each base injection payload should have an _urlx2 sibling
    assert any(l == "sqli_quote" for l in labels)
    assert any(l == "sqli_quote_urlx2" for l in labels)
    assert any(l == "xss_basic" for l in labels)
    assert any(l == "xss_basic_urlx2" for l in labels)


def test_open_redirect_recipe_emits_double_encoded_variant():
    f = _finding("https://api.example.com/login?redirect=/dashboard",
                 [Cat.REDIRECT])
    probes = rc.OpenRedirectRecipe().probes(f)
    labels = [p.label for p in probes]
    assert "redirect_redirect_to_evil" in labels
    assert "redirect_redirect_urlx2" in labels


def test_ssrf_recipe_body_location_unchanged():
    # When the SSRF param is in the JSON body (not query string), we should
    # NOT emit double-encoded variants — that breaks JSON formatting and
    # wasn't the bypass we were targeting.
    body = '{"url": "https://orig.example/"}'
    f = _finding("https://api.example.com/webhook", [Cat.SSRF],
                 method="POST", body=body)
    probes = rc.SSRFRecipe().probes(f)
    labels = [p.label for p in probes]
    assert any(l.startswith("ssrf_") for l in labels)
    # No urlx2 variants in body-location mode
    assert not any(l.startswith("ssrf_urlx2_") for l in labels)
