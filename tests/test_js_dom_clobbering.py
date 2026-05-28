"""Tests for _detect_dom_clobbering in js_deep_analyzer.

Run:  python -m pytest tests/test_js_dom_clobbering.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import js_deep_analyzer as jda  # noqa: E402


def test_detects_window_fallback_init():
    content = 'var config = window.config || {api: "/v1"};'
    out = jda._detect_dom_clobbering(content, "app.js")
    fallback = [c for c in out if c.pattern == "window_fallback_init"]
    assert fallback, f"expected window_fallback_init, got {[c.pattern for c in out]}"
    assert fallback[0].identifier == "config"
    assert fallback[0].priority == "high"


def test_detects_document_named_element():
    content = 'if (document.userToken) { send(document.userToken.value); }'
    out = jda._detect_dom_clobbering(content, "auth.js")
    named = [c for c in out if c.pattern == "document_named_element"]
    assert named, f"expected document_named_element, got {[c.pattern for c in out]}"
    assert any(c.identifier == "userToken" for c in named)


def test_ignores_real_dom_apis():
    content = '''
        var el = document.querySelector("#x");
        document.body.appendChild(el);
        document.getElementById("y").focus();
        document.addEventListener("click", h);
    '''
    out = jda._detect_dom_clobbering(content, "ui.js")
    named = [c for c in out if c.pattern == "document_named_element"]
    assert not named, \
        f"real DOM APIs should not fire document_named_element, got {[c.identifier for c in named]}"


def test_truthy_check_requires_window_ref():
    bare = 'if (debug) { log("on"); }'
    out_bare = jda._detect_dom_clobbering(bare, "a.js")
    assert not [c for c in out_bare if c.pattern == "truthy_check_clobberable"]

    with_ref = 'var x = window.debug; if (debug) { log("on"); }'
    out_with = jda._detect_dom_clobbering(with_ref, "b.js")
    truthy = [c for c in out_with if c.pattern == "truthy_check_clobberable"]
    assert truthy, "expected truthy_check_clobberable when window.debug is also read"
    assert truthy[0].identifier == "debug"


def test_typeof_guard_suppresses_truthy_check():
    content = 'var x = window.debug; if (typeof debug !== "undefined" && debug) { log(); }'
    out = jda._detect_dom_clobbering(content, "guarded.js")
    truthy = [c for c in out if c.pattern == "truthy_check_clobberable"]
    assert not truthy, "typeof guard near the check should suppress the finding"


def test_getbyid_chained_unknown_property():
    content = 'var n = document.getElementById("widget").customConfig;'
    out = jda._detect_dom_clobbering(content, "x.js")
    chains = [c for c in out if c.pattern == "getbyid_prop_chain"]
    assert chains, f"expected getbyid_prop_chain, got {[c.pattern for c in out]}"


def test_getbyid_chained_known_property_ignored():
    content = 'var v = document.getElementById("input").value;'
    out = jda._detect_dom_clobbering(content, "x.js")
    chains = [c for c in out if c.pattern == "getbyid_prop_chain"]
    assert not chains, "known element props should not fire (value is in allowlist)"


def test_window_builtins_not_flagged():
    content = 'console.log(window.innerWidth, window.location, window.navigator);'
    out = jda._detect_dom_clobbering(content, "x.js")
    named = [c for c in out if c.pattern == "window_named_read"]
    assert not named, f"window builtins should be filtered, got {[c.identifier for c in named]}"


def test_in_result_to_dict():
    content = 'var config = window.config || {};'
    result = jda.JSAnalysisResult()
    result.dom_clobbering.extend(jda._detect_dom_clobbering(content, "app.js"))
    out = result.to_dict()
    assert "dom_clobbering" in out
    assert len(out["dom_clobbering"]) >= 1
    assert "pattern" in out["dom_clobbering"][0]
