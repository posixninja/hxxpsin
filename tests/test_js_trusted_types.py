"""Tests for _detect_trusted_types in js_deep_analyzer.

Covers policy-presence detection, violation emission, sink wrap-detection,
and TT↔DOM XSS dedup/enrichment in _deduplicate.

Run:  python -m pytest tests/test_js_trusted_types.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import js_deep_analyzer as jda  # noqa: E402


def test_detects_policy_creation():
    content = 'const p = trustedTypes.createPolicy("default", {createHTML: s => s});'
    tt = jda._detect_trusted_types(content, "app.js")
    assert tt.has_policy is True
    assert "default" in tt.policy_names
    assert tt.has_default_policy is True


def test_no_policy_means_innerHTML_violates():
    content = 'el.innerHTML = userInput;'
    tt = jda._detect_trusted_types(content, "v.js")
    assert tt.has_policy is False
    inner = [v for v in tt.violations if v.sink == "innerHTML"]
    assert inner, f"expected innerHTML violation, got {[v.sink for v in tt.violations]}"
    assert inner[0].has_policy_in_scope is False
    assert inner[0].priority == "high"


def test_innerHTML_with_policy_wrap_is_clean():
    content = (
        'const policy = trustedTypes.createPolicy("p", {createHTML: s => s});'
        'el.innerHTML = policy.createHTML(userInput);'
    )
    tt = jda._detect_trusted_types(content, "ok.js")
    assert tt.has_policy is True
    inner = [v for v in tt.violations if v.sink == "innerHTML"]
    assert not inner, \
        f"policy-wrapped innerHTML should not violate, got {[v.matched_code for v in inner]}"


def test_worker_with_variable_url_violates():
    content = 'new Worker(userUrl);'
    tt = jda._detect_trusted_types(content, "w.js")
    workers = [v for v in tt.violations if v.sink == "worker"]
    assert workers, f"expected worker violation, got {[v.sink for v in tt.violations]}"


def test_worker_with_literal_url_clean():
    content = 'new Worker("/static/worker.js");'
    tt = jda._detect_trusted_types(content, "w.js")
    workers = [v for v in tt.violations if v.sink == "worker"]
    assert not workers, "static literal Worker URL should not violate"


def test_react_dsi_wrapped_with_dompurify():
    content = (
        'React.createElement("div", { '
        'dangerouslySetInnerHTML: {__html: DOMPurify.sanitize(html)} });'
    )
    tt = jda._detect_trusted_types(content, "r.js")
    dsi = [v for v in tt.violations if v.sink == "dangerouslySetInnerHTML"]
    assert not dsi, "DOMPurify-wrapped dangerouslySetInnerHTML should be clean"


def test_react_dsi_unwrapped_violates():
    content = (
        'React.createElement("div", { '
        'dangerouslySetInnerHTML: {__html: userHtml} });'
    )
    tt = jda._detect_trusted_types(content, "r.js")
    dsi = [v for v in tt.violations if v.sink == "dangerouslySetInnerHTML"]
    assert dsi, f"expected dsi violation, got {[v.sink for v in tt.violations]}"


def test_csp_hint_detected():
    content = '/* CSP: require-trusted-types-for "script" */ el.innerHTML = x;'
    tt = jda._detect_trusted_types(content, "csp.js")
    assert tt.enforces_csp_hint is True


def test_tt_dom_xss_dedup_enrichment():
    """When both DOM XSS and TT fire on the same innerHTML sink with no
    policy in the file, _deduplicate should annotate the DOM XSS finding
    with 'no_tt_policy', bump its priority to high, and drop the TT
    violation as a duplicate."""
    content = 'var q = location.search; el.innerHTML = q;'
    result = jda.JSAnalysisResult()
    result.dom_xss.extend(jda._detect_dom_xss(content, "x.js"))
    result.trusted_types.append(jda._detect_trusted_types(content, "x.js"))

    assert any(x.sink == "innerHTML" for x in result.dom_xss), \
        "precondition: DOM XSS should fire on innerHTML"
    pre_tt = [v for v in result.trusted_types[0].violations if v.sink == "innerHTML"]
    assert pre_tt, "precondition: TT should also flag innerHTML"

    jda._deduplicate(result)

    inner_xss = [x for x in result.dom_xss if x.sink == "innerHTML"]
    assert len(inner_xss) == 1
    assert "no_tt_policy" in inner_xss[0].notes
    assert inner_xss[0].priority == "high"

    post_tt = [v for v in result.trusted_types[0].violations if v.sink == "innerHTML"]
    assert not post_tt, \
        f"TT innerHTML violation should be dropped after enrichment, got {post_tt}"


def test_standalone_tt_violations_survive_dedup():
    """Sinks DOM XSS doesn't cover (Worker, script_src_assign) must survive
    _deduplicate even when DOM XSS fires elsewhere in the same file."""
    content = 'var q = location.search; el.innerHTML = q; new Worker(workerSrc);'
    result = jda.JSAnalysisResult()
    result.dom_xss.extend(jda._detect_dom_xss(content, "x.js"))
    result.trusted_types.append(jda._detect_trusted_types(content, "x.js"))
    jda._deduplicate(result)

    workers = [v for v in result.trusted_types[0].violations if v.sink == "worker"]
    assert workers, "worker violation should survive dedup (no DOM XSS counterpart)"


def test_to_dict_shape():
    content = 'el.innerHTML = userInput;'
    result = jda.JSAnalysisResult()
    result.trusted_types.append(jda._detect_trusted_types(content, "t.js"))
    out = result.to_dict()
    assert "trusted_types" in out
    assert len(out["trusted_types"]) == 1
    entry = out["trusted_types"][0]
    assert entry["source_file"] == "t.js"
    assert "violations" in entry
    assert "has_policy" in entry
