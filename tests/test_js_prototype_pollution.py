"""Tests for _detect_prototype_pollution in js_deep_analyzer.

Run:  python -m pytest tests/test_js_prototype_pollution.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import js_deep_analyzer as jda  # noqa: E402


def test_detects_lodash_merge_with_user_input():
    content = 'var body = JSON.parse(req.body); _.merge(target, body);'
    out = jda._detect_prototype_pollution(content, "app.js")
    lodash = [p for p in out if p.sink == "lodash_merge"]
    assert lodash, f"expected lodash_merge, got {[p.sink for p in out]}"
    assert lodash[0].severity == "high"
    assert lodash[0].near_user_input is True
    assert lodash[0].target == "merge"


def test_detects_jquery_deep_extend():
    content = 'var dst = {}; jQuery.extend(true, dst, src);'
    out = jda._detect_prototype_pollution(content, "j.js")
    jq = [p for p in out if p.sink == "jquery_extend_deep"]
    assert jq, f"expected jquery_extend_deep, got {[p.sink for p in out]}"


def test_detects_proto_literal_bracket():
    content = 'obj["__proto__"].polluted = 1;'
    out = jda._detect_prototype_pollution(content, "p.js")
    lit = [p for p in out if p.sink == "proto_literal"]
    assert lit, f"expected proto_literal, got {[p.sink for p in out]}"


def test_detects_constructor_prototype():
    content = 'obj.constructor.prototype.evil = true;'
    out = jda._detect_prototype_pollution(content, "p.js")
    lit = [p for p in out if p.sink == "proto_literal"]
    assert lit, f"expected proto_literal from constructor.prototype"


def test_recursive_merge_loop():
    content = '''
        function merge(dst, src) {
            for (var k in src) {
                dst[k] = src[k];
            }
        }
    '''
    out = jda._detect_prototype_pollution(content, "m.js")
    recs = [p for p in out if p.sink == "recursive_merge"]
    assert recs, f"expected recursive_merge, got {[p.sink for p in out]}"
    # No user-input source nearby in this snippet — medium severity.
    assert recs[0].severity == "medium"


def test_object_assign_empty_target_with_json_parse():
    content = 'var merged = Object.assign({}, JSON.parse(x));'
    out = jda._detect_prototype_pollution(content, "o.js")
    oa = [p for p in out if p.sink == "object_assign"]
    assert oa, f"expected object_assign, got {[p.sink for p in out]}"
    assert oa[0].severity == "high"


def test_object_assign_named_target_low():
    content = 'Object.assign(myObj, otherObj);'
    out = jda._detect_prototype_pollution(content, "o.js")
    oa = [p for p in out if p.sink == "object_assign"]
    assert oa, "expected object_assign finding"
    assert oa[0].severity in ("low", "medium"), \
        f"named target without user input should not be high, got {oa[0].severity}"


def test_path_setter_helper():
    content = '_.set(target, "a.b.c", value);'
    out = jda._detect_prototype_pollution(content, "p.js")
    # _.set should also match _PROTO_LODASH_RE — both findings are fine,
    # but a path_setter or lodash_merge with sink=set must exist.
    assert any(p.sink == "lodash_merge" and p.target == "set" for p in out), \
        f"expected lodash set, got {[(p.sink, p.target) for p in out]}"


def test_in_result_to_dict():
    content = '_.merge({}, JSON.parse(input));'
    result = jda.JSAnalysisResult()
    result.prototype_pollution.extend(
        jda._detect_prototype_pollution(content, "x.js"))
    out = result.to_dict()
    assert "prototype_pollution" in out
    assert len(out["prototype_pollution"]) >= 1
    assert "severity" in out["prototype_pollution"][0]


def test_dedup_collapses_same_sink_in_file():
    content = '_.merge(a, b); _.merge(a, b);'
    result = jda.JSAnalysisResult()
    result.prototype_pollution.extend(
        jda._detect_prototype_pollution(content, "x.js"))
    jda._deduplicate(result)
    lodash = [p for p in result.prototype_pollution if p.sink == "lodash_merge"]
    assert len(lodash) == 1, f"expected 1 after dedup, got {len(lodash)}"
