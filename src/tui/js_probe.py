"""
js_probe.py — TUI-side runner for JS deep analysis.

Runs JSDeepAnalyzer on a single JS bundle URL and returns a flat list of
finding dicts that can be merged into state.probe_results["js"].

Called via probe_runner.RUNNERS["js"].
"""
from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_path() -> None:
    src = str(Path(__file__).resolve().parents[1])
    if src not in sys.path:
        sys.path.insert(0, src)


async def run_js(req: dict) -> list[dict]:
    """
    Analyze a JS bundle URL with JSDeepAnalyzer.

    req must be a request dict with url pointing to a .js resource.
    Returns a flat list of finding dicts (endpoint, secret, dom_xss,
    auth_smell, graphql_op) tagged with _probe="js".
    """
    _ensure_src_path()
    from js_deep_analyzer import JSDeepAnalyzer

    url = req.get("url", "")
    if not url:
        return []

    result = await JSDeepAnalyzer([url]).run()
    findings: list[dict] = []

    for ep in result.endpoints:
        findings.append({
            "_probe":      "js",
            "type":        "endpoint",
            "path":        ep.path,
            "method":      ep.method_hint,
            "risks":       ep.risks,
            "reasons":     ep.reasons,
            "source_file": ep.source_file,
            "url":         ep.source_file,
            "verdict":     "likely" if ep.risks else "informational",
            "category":    "JS Endpoint",
        })

    for s in result.secrets:
        if s.public_by_design:
            continue
        findings.append({
            "_probe":        "js",
            "type":          "secret",
            "secret_type":   s.type,
            "value_preview": s.value_preview,
            "entropy":       s.entropy,
            "source_file":   s.source_file,
            "url":           s.source_file,
            "verdict":       "confirmed",
            "category":      "JS Secret",
        })

    for x in result.dom_xss:
        findings.append({
            "_probe":      "js",
            "type":        "dom_xss",
            "source":      x.source,
            "sink":        x.sink,
            "priority":    x.priority,
            "source_file": x.source_file,
            "url":         x.source_file,
            "verdict":     "likely",
            "category":    "DOM XSS",
        })

    for a in result.auth_smells:
        findings.append({
            "_probe":      "js",
            "type":        "auth_smell",
            "pattern":     a.pattern,
            "role_value":  a.role_value,
            "source_file": a.source_file,
            "url":         a.source_file,
            "verdict":     "informational",
            "category":    "JS Auth Pattern",
        })

    for g in result.graphql_ops:
        findings.append({
            "_probe":      "js",
            "type":        "graphql_op",
            "op_type":     g.op_type,
            "name":        g.name,
            "risk":        g.risk,
            "source_file": g.source_file,
            "url":         g.source_file,
            "verdict":     "informational" if not g.risk else "likely",
            "category":    "GraphQL",
        })

    return findings
