"""
reporter.py — Markdown and JSON report generator for hxxpsin.

Consumes output from every upstream module and writes two files:
  {out_dir}/report.md   — structured Markdown for reading during the challenge
  {out_dir}/report.json — full machine-readable data

Usage:
    reporter = Reporter(result, profile=profile, desync=desync, enrichment=enrichment)
    md_path, json_path = reporter.write("./output")
    print(reporter.to_markdown())
"""

import json
from datetime import date
from pathlib import Path
from typing import Optional

from classifier import ClassifierResult, Cat, Finding
from desync_probe import DesyncResult
from stackprint import StackProfile


_SEVERITY_LABEL = {
    "high": "🔴 HIGH",
    "medium": "🟡 MED",
    "low": "🟢 LOW",
    "info": "ℹ️  INFO",
}

_CAT_ORDER = [
    Cat.IDOR, Cat.BFLA, Cat.MASS_ASSIGN, Cat.ADMIN, Cat.GRAPHQL,
    Cat.WEBSOCKET, Cat.SSRF, Cat.UPLOAD, Cat.RACE, Cat.INJECTION,
    Cat.AUTH, Cat.WRITE,
]


class Reporter:
    def __init__(
        self,
        result: ClassifierResult,
        target: str = "",
        profile: Optional[StackProfile] = None,
        desync: Optional[DesyncResult] = None,
        jwt=None,           # Optional[JWTAttackResult]
        params=None,        # Optional[ParamMineResult]
        active_scan=None,   # Optional[ActiveScanResult]
        redirect=None,      # Optional[OpenRedirectResult]
        crlf=None,          # Optional[CRLFResult]
        nosql=None,         # Optional[NoSQLResult]
        auto_auth=None,     # Optional[AuthSession]
        auth_bypass=None,   # Optional[AuthBypassResult]
        challenges=None,    # Optional[ChallengeTrackerResult]
        idor=None,          # Optional[IDORResult]
        dom_xss=None,       # Optional[DOMXSSResult]
        files=None,         # Optional[FileGrabResult]
        har=None,           # Optional[HARImportResult]
        access_replay=None, # Optional[AccessReplayResult]
        enrichment=None,    # Optional[EnrichmentResult]
        data_extract=None,  # Optional[DataExtractResult]
        llm_verification=None,  # Optional[LLMVerificationResult]
        upload_probe=None,  # Optional[UploadProbeResult]
        sql_dump=None,      # Optional[SQLDumpResult]
        ws_probe=None,      # Optional[WSProbeResult]
        ct_probe=None,      # Optional[CTProbeResult]
        auto_fuzz=None,     # Optional[AutoFuzzResult]
    ):
        self._result = result
        self._target = target
        self._profile = profile
        self._desync = desync
        self._jwt = jwt
        self._params = params
        self._active_scan = active_scan
        self._redirect = redirect
        self._crlf = crlf
        self._nosql = nosql
        self._auto_auth = auto_auth
        self._auth_bypass = auth_bypass
        self._challenges = challenges
        self._idor = idor
        self._dom_xss = dom_xss
        self._files = files
        self._har = har
        self._access_replay = access_replay
        self._enrichment = enrichment
        self._data_extract = data_extract
        self._llm_verification = llm_verification
        self._upload_probe = upload_probe
        self._sql_dump = sql_dump
        self._ws_probe = ws_probe
        self._ct_probe = ct_probe
        self._auto_fuzz = auto_fuzz

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def write(self, out_dir: str) -> tuple[str, str]:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)

        md_path = d / "report.md"
        json_path = d / "report.json"

        md_path.write_text(self.to_markdown())
        json_path.write_text(json.dumps(self.to_dict(), indent=2))

        return str(md_path), str(json_path)

    def to_markdown(self) -> str:
        sections: list[str] = []
        sections.append(self._section_header())
        if self._profile:
            sections.append(self._section_stack())
        sections.append(self._section_top_findings())
        sections.append(self._section_by_category())
        if self._jwt and self._jwt.findings:
            sections.append(self._section_jwt())
        if self._params and self._params.interesting:
            sections.append(self._section_param_mine())
        if self._auto_auth and self._auto_auth.has_auth:
            sections.append(self._section_auto_auth())
        if self._auth_bypass and self._auth_bypass.findings:
            sections.append(self._section_auth_bypass())
        if self._idor and self._idor.findings:
            sections.append(self._section_idor())
        if self._dom_xss and self._dom_xss.findings:
            sections.append(self._section_dom_xss())
        if self._files and self._files.grabbed:
            sections.append(self._section_files())
        if self._access_replay and self._access_replay.unlocked:
            sections.append(self._section_access_replay())
        if self._challenges and self._challenges.newly_triggered:
            sections.append(self._section_challenges())
        if self._redirect and self._redirect.findings:
            sections.append(self._section_redirect())
        if self._crlf and self._crlf.findings:
            sections.append(self._section_crlf())
        if self._ct_probe and self._ct_probe.findings:
            sections.append(self._section_ct_probe())
        if self._auto_fuzz and self._auto_fuzz.findings:
            sections.append(self._section_auto_fuzz())
        if self._active_scan and self._active_scan.findings:
            sections.append(self._section_active_scan())
        if self._nosql and self._nosql.findings:
            sections.append(self._section_nosql())
        if self._desync and self._desync.findings:
            sections.append(self._section_desync())
        if self._result.websocket_findings:
            sections.append(self._section_websockets())
        if self._ws_probe and self._ws_probe.confirmed:
            sections.append(self._section_ws_probe())
        if self._result.js_route_findings:
            sections.append(self._section_js_routes())
        if self._enrichment and (self._enrichment.users or self._enrichment.secrets
                                  or self._enrichment.hosts):
            sections.append(self._section_enrichment())
        if self._data_extract and self._data_extract.records_pulled:
            sections.append(self._section_data_extract())
        if self._upload_probe and self._upload_probe.findings:
            sections.append(self._section_upload_probe())
        if self._sql_dump and (self._sql_dump.fingerprints or self._sql_dump.rows_dumped):
            sections.append(self._section_sql_dump())
        if self._llm_verification and self._llm_verification.findings:
            sections.append(self._section_llm_verification())
        if self._profile:
            sections.append(self._section_recommended())
        return "\n\n---\n\n".join(sections) + "\n"

    def to_dict(self) -> dict:
        out: dict = {
            "target": self._target,
            "date": str(date.today()),
            "summary": self._summary_counts(),
            "top_findings": [f.to_dict() for f in self._result.request_findings[:20]],
            "findings_by_category": {
                cat: [f.to_dict() for f in findings]
                for cat, findings in self._result.by_category.items()
            },
            "websocket_findings": [w.to_dict() for w in self._result.websocket_findings],
            "js_routes": self._result.js_route_findings[:30],
            "js_constants": self._result.js_constants[:20],
        }
        if self._profile:
            out["stack"] = self._profile.to_dict()
        if self._desync:
            out["desync"] = self._desync.to_dict()
        if self._enrichment:
            out["enrichment"] = self._enrichment.summary()
        if self._data_extract:
            out["data_extract"] = self._data_extract.to_dict()
        if self._jwt:
            out["jwt_attacks"] = self._jwt.to_dict()
        if self._params:
            out["param_mine"] = self._params.to_dict()
        if self._active_scan:
            out["active_scan"] = self._active_scan.to_dict()
        if self._redirect:
            out["open_redirect"] = self._redirect.to_dict()
        if self._crlf:
            out["crlf"] = self._crlf.to_dict()
        if self._nosql:
            out["nosql"] = self._nosql.to_dict()
        if self._auto_auth:
            out["auto_auth"] = self._auto_auth.to_dict()
        if self._auth_bypass:
            out["auth_bypass"] = self._auth_bypass.to_dict()
        if self._idor:
            out["idor"] = self._idor.to_dict()
        if self._dom_xss:
            out["dom_xss"] = self._dom_xss.to_dict()
        if self._files:
            out["files"] = self._files.to_dict()
        if self._challenges:
            out["challenges"] = self._challenges.to_dict()
        if self._ws_probe:
            out["ws_probe"] = self._ws_probe.to_dict()
        if self._ct_probe:
            out["ct_probe"] = self._ct_probe.to_dict()
        if self._auto_fuzz:
            out["auto_fuzz"] = self._auto_fuzz.to_dict()
        return out

    # ------------------------------------------------------------------
    # Markdown section builders
    # ------------------------------------------------------------------

    def _section_header(self) -> str:
        counts = self._summary_counts()
        # Data source — Crawler (live Playwright) vs HAR import vs other
        if self._har:
            ds = (f"**Data source:** Imported from HAR — "
                  f"{self._har.source_tool} {self._har.source_version}, "
                  f"{len(self._har.requests)} requests "
                  f"(crawler skipped)")
        else:
            ds = "**Data source:** Live Playwright crawl"
        lines = [
            f"# hxxpsin — {self._target or 'unknown'}",
            f"**Date:** {date.today()}",
            ds,
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| **Total confirmed exploits (all subsystems)** | **{counts['total_confirmed']}** |",
            f"| Requests captured | {counts['requests']} |",
            f"| Unique endpoints scored | {counts['findings']} |",
            f"| High-priority findings | {counts['high']} |",
            f"| Categories triggered | {counts['categories']} |",
            f"| WebSocket channels | {counts['websockets']} |",
            f"| JS-discovered routes | {counts['js_routes']} |",
        ]
        if self._desync:
            lines.append(f"| Desync/cache risks | {counts['desync']} |")
        if self._params and counts["params_found"]:
            lines.append(f"| Hidden params found | {counts['params_found']} |")
        # Per-subsystem confirmation breakdown — only show the rows that
        # actually have something to report.
        breakdown = [
            ("JWT attacks", counts["jwt_confirmed"], self._jwt),
            ("Active scan (injection)", counts["active_scan_confirmed"], self._active_scan),
            ("Auth bypass (SQLi at login)", counts["auth_bypass_confirmed"], self._auth_bypass),
            ("NoSQL injection", counts["nosql_confirmed"], self._nosql),
            ("CRLF injection", counts["crlf_confirmed"], self._crlf),
            ("Open redirect", counts["redirect_confirmed"], self._redirect),
            ("Cross-account IDOR / BOLA", counts["idor_confirmed"], self._idor),
            ("DOM XSS (browser-verified)", counts["dom_xss_confirmed"], self._dom_xss),
            ("WebSocket security", counts["ws_probe_confirmed"], self._ws_probe),
            ("Content-type confusion", counts["ct_probe_confirmed"], self._ct_probe),
            ("Auto-fuzz anomalies",   counts["auto_fuzz_anomalies"],  self._auto_fuzz),
        ]
        for label, n, present in breakdown:
            if present and n:
                lines.append(f"| &nbsp;&nbsp;↳ {label} confirmed | {n} |")
        return "\n".join(lines)

    def _section_stack(self) -> str:
        p = self._profile
        lines = ["## Stack Fingerprint", ""]

        if p.detected:
            lines += ["| Category | Detected |", "|---|---|"]
            for cat, techs in p.detected.items():
                lines.append(f"| {cat} | {', '.join(techs)} |")
            lines.append("")

        lines.append(f"**Protocols:** {', '.join(p.protocols) or 'unknown'}")

        if p.risk_flags:
            lines += ["", "**Risk flags:**"]
            for f in p.risk_flags:
                lines.append(f"- `{f}`")

        if p.interesting_paths:
            lines += ["", "**Interesting paths confirmed:**"]
            lines.append("`" + "`, `".join(p.interesting_paths[:12]) + "`")

        if p.websocket_urls:
            lines += ["", "**WebSocket URLs:**"]
            for u in p.websocket_urls:
                lines.append(f"- `{u}`")

        return "\n".join(lines)

    def _section_top_findings(self) -> str:
        findings = self._result.request_findings[:15]
        if not findings:
            return "## Top Findings\n\n_No findings scored._"

        lines = [
            "## Top Findings",
            "",
            "| Score | Method | URL | Categories |",
            "|---|---|---|---|",
        ]
        for f in findings:
            cats = ", ".join(f.categories[:2])
            url = f.url[:80] + ("…" if len(f.url) > 80 else "")
            lines.append(f"| {f.score} | `{f.method}` | `{url}` | {cats} |")
        return "\n".join(lines)

    def _section_by_category(self) -> str:
        lines = ["## Findings by Category"]

        for cat in _CAT_ORDER:
            cat_findings = self._result.by_category.get(cat, [])
            if not cat_findings:
                continue

            lines += ["", f"### {cat} ({len(cat_findings)} endpoint{'s' if len(cat_findings) > 1 else ''})"]

            for f in cat_findings[:5]:
                url = f.url[:90] + ("…" if len(f.url) > 90 else "")
                lines += [
                    "",
                    f"**`{f.method} {url}`** — score {f.score}",
                ]
                for ev in f.evidence:
                    lines.append(f"- {ev}")
                if f.body:
                    snippet = f.body[:120].replace("\n", " ")
                    lines.append(f"> body: `{snippet}`")

        return "\n".join(lines)

    def _section_desync(self) -> str:
        lines = ["## Protocol / Cache Risks"]
        for finding in self._desync.findings:
            sev = _SEVERITY_LABEL.get(finding.severity, finding.severity.upper())
            lines += [
                "",
                f"### {sev} — {finding.risk}",
                f"**Probe:** {finding.probe}  **URL:** `{finding.url}`",
                "",
                "**Signals:**",
            ]
            for s in finding.signals:
                lines.append(f"- {s}")
            lines += ["", "**Manual tests:**"]
            for t in finding.manual_tests:
                lines.append(f"1. {t}")
        return "\n".join(lines)

    def _section_websockets(self) -> str:
        lines = ["## WebSocket Channels", ""]
        for ws in self._result.websocket_findings:
            lines.append(f"**`{ws.url}`** — score {ws.score}")
            for ev in ws.evidence:
                lines.append(f"- {ev}")
            if ws.keys_observed:
                lines.append(f"- Keys observed: `{'`, `'.join(ws.keys_observed)}`")
            lines.append("")
        return "\n".join(lines)

    def _section_js_routes(self) -> str:
        lines = ["## JS-Discovered Routes", ""]
        for r in self._result.js_route_findings[:20]:
            lines.append(f"- `{r['route']}` (score {r['score']})")
        return "\n".join(lines)

    def _section_sql_dump(self) -> str:
        s = self._sql_dump
        fp = ", ".join(f"`{f.dialect}` ({f.confidence:.2f})" for f in s.fingerprints) or "—"
        lines = [
            f"## SQL Dump ({s.tables_dumped} tables, {s.rows_dumped} rows pulled)",
            "",
            f"**Dialect fingerprints:** {fp}",
            "",
            f"For every confirmed/likely SQLi finding from active scan we "
            f"fingerprinted the DBMS, dumped the schema via UNION extraction, "
            f"and pulled rows from interesting tables (users, accounts, "
            f"sessions, orders, payment, secrets). Per-table data lives in "
            f"`{s.out_dir}/data/`. Rows that match a discovered identity were "
            f"cross-linked into `enrichment/users/<id>/db_rows/<table>.json`.",
            "",
        ]
        if s.schema:
            lines.append(f"### Schema ({len(s.schema)} tables discovered)")
            lines.append("")
            for t in s.schema[:30]:
                lines.append(f"- `{t.name}`")
            if len(s.schema) > 30:
                lines.append(f"- _... {len(s.schema) - 30} more in `schema/tables.txt`_")
            lines.append("")
        if s.notes:
            lines.append("**Notes:**")
            for n in s.notes[:8]:
                lines.append(f"- {n}")
        return "\n".join(lines)

    def _section_upload_probe(self) -> str:
        u = self._upload_probe
        lines = [
            f"## File Upload Bypass Tests "
            f"({len(u.confirmed)} confirmed RCE/XSS, {len(u.accepted)} accepted, "
            f"{u.tests_sent} tests across {u.endpoints_tested} endpoints)",
            "",
            f"For every classified upload endpoint we run the canonical "
            f"bypass suite: magic-byte spoof (PNG header + PHP body), "
            f"double extension (`shell.php.png`), Content-Type bypass, "
            f"path traversal in filename, null-byte truncation, SVG with "
            f"embedded `<script>`, GIF/PHP polyglot, and 10 MB oversized "
            f"junk. Uploaded artifacts and server responses are saved under "
            f"`{u.out_dir}/<endpoint>/<test>__*` for replay/inspection.",
            "",
            "| Test | Endpoint | filename | CT | Status | Verdict | Marker |",
            "|---|---|---|---|---|---|---|",
        ]
        ordered = sorted(u.findings, key=lambda f: (
            0 if f.verdict == "confirmed" else
            1 if f.verdict == "accepted" else
            2 if f.verdict == "likely" else 3
        ))
        for f in ordered[:50]:
            ep = f.endpoint if len(f.endpoint) <= 50 else f.endpoint[:40] + "…" + f.endpoint[-7:]
            lines.append(
                f"| `{f.test_name}` | `{ep}` | `{f.filename_sent}` | "
                f"`{f.content_type_sent}` | {f.response_status} | "
                f"`{f.verdict}` | `{f.execution_marker or '-'}` |"
            )
        return "\n".join(lines)

    def _section_llm_verification(self) -> str:
        v = self._llm_verification
        lines = [
            f"## LLM Verification ({v.model} via {v.host}) — "
            f"{v.promoted_to_confirmed} promoted, {v.refuted} refuted, "
            f"{v.inconclusive} inconclusive, {v.errors} errors",
            "",
            "Each 'likely' heuristic finding was independently re-evaluated by a "
            "local Ollama model. The LLM verdict is **additive** — it never "
            "overrides the heuristic. Treat 'promoted' (heuristic=likely + "
            "llm=confirmed) as the highest-priority second opinion.",
            "",
            "| Probe | Heuristic | LLM | URL | Reason |",
            "|---|---|---|---|---|",
        ]
        # Promoted findings first, then refuted, then inconclusive
        order_key = lambda f: (
            0 if f.get("llm") == "confirmed" and f.get("heuristic") == "likely"
            else 1 if f.get("llm") == "refuted"
            else 2
        )
        for f in sorted(v.findings, key=order_key)[:60]:
            url = f.get("url") or ""
            if len(url) > 60:
                url = url[:50] + "…" + url[-9:]
            reason = (f.get("reason") or "")[:120]
            lines.append(
                f"| `{f.get('kind')}` | `{f.get('heuristic')}` | "
                f"`{f.get('llm')}` | `{url}` | {reason} |"
            )
        return "\n".join(lines)

    def _section_enrichment(self) -> str:
        e = self._enrichment
        s = e.summary()
        by_type = ", ".join(f"`{k}`: {v}" for k, v in sorted(s["users_by_type"].items())) or "—"
        lines = [
            f"## Enrichment ({s['users']} identities, {s['secrets']} secrets, "
            f"{s['hosts']} hosts, {s['images_analyzed']} images, "
            f"{s['unvisited_urls']} unvisited URLs)",
            "",
            f"**By type:** {by_type}",
            "",
            f"All structured data is in `{s['out_dir']}/`. Each entity has its "
            f"own folder with `record.json`, `provenance.json`, and (for users) "
            f"`auth.json`/`images/` if creds or images were discovered.",
            "",
        ]
        if e.users:
            lines.append("### Top identities (by enrichment score)")
            lines.append("")
            lines.append("| Type | ID | Emails | Usernames | Auth |")
            lines.append("|---|---|---|---|---|")
            top = sorted(e.users.values(), key=lambda u: -u.score)[:25]
            for u in top:
                emails = ", ".join(sorted(u.emails)[:2]) or "—"
                names = ", ".join(sorted(u.usernames)[:2]) or "—"
                auth_marker = "✓" if u.auth_credentials else "—"
                lines.append(
                    f"| `{u.entity_type}` | `{u.canonical_id}` | "
                    f"`{emails}` | `{names}` | {auth_marker} |"
                )
            lines.append("")
        if e.oauth_apps:
            lines.append("### OAuth applications")
            lines.append("")
            for app in e.oauth_apps.values():
                redirects = ", ".join(sorted(app.redirect_uris)[:3]) or "—"
                lines.append(
                    f"- **`{app.client_id[:60]}`** "
                    f"({'with secret' if app.client_secret else 'no secret'}) "
                    f"redirects: `{redirects}`"
                )
            lines.append("")
        if e.secrets:
            lines.append("### Secrets discovered (top 15 by entropy)")
            lines.append("")
            for sec in sorted(e.secrets.values(), key=lambda x: -x.entropy)[:15]:
                preview = sec.value[:60] + ("…" if len(sec.value) > 60 else "")
                lines.append(
                    f"- `{sec.type_hint}` (entropy {sec.entropy:.1f}) — `{preview}`"
                )
            lines.append("")
        if e.hosts:
            lines.append("### Hosts discovered (top 15)")
            lines.append("")
            for h in sorted(e.hosts.values(), key=lambda x: x.hostname)[:15]:
                ips = f" [{', '.join(sorted(h.ips))}]" if h.ips else ""
                lines.append(f"- `{h.hostname}`{ips} — {len(h.related_urls)} URLs")
            lines.append("")
        return "\n".join(lines)

    def _section_data_extract(self) -> str:
        d = self._data_extract
        confirmed = getattr(d, "confirmed_idor_endpoints", 0)
        public = getattr(d, "public_endpoints", d.shared_endpoints)
        auth_req = getattr(d, "auth_required_endpoints", 0)
        lines = [
            f"## IDOR Data Extraction "
            f"({d.records_pulled} records pulled — "
            f"**{confirmed} confirmed IDOR**, "
            f"{d.per_user_endpoints} per-user, {public} public, "
            f"{auth_req} auth-required, {d.error_endpoints} errors)",
            "",
            f"Walked endpoints from confirmed/likely IDOR findings using each "
            f"available account PLUS an anonymous baseline. The anon column "
            f"distinguishes 'truly public' (anon=2xx, same content) from "
            f"'access bypass' (anon=4xx, but accounts read the same content — "
            f"someone is reading data they don't own). Records under "
            f"`{d.out_dir}/`:",
            "",
            f"- `confirmed_idor/<endpoint>/A.json,B.json,anon.json` — auth-bypass proof",
            f"- `per_user/<endpoint>/` — each account sees its own data (correct behaviour)",
            f"- `public/<endpoint>.json` — genuinely shared content",
            f"- `errors/<endpoint>.txt` — 5xx responses",
            "",
            "| Kind | Endpoint | anon | A | B | Distinct | Saved as |",
            "|---|---|---|---|---|---|---|",
        ]
        # Sort confirmed_idor first so the most important rows are at the top
        ordered = sorted(d.endpoint_summaries,
                         key=lambda r: 0 if r.get("kind") == "confirmed_idor" else 1)
        for r in ordered[:40]:
            lines.append(
                f"| `{r['kind']}` | `{r['endpoint'][:55]}` | "
                f"{r.get('anon_status') or '-'} | "
                f"{r.get('a_status') or '-'} | "
                f"{r.get('b_status') or '-'} | "
                f"{r['distinct_bodies']} | "
                f"`{r['saved_to']}` |"
            )
        return "\n".join(lines)

    def _section_recommended(self) -> str:
        tests = self._profile.recommended_tests
        if not tests:
            return ""
        lines = ["## Recommended Manual Tests", ""]
        for i, t in enumerate(tests[:20], 1):
            lines.append(f"{i}. {t}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _summary_counts(self) -> dict:
        # Per-subsystem confirmation counters. The sum is reported as the
        # headline "total confirmed exploits across all subsystems" — that
        # number is what the user actually wants to see.
        jwt_c = len(self._jwt.confirmed) if self._jwt else 0
        active_c = len(self._active_scan.confirmed) if self._active_scan else 0
        auth_bypass_c = len(self._auth_bypass.confirmed) if self._auth_bypass else 0
        nosql_c = len(self._nosql.confirmed) if self._nosql else 0
        crlf_c = len(self._crlf.confirmed) if self._crlf else 0
        redirect_c = len(self._redirect.confirmed) if self._redirect else 0
        idor_c = len(self._idor.confirmed) if self._idor else 0
        dom_xss_c = len(self._dom_xss.confirmed) if self._dom_xss else 0
        ws_probe_c = len(self._ws_probe.confirmed) if self._ws_probe else 0
        ct_probe_c = len(self._ct_probe.confirmed) if self._ct_probe else 0
        auto_fuzz_c = len(self._auto_fuzz.findings) if self._auto_fuzz else 0
        total_confirmed = (
            jwt_c + active_c + auth_bypass_c + nosql_c
            + crlf_c + redirect_c + idor_c + dom_xss_c + ws_probe_c + ct_probe_c + auto_fuzz_c
        )
        return {
            "requests": sum(
                len(v) for v in self._result.by_category.values()
            ),
            "findings": len(self._result.request_findings),
            "high": sum(
                1 for f in self._result.request_findings if f.score >= 10
            ),
            "categories": len(self._result.by_category),
            "websockets": len(self._result.websocket_findings),
            "js_routes": len(self._result.js_route_findings),
            "desync": len(self._desync.findings) if self._desync else 0,
            "jwt_confirmed": jwt_c,
            "params_found": len(self._params.interesting) if self._params else 0,
            "active_scan_confirmed": active_c,
            "auth_bypass_confirmed": auth_bypass_c,
            "nosql_confirmed": nosql_c,
            "crlf_confirmed": crlf_c,
            "redirect_confirmed": redirect_c,
            "idor_confirmed": idor_c,
            "dom_xss_confirmed": dom_xss_c,
            "ws_probe_confirmed": ws_probe_c,
            "ct_probe_confirmed": ct_probe_c,
            "auto_fuzz_anomalies": auto_fuzz_c,
            "total_confirmed": total_confirmed,
        }

    def _section_jwt(self) -> str:
        jwt = self._jwt
        lines = [f"## JWT Attack Results ({len(jwt.confirmed)} confirmed / {len(jwt.findings)} total)", ""]

        verdict_order = {"confirmed": 0, "likely": 1, "not_confirmed": 2}
        sorted_findings = sorted(jwt.findings, key=lambda f: verdict_order.get(f.verdict, 9))

        for f in sorted_findings:
            icon = "✓" if f.verdict == "confirmed" else ("△" if f.verdict == "likely" else "✗")
            lines.append(f"**{icon} [{f.verdict.upper()}]** `{f.attack_name}` — `{f.method} {f.endpoint}`")
            lines.append(f"> {f.evidence}")
            if f.cracked_secret:
                lines.append(f"> Cracked secret: `{f.cracked_secret}`")
            if f.crafted_token and f.verdict == "confirmed":
                short = f.crafted_token[:60] + "..." if len(f.crafted_token) > 60 else f.crafted_token
                lines.append(f"> Crafted token: `{short}`")
            lines.append("")

        return "\n".join(lines)

    def _section_param_mine(self) -> str:
        params = self._params
        interesting = params.interesting
        lines = [f"## Hidden Parameter Discovery ({len(interesting)} interesting / {params.endpoints_probed} endpoints probed)", ""]
        lines += ["| Endpoint | Method | Param | Evidence |", "|---|---|---|---|"]
        for pf in interesting[:20]:
            ep = pf.endpoint.split("?")[0]
            lines.append(f"| `{ep}` | `{pf.method}` | `{pf.param_name}` | {pf.evidence} |")
        lines.append("")
        if len(interesting) > 20:
            lines.append(f"*{len(interesting) - 20} more findings in report.json*")
        return "\n".join(lines)

    def _section_active_scan(self) -> str:
        scan = self._active_scan
        lines = [
            f"## Active Scan Results ({len(scan.confirmed)} confirmed / {len(scan.actionable)} actionable)",
            ""
        ]
        by_type: dict[str, list] = {}
        for f in scan.findings:
            by_type.setdefault(f.attack_type, []).append(f)

        for attack_type, findings in sorted(by_type.items()):
            confirmed = [f for f in findings if f.verdict == "confirmed"]
            lines.append(f"### {attack_type.replace('_', ' ').title()} ({len(confirmed)}/{len(findings)} confirmed)")
            lines.append("")
            for f in sorted(findings, key=lambda x: x.confidence, reverse=True):
                icon = "✓" if f.verdict == "confirmed" else "△"
                oob = " [OOB]" if f.oob_hit else ""
                timing = f" (delay: {f.timing_delta:.1f}s)" if f.timing_delta > 0 else ""
                lines.append(f"**{icon}** `{f.endpoint}` — param: `{f.param}`{oob}{timing}")
                lines.append(f"> {f.evidence}")
                if f.response_snippet:
                    snip = f.response_snippet[:100].replace("\n", " ")
                    lines.append(f"> `{snip}`")
                lines.append("")
        return "\n".join(lines)

    def _section_challenges(self) -> str:
        c = self._challenges
        lines = [
            f"## Ground-Truth Bugs (via {c.target_app} scoreboard)",
            "",
            f"**Newly triggered: {c.newly_triggered}** "
            f"(pre-scan solved: {c.pre_solved}, post-scan solved: {c.post_solved})",
            "",
            "These are bugs the target app *itself* confirmed we triggered. ",
            "Use this as ground truth for hxxpsin coverage.",
            "",
            "| Difficulty | Name | Category |",
            "|---|---|---|",
        ]
        for ch in c.triggered:
            lines.append(f"| {ch.difficulty} | {ch.name} | {ch.category} |")
        lines.append("")
        for ch in c.triggered:
            if ch.description:
                lines.append(f"**{ch.name}** — {ch.description[:300]}")
                lines.append("")
        return "\n".join(lines)

    def _section_auth_bypass(self) -> str:
        a = self._auth_bypass
        lines = [f"## Auth Bypass — SQLi ({len(a.confirmed)} confirmed / {a.endpoints_tested} login endpoints)", ""]
        if a.confirmed:
            lines.append("**CRITICAL:** the following payloads logged in without valid credentials.")
            lines.append("")
        for f in a.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            lines.append(f"**{icon}** `{f.method} {f.endpoint}` — field: `{f.field}` — payload: `{f.payload}`")
            lines.append(f"> {f.evidence}")
            if f.response_snippet:
                snip = f.response_snippet[:200].replace("\n", " ")
                lines.append(f"> `{snip}`")
            lines.append("")
        return "\n".join(lines)

    def _section_files(self) -> str:
        f = self._files
        by_ext = f.by_extension()
        ext_summary = ", ".join(f"{e or 'no-ext'}:{n}" for e, n in
                                sorted(by_ext.items(), key=lambda kv: -kv[1]))
        lines = [
            f"## Files Downloaded ({len(f.grabbed)} files, "
            f"{f.total_bytes // 1024} KB) — saved to `{f.out_dir}/`",
            "",
            f"**By extension:** {ext_summary or '(none)'}",
            "",
            "These are binary / non-renderable URLs the crawler captured. "
            "Inspect them offline for: leaked credentials, EXIF metadata, "
            "embedded JS in SVGs, archive contents (`unzip -l`), .bak/.sql "
            "dumps with prod data, KeePass databases, source maps revealing "
            "internal paths.",
            "",
            "| Extension | URL | Bytes | SHA-256 |",
            "|---|---|---|---|",
        ]
        # Show top 50 by size descending so the most interesting (largest)
        # surface first
        sorted_files = sorted(f.grabbed, key=lambda g: -g.bytes)[:50]
        for g in sorted_files:
            url_short = g.url if len(g.url) <= 80 else g.url[:60] + "…" + g.url[-15:]
            lines.append(f"| `{g.extension}` | `{url_short}` | {g.bytes:,} | `sha256:{g.sha256[:16]}…` |")
        if len(f.grabbed) > 50:
            lines.append("")
            lines.append(f"_... {len(f.grabbed) - 50} more files in `file_grabber.json`._")
        return "\n".join(lines)

    def _section_access_replay(self) -> str:
        a = self._access_replay
        lines = [
            f"## Access Bypass Replay ({len(a.unlocked)} unlocked / "
            f"{a.forbidden_urls_seen} forbidden URLs / "
            f"{a.bypass_tokens_tried} bypass tokens) — "
            f"{a.total_bytes_recovered // 1024} KB recovered",
            "",
            "These URLs returned **401/403 during the crawl** but became "
            "readable when re-fetched with auth bypasses discovered later "
            "(forged JWTs, harvested SQLi tokens, victim accounts). "
            "Saved bodies are in the `access_bypass/` directory next to this "
            "report — inspect for leaked admin data, hidden user lists, "
            "internal config, etc.",
            "",
            "| Original | New | Bypass | URL | Bytes | Saved as |",
            "|---|---|---|---|---|---|",
        ]
        for u in sorted(a.unlocked, key=lambda x: -x.bytes_recovered)[:50]:
            url_short = u.url if len(u.url) <= 70 else u.url[:50] + "…" + u.url[-15:]
            saved = Path(u.body_path).name if u.body_path else "(not saved)"
            lines.append(
                f"| {u.original_status} | {u.new_status} | "
                f"`{u.bypass_source}:{u.bypass_label}` | "
                f"`{url_short}` | {u.bytes_recovered:,} | `{saved}` |"
            )
        if len(a.unlocked) > 50:
            lines.append("")
            lines.append(f"_... {len(a.unlocked) - 50} more unlocked URLs in `access_replay.json`._")
        if a.bypass_tokens:
            lines.append("")
            lines.append("**Bypass tokens tried:**")
            for t in a.bypass_tokens:
                hdr_keys = ", ".join(t.to_dict()["header_keys"]) or "(none)"
                lines.append(f"- `{t.source}:{t.label}` — headers: `{hdr_keys}` — {t.evidence}")
        if a.notes:
            lines.append("")
            lines.append("**Notes:**")
            for n in a.notes[:8]:
                lines.append(f"- {n}")
        lines.append("")
        return "\n".join(lines)

    def _section_dom_xss(self) -> str:
        d = self._dom_xss
        lines = [
            f"## DOM XSS (browser-verified) "
            f"({len(d.confirmed)} confirmed / {len(d.likely)} likely / "
            f"{d.candidates_probed}/{d.candidates_total} candidates probed)",
            "",
        ]
        if d.confirmed:
            lines.append(
                "**CRITICAL:** the following client-side DOM sinks fired our "
                "canary payload when fed via the matched URL source. JS execution "
                "proven in a real browser."
            )
            lines.append("")
        for f in d.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            lines.append(f"**{icon}** `{f.source}` → `{f.sink}`  (conf={f.confidence:.2f}, signal={f.signal})")
            lines.append(f"> Probe URL: `{f.probe_url}`")
            lines.append(f"> {f.evidence}")
            if f.source_file:
                lines.append(f"> Source bundle: `{f.source_file}`")
            lines.append("")
        if d.notes:
            lines.append("**Notes:**")
            for n in d.notes[:8]:
                lines.append(f"- {n}")
            lines.append("")
        return "\n".join(lines)

    def _section_idor(self) -> str:
        i = self._idor
        lines = [
            f"## Cross-Account IDOR / BOLA "
            f"({len(i.confirmed)} confirmed / {len(i.likely)} likely / "
            f"{i.endpoints_tested} tested)",
            "",
        ]
        if i.confirmed:
            lines.append(
                "**CRITICAL:** the following endpoints returned account A's "
                "data when fetched as account B (or vice versa). This is a "
                "broken-object-level-authorization (BOLA) bug — OWASP API #1."
            )
            lines.append("")
        for f in i.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            lines.append(f"**{icon}** `{f.method} {f.url}`  ({f.test_kind}, conf={f.confidence:.2f})")
            lines.append(f"> {f.evidence}")
            if f.response_a:
                lines.append(f"> A: `{f.response_a[:160].replace(chr(10), ' ')}`")
            if f.response_b:
                lines.append(f"> B: `{f.response_b[:160].replace(chr(10), ' ')}`")
            lines.append("")
        if i.notes:
            lines.append("**Notes:**")
            for n in i.notes:
                lines.append(f"- {n}")
            lines.append("")
        return "\n".join(lines)

    def _section_auto_auth(self) -> str:
        a = self._auto_auth
        lines = ["## Auto-Authentication", ""]
        lines.append(f"**Credentials provisioned:** `{a.credentials.username}` / `{a.credentials.email}`")
        lines.append("")
        if a.register_succeeded:
            lines.append(f"- ✓ **Register:** `POST {a.register_url}` ({a.register_shape}) → {a.register_status}")
        else:
            lines.append("- ✗ Register: failed (no working endpoint)")
        if a.login_succeeded:
            kind = "JWT token" if a.token else f"{len(a.cookies)} session cookie(s) ({', '.join(a.cookies)})"
            lines.append(f"- ✓ **Login:** `POST {a.login_url}` ({a.login_shape}) → {a.login_status} — got {kind}")
        else:
            lines.append("- ✗ Login: failed")
        lines.append("")
        lines.append("**Notes:**")
        for n in a.notes:
            lines.append(f"- {n}")
        lines.append("")
        return "\n".join(lines)

    def _section_redirect(self) -> str:
        r = self._redirect
        lines = [f"## Open Redirect ({len(r.confirmed)} confirmed / {r.endpoints_tested} tested)", ""]
        for f in r.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            lines.append(f"**{icon}** `{f.url}` — param: `{f.param}`")
            lines.append(f"> {f.evidence}")
            if f.redirect_target:
                lines.append(f"> Target: `{f.redirect_target}`")
            lines.append("")
        return "\n".join(lines)

    def _section_crlf(self) -> str:
        r = self._crlf
        lines = [f"## CRLF Injection ({len(r.confirmed)} confirmed / {r.urls_tested} tested)", ""]
        for f in r.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            lines.append(f"**{icon}** `{f.url}`")
            lines.append(f"> {f.evidence}")
            if f.injected_header:
                lines.append(f"> Injected: `{f.injected_header}`")
            lines.append("")
        return "\n".join(lines)

    def _section_auto_fuzz(self) -> str:
        r = self._auto_fuzz
        n = len(r.findings)
        lines = [
            f"## Auto-Fuzz Anomalies ({n} / {r.requests_sent} requests across {r.endpoints_fuzzed} endpoints)", "",
            "> Anomalies detected by status-code delta, response-length delta (>30%),",
            "> error keywords, or payload reflection. Not all are exploitable —",
            "> review payload and response to confirm.", "",
        ]
        # Group by URL to keep the table compact
        by_url: dict[str, list] = {}
        for f in r.findings:
            by_url.setdefault(f.url, []).append(f)
        for url, hits in list(by_url.items())[:15]:
            lines.append(f"**`{hits[0].method} {url}`**")
            for h in hits[:5]:
                lines.append(f"- `{h.position}` → `{h.payload[:40]}` — {h.anomaly}")
            if len(hits) > 5:
                lines.append(f"- … {len(hits) - 5} more")
            lines.append("")
        return "\n".join(lines)

    def _section_ct_probe(self) -> str:
        r = self._ct_probe
        n = len(r.findings)
        lines = [
            f"## Content-Type Confusion ({n} confirmed / {r.endpoints_tested} tested)", "",
            "> These endpoints process the request body regardless of Content-Type.",
            "> An attacker can submit the same payload via a plain HTML form (`text/plain`",
            "> or `application/x-www-form-urlencoded`) — no CORS preflight is triggered,",
            "> bypassing CORS-as-CSRF-protection entirely.", "",
        ]
        for f in r.findings:
            sev = f.severity.upper()
            lines.append(f"**[{sev}]** `{f.method} {f.url}`")
            lines.append(f"> Original: `{f.original_ct}` → confused: `{f.confused_ct}`")
            lines.append(f"> {f.evidence}")
            lines.append("")
        return "\n".join(lines)

    def _section_ws_probe(self) -> str:
        r = self._ws_probe
        n = len(r.confirmed)
        lines = [f"## WebSocket Security ({n} finding{'s' if n != 1 else ''} / {len(r.urls_tested)} URL{'s' if len(r.urls_tested) != 1 else ''} tested)", ""]
        sev_order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(r.confirmed, key=lambda x: sev_order.get(x.get("severity", "low"), 2)):
            sev = f.get("severity", "?").upper()
            cat = f.get("category", "unknown")
            url = f.get("url", "")
            lines.append(f"**[{sev}]** `{cat}` — `{url}`")
            lines.append(f"> {f.get('evidence', '')}")
            impact = f.get("impact", "")
            if impact:
                lines.append(f"> **Impact:** {impact}")
            cwe = f.get("cwe", "")
            if cwe:
                lines.append(f"> {cwe}")
            lines.append("")
        return "\n".join(lines)

    def _section_nosql(self) -> str:
        r = self._nosql
        lines = [f"## NoSQL Injection ({len(r.confirmed)} confirmed / {r.endpoints_tested} tested)", ""]
        for f in r.findings:
            icon = "✓" if f.verdict == "confirmed" else "△"
            timing = f" (delay: {f.timing_delta:.1f}s)" if f.timing_delta > 0 else ""
            lines.append(f"**{icon}** `{f.url}` — param: `{f.param}` [{f.attack_type}]{timing}")
            lines.append(f"> {f.evidence}")
            if f.response_snippet:
                snip = f.response_snippet[:120].replace("\n", " ")
                lines.append(f"> `{snip}`")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from collector import Collector, CapturedRequest, CapturedWebSocket
    from classifier import classify
    from stackprint import StackProfile

    col = Collector("http://localhost:8080")
    col.add_request(CapturedRequest("PATCH", "http://localhost:8080/api/users/99",
        {"authorization": "Bearer eyJx"}, '{"role":"admin","is_admin":true}', "xhr"))
    col.add_request(CapturedRequest("GET", "http://localhost:8080/api/invoices/1042",
        {}, None, "xhr"))
    col.add_request(CapturedRequest("POST", "http://localhost:8080/api/fetch",
        {}, '{"url":"http://127.0.0.1/"}', "xhr"))
    col.add_request(CapturedRequest("POST", "http://localhost:8080/graphql",
        {"content-type": "application/json"}, '{"query":"{ __schema { } }"}', "xhr"))

    ws = CapturedWebSocket(url="wss://localhost:8080/cable")
    ws.messages_sent.append({"raw": '{"action":"subscribe","room_id":42,"user_id":7}'})
    col.add_websocket(ws)
    col.add_js_discovered_route("/api/v2/admin/users")
    col.add_js_discovered_route("/graphql")

    result = classify(col)
    reporter = Reporter(result, target="http://localhost:8080")
    print(reporter.to_markdown())
