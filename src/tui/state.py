"""Shared application state for the hxxpsin TUI."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal


@dataclass
class RepeaterSession:
    label: str
    raw_request: str
    last_response: str = ""
    last_status: int = 0


@dataclass
class AppState:
    out_dir: str | None = None
    target: str = ""
    scan_status: Literal["idle", "running", "done"] = "idle"

    # Core entity lists
    requests: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    probe_results: dict[str, list[dict]] = field(default_factory=dict)
    probe_status: dict[str, str] = field(default_factory=dict)

    # Enrichment
    enrichment_dir: str | None = None

    # Stackprint
    stackprint: dict = field(default_factory=dict)

    # JS analysis — routes found by static JS bundle analysis (not necessarily crawled)
    js_discovered_routes: list[str] = field(default_factory=list)
    js_bundle_urls: list[str] = field(default_factory=list)

    # Repeater / Intruder
    repeater_sessions: list[RepeaterSession] = field(default_factory=list)
    intruder_results: list[dict] = field(default_factory=list)

    # Canary / challenge
    canary_hits: list[dict] = field(default_factory=list)
    canary_tag_map: dict[str, str] = field(default_factory=dict)
    challenge_triggers: list[dict] = field(default_factory=list)

    # Surface mapper / DNS recon (scope.json carries both)
    scope: dict = field(default_factory=dict)

    # OOB infrastructure
    tunnel_hits: list[dict] = field(default_factory=list)
    tunnel_context: dict = field(default_factory=dict)
    tunnel_backend: str = ""
    tunnel_public_url: str = ""

    # Metasploit Framework workspace
    msf_backend: str = ""          # "rpc" | "db" | ""
    msf_workspace: str = ""
    msf_result: dict = field(default_factory=dict)   # MSFIngestResult.to_dict()
    msf_step_log: list[str] = field(default_factory=list)
    msf_sessions_on_target: list[dict] = field(default_factory=list)
    msf_suggested_modules: dict = field(default_factory=dict)

    # LDAP / AD dump
    ldap_dump: dict = field(default_factory=dict)
    ldap_accounts: list[dict] = field(default_factory=list)

    # SQL dump (from sql_dump.py — post-step after confirmed SQLi)
    sql_dump: dict = field(default_factory=dict)
    sql_dump_rows: dict[str, list] = field(default_factory=dict)  # table → rows

    # AI briefings keyed by finding index (from solver.json findings[].briefing)
    briefings: dict[int, dict] = field(default_factory=dict)

    # LLM agentic decisions (challenge solver + briefing generator)
    llm_decisions: list[dict] = field(default_factory=list)
    stage_status: dict[str, dict] = field(default_factory=dict)

    # Saved targets
    targets: list[dict] = field(default_factory=list)

    # Scope
    allowed_hosts: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)

    # Wizard config persisted from the last "New Session" so manual-mode
    # actions (Spider crawl, probe runs) can pick up the auth / scope without
    # re-prompting the user.
    session_config: dict = field(default_factory=dict)

    # Current request-tab selection (list of request dicts)
    selected_requests: list = field(default_factory=list)

    # Step log (mixed step + err lines, for tail display)
    step_log: list[str] = field(default_factory=list)
    # Last scan-step progress (set only on "step" events; never overwritten by "err")
    scan_step_n: int = 0
    scan_step_total: int = 0
    scan_step_label: str = ""

    # Listeners — registered by the app; called on the main thread via call_from_thread
    _listeners: list[Callable[[str, Any], None]] = field(default_factory=list, repr=False)

    def add_listener(self, cb: Callable[[str, Any], None]) -> None:
        self._listeners.append(cb)

    def remove_listener(self, cb: Callable[[str, Any], None]) -> None:
        if cb in self._listeners:
            self._listeners.remove(cb)

    def emit(self, event: str, data: Any = None) -> None:
        for cb in list(self._listeners):
            try:
                cb(event, data)
            except Exception:
                pass

    def on_pipeline_event(self, event: str, *args) -> None:
        """Called from the scan worker thread via set_progress_cb()."""
        if event == "step":
            n, total, label = args
            self.scan_step_n = n
            self.scan_step_total = total
            self.scan_step_label = label
            self.step_log.append(f"[{n}/{total}] {label}")
            self.emit("step", {"n": n, "total": total, "label": label})
        elif event == "err":
            msg = args[0]
            self.step_log.append(f"  {msg}")
            self.emit("err", msg)
        elif event == "collector":
            # Crawl phase complete — load requests immediately so site map populates
            out_path = args[0]
            self._load_collector(Path(out_path))
            self.emit("requests_updated", None)
        elif event == "request_added":
            # Live request streamed from the running crawler/collector.
            # Append (deduping by url+method) and emit for live UI updates.
            req = args[0]
            if isinstance(req, dict):
                key = (req.get("method", ""), req.get("url", ""))
                if not any(
                    (r.get("method", ""), r.get("url", "")) == key
                    for r in self.requests
                ):
                    self.requests.append(req)
                    self.emit("request_added", req)
        elif event == "canary":
            self.canary_hits.append(args[0])
            self.emit("canary", args[0])
        elif event == "challenge":
            self.challenge_triggers.append(args[0])
            self.emit("challenge", args[0])
        elif event == "tunnel_up":
            backend, public_url = args[0], args[1]
            self.tunnel_backend = backend or ""
            self.tunnel_public_url = public_url or ""
            self.emit("tunnel_up", {"backend": backend, "public_url": public_url})
        elif event == "tunnel_hit":
            hit = args[0]
            if isinstance(hit, dict):
                self.tunnel_hits.append(hit)
                self.emit("tunnel_hit", hit)
        elif event == "surface_step":
            phase, count = args[0], args[1]
            self.emit("surface_step", {"phase": phase, "count": count})
        elif event == "msf_ingest_step":
            phase, count = args[0], args[1] if len(args) > 1 else 0
            self.msf_step_log.append(f"{phase}: {count}")
            self.emit("msf_ingest_step", {"phase": phase, "count": count})
        elif event == "llm_decision":
            decision = args[0]
            if isinstance(decision, dict):
                self.llm_decisions.append(decision)
                self.emit("llm_decision", decision)
        elif event in ("stage_start", "stage_done", "stage_error"):
            payload = args[0] if args and isinstance(args[0], dict) else {}
            name = payload.get("name", "?")
            if name:
                self.stage_status[name] = payload
            self.step_log.append(
                f"  stage {name}: {payload.get('status', 'running')}"
            )
            self.emit(event, payload)

    def _load_collector(self, p: Path) -> None:
        collector_path = p / "collector.json"
        if not collector_path.exists():
            return
        try:
            data = json.loads(collector_path.read_text())
            self.requests = data.get("requests", [])
            self.js_discovered_routes = data.get("js_discovered_routes", [])
            self.js_bundle_urls = data.get("js_bundle_urls", [])
            self.out_dir = str(p)
            if not self.target:
                self.target = data.get("origin", "")
        except Exception as e:
            self.step_log.append(f"[load error] collector.json: {e}")

    def load_output_dir(self, path: str) -> None:
        """Load all artifacts from a completed scan directory and notify listeners."""
        p = Path(path)
        self.out_dir = str(p)

        self._load_collector(p)

        sp = p / "stackprint.json"
        if sp.exists():
            try:
                self.stackprint = json.loads(sp.read_text())
                if not self.target:
                    self.target = self.stackprint.get("origin", "")
            except Exception as e:
                self.step_log.append(f"[load error] stackprint.json: {e}")

        enrich = p / "enrichment"
        if enrich.is_dir():
            self.enrichment_dir = str(enrich)

        probe_files = {
            "jwt":          "jwt_attack.json",
            "idor":         "idor_probe.json",
            "desync":       "desync_probe.json",
            "nosql":        "nosql_probe.json",
            "crlf":         "crlf_probe.json",
            "upload":       "upload_probe.json",
            "dom_xss":      "dom_xss_probe.json",
            "active":       "verify.json",
            "access_replay":"access_replay.json",
            "auto_fuzz":    "auto_fuzz.json",
            "ws":           "ws_probe.json",
            "ct":           "ct_probe.json",
            "graphql":      "graphql_probe.json",
            "oauth":        "oauth_probe.json",
            "race":         "race_probe.json",
        }
        sched_path = p / "stages" / "_scheduler.json"
        if sched_path.exists():
            try:
                sched = json.loads(sched_path.read_text())
                for name, rec in (sched.get("records") or {}).items():
                    self.stage_status[name] = rec
                    st = rec.get("status", "")
                    if st == "done":
                        self.probe_status[name] = "done"
                    elif st == "error":
                        self.probe_status[name] = "failed"
                    elif st == "running":
                        self.probe_status[name] = "running"
            except Exception as e:
                self.step_log.append(f"[load error] stages/_scheduler.json: {e}")
        self.findings = []
        for probe, filename in probe_files.items():
            fp = p / filename
            if not fp.exists():
                continue
            try:
                raw = json.loads(fp.read_text())
                findings = (
                    raw if isinstance(raw, list)
                    else raw.get("findings") or raw.get("confirmed") or raw.get("results") or []
                )
                self.probe_results[probe] = findings
                self.probe_status[probe] = "done"
                for f in findings:
                    if isinstance(f, dict):
                        f.setdefault("_probe", probe)
                        self.findings.append(f)
            except Exception as e:
                self.step_log.append(f"[load error] {filename}: {e}")

        report = p / "report.json"
        if report.exists():
            try:
                rdata = json.loads(report.read_text())
                for f in rdata.get("top_findings", []):
                    if isinstance(f, dict) and f not in self.findings:
                        f.setdefault("_probe", "report")
                        self.findings.append(f)
                sql = rdata.get("sql_dump")
                if isinstance(sql, dict) and not self.sql_dump:
                    self.sql_dump = sql
                msf = rdata.get("msf_ingest")
                if isinstance(msf, dict):
                    self.msf_result = msf
                    self.msf_backend = msf.get("backend", "") or ""
                    self.msf_workspace = msf.get("workspace", "") or ""
                    sot = msf.get("sessions_on_target") or []
                    self.msf_sessions_on_target = [s for s in sot if isinstance(s, dict)]
                    sug = msf.get("suggested_modules") or {}
                    self.msf_suggested_modules = sug if isinstance(sug, dict) else {}
            except Exception as e:
                self.step_log.append(f"[load error] report.json: {e}")

        scope_fp = p / "recon" / "scope.json"
        if scope_fp.exists():
            try:
                self.scope = json.loads(scope_fp.read_text())
            except Exception as e:
                self.step_log.append(f"[load error] recon/scope.json: {e}")

        tunnel_fp = p / "tunnel_hits.json"
        if tunnel_fp.exists():
            try:
                tdata = json.loads(tunnel_fp.read_text())
                self.tunnel_hits = list(tdata.get("hits", []))
                self.tunnel_context = tdata.get("context", {}) or {}
                self.tunnel_backend = self.tunnel_context.get("tunnel_backend", "") or ""
                self.tunnel_public_url = self.tunnel_context.get("public_url", "") or ""
            except Exception as e:
                self.step_log.append(f"[load error] tunnel_hits.json: {e}")

        ldap_fp = p / "ldap_dump.json"
        if ldap_fp.exists():
            try:
                self.ldap_dump = json.loads(ldap_fp.read_text())
                self.ldap_accounts = list(self.ldap_dump.get("accounts", []))
            except Exception as e:
                self.step_log.append(f"[load error] ldap_dump.json: {e}")
        accounts_dir = p / "ldap_dump" / "accounts"
        if accounts_dir.is_dir() and not self.ldap_accounts:
            for af in accounts_dir.glob("*.json"):
                try:
                    self.ldap_accounts.append(json.loads(af.read_text()))
                except Exception as e:
                    self.step_log.append(f"[load error] {af.name}: {e}")

        # SQL dump — summary lives inside report.json["sql_dump"]; per-table
        # row payloads live as <out>/sql_dump/data/<table>.json
        sql_fp_summary = p / "sql_dump.json"
        if sql_fp_summary.exists():
            try:
                self.sql_dump = json.loads(sql_fp_summary.read_text())
            except Exception as e:
                self.step_log.append(f"[load error] sql_dump.json: {e}")
        sql_data_dir = p / "sql_dump" / "data"
        if sql_data_dir.is_dir():
            for tf in sql_data_dir.glob("*.json"):
                try:
                    self.sql_dump_rows[tf.stem] = json.loads(tf.read_text())
                except Exception as e:
                    self.step_log.append(f"[load error] {tf.name}: {e}")
        sql_fp_text = p / "sql_dump" / "fingerprint.json"
        if not self.sql_dump and sql_fp_text.exists():
            try:
                self.sql_dump = {
                    "fingerprints": json.loads(sql_fp_text.read_text()),
                    "out_dir": str(p / "sql_dump"),
                }
            except Exception as e:
                self.step_log.append(f"[load error] sql_dump/fingerprint.json: {e}")

        solver_fp = p / "solver.json"
        url_briefings: dict[tuple[str, str], dict] = {}
        if solver_fp.exists():
            try:
                sdata = json.loads(solver_fp.read_text())
                for sf in sdata.get("findings", []):
                    if not isinstance(sf, dict):
                        continue
                    br = sf.get("briefing")
                    if not isinstance(br, dict):
                        continue
                    idx = int(sf.get("finding_index", -1))
                    if idx >= 0:
                        self.briefings[idx] = br
                    key = (
                        str(sf.get("url", "")),
                        str(sf.get("method", "")).upper(),
                    )
                    if key[0]:
                        url_briefings[key] = br
            except Exception as e:
                self.step_log.append(f"[load error] solver.json: {e}")
        if url_briefings:
            for f in self.findings:
                if not isinstance(f, dict) or f.get("_briefing"):
                    continue
                key = (
                    str(f.get("url", f.get("endpoint", ""))),
                    str(f.get("method", "GET")).upper(),
                )
                br = url_briefings.get(key)
                if br is not None:
                    f["_briefing"] = br

        self.scan_status = "done"
        # Single event — app listens and refreshes all screens
        self.emit("loaded", str(p))
