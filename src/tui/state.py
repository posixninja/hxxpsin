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
        }
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
            except Exception as e:
                self.step_log.append(f"[load error] report.json: {e}")

        self.scan_status = "done"
        # Single event — app listens and refreshes all screens
        self.emit("loaded", str(p))
