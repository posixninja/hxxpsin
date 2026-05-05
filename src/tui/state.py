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
    requests: list[dict] = field(default_factory=list)       # collector.json entries
    findings: list[dict] = field(default_factory=list)       # all findings (any probe)
    probe_results: dict[str, list[dict]] = field(default_factory=dict)
    probe_status: dict[str, str] = field(default_factory=dict)  # probe → idle/running/done

    # Enrichment
    enrichment_dir: str | None = None   # output/enrichment/ — read lazily

    # Stackprint
    stackprint: dict = field(default_factory=dict)

    # Repeater / Intruder
    repeater_sessions: list[RepeaterSession] = field(default_factory=list)
    intruder_results: list[dict] = field(default_factory=list)

    # Canary / challenge — feed bottom alerts bar
    canary_hits: list[dict] = field(default_factory=list)
    canary_tag_map: dict[str, str] = field(default_factory=dict)  # tag → probe name
    challenge_triggers: list[dict] = field(default_factory=list)

    # Saved target list (persists across modal opens within the session)
    targets: list[dict] = field(default_factory=list)  # list of config dicts from NewTargetModal

    # Scope for the active target
    allowed_hosts: list[str] = field(default_factory=list)      # extra netlocs crawler may follow
    excluded_patterns: list[str] = field(default_factory=list)  # regex — URLs to never crawl

    # Current request-tab selection (indices into self.requests)
    selected_requests: list[int] = field(default_factory=list)

    # Step log lines (for dashboard + step runner)
    step_log: list[str] = field(default_factory=list)

    # Listeners — TUI widgets register here for live updates
    _listeners: list[Callable[[str, Any], None]] = field(default_factory=list, repr=False)

    def add_listener(self, cb: Callable[[str, Any], None]) -> None:
        self._listeners.append(cb)

    def remove_listener(self, cb: Callable[[str, Any], None]) -> None:
        self._listeners.discard(cb) if hasattr(self._listeners, "discard") else None
        if cb in self._listeners:
            self._listeners.remove(cb)

    def emit(self, event: str, data: Any = None) -> None:
        for cb in list(self._listeners):
            try:
                cb(event, data)
            except Exception:
                pass

    def on_pipeline_event(self, event: str, *args) -> None:
        """Callback registered with main.set_progress_cb() — called from worker thread."""
        if event == "step":
            n, total, label = args
            msg = f"[{n}/{total}] {label}"
            self.step_log.append(msg)
            self.emit("step", {"n": n, "total": total, "label": label})
        elif event == "err":
            msg = args[0]
            self.step_log.append(f"  {msg}")
            self.emit("err", msg)
        elif event == "canary":
            hit = args[0]
            self.canary_hits.append(hit)
            self.emit("canary", hit)
        elif event == "challenge":
            trigger = args[0]
            self.challenge_triggers.append(trigger)
            self.emit("challenge", trigger)

    def load_output_dir(self, path: str) -> None:
        """Load all JSON artifacts from a completed scan directory."""
        p = Path(path)
        self.out_dir = str(p)

        collector_path = p / "collector.json"
        if collector_path.exists():
            try:
                data = json.loads(collector_path.read_text())
                self.requests = data.get("requests", [])
                if self.requests and not self.target:
                    self.target = data.get("origin", "")
            except Exception:
                pass

        stackprint_path = p / "stackprint.json"
        if stackprint_path.exists():
            try:
                self.stackprint = json.loads(stackprint_path.read_text())
                if not self.target:
                    self.target = self.stackprint.get("origin", "")
            except Exception:
                pass

        enrichment_p = p / "enrichment"
        if enrichment_p.is_dir():
            self.enrichment_dir = str(enrichment_p)

        # Load probe result files
        probe_files = {
            "jwt": "jwt_attack.json",
            "idor": "idor_probe.json",
            "desync": "desync_probe.json",
            "nosql": "nosql_probe.json",
            "crlf": "crlf_probe.json",
            "upload": "upload_probe.json",
            "dom_xss": "dom_xss_probe.json",
            "active": "verify.json",
            "access_replay": "access_replay.json",
            "auto_fuzz": "auto_fuzz.json",
            "ws": "ws_probe.json",
            "ct": "ct_probe.json",
        }
        for probe, filename in probe_files.items():
            fp = p / filename
            if fp.exists():
                try:
                    raw = json.loads(fp.read_text())
                    # Normalize to list of findings
                    if isinstance(raw, dict):
                        findings = (
                            raw.get("findings", [])
                            or raw.get("confirmed", [])
                            or raw.get("results", [])
                            or []
                        )
                    elif isinstance(raw, list):
                        findings = raw
                    else:
                        findings = []
                    self.probe_results[probe] = findings
                    self.probe_status[probe] = "done"
                    # Merge into global findings list with source tag
                    for f in findings:
                        if isinstance(f, dict):
                            f.setdefault("_probe", probe)
                            self.findings.append(f)
                except Exception:
                    pass

        # Load report findings
        report_path = p / "report.json"
        if report_path.exists():
            try:
                rdata = json.loads(report_path.read_text())
                top = rdata.get("top_findings", [])
                for f in top:
                    if isinstance(f, dict):
                        f.setdefault("_probe", "report")
                        if f not in self.findings:
                            self.findings.append(f)
            except Exception:
                pass

        self.scan_status = "done"
        self.emit("loaded", path)
