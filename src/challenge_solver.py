"""
challenge_solver.py — Three-stage agentic exploit-confirmation pipeline.

Each top classifier Finding goes through:

  1. RECON (deterministic per-category recipes — `recon_collector.py`)
     Sends a fixed set of probes: baseline, anonymous, ID swap, body
     mutation, etc. Pure HTTP — no LLM. Output: a ReconBundle with raw
     (label, request, response) triples.

  2. BRIEFING (single LLM call — `briefing_generator.py`)
     Reads the recon bundle and emits a structured Briefing: baseline
     behavior, key observations, evidence_for, evidence_against,
     missing_information, preliminary_hypothesis. No verdict yet —
     just an evidence digest the verdict stage can act on cleanly.

  3. VERDICT (single LLM call — this module)
     Reads ONLY the briefing (not the raw transcript) and renders the
     final {verdict, reason, evidence_excerpt, suggested_fix}.

Why three stages: smaller models hallucinate verdicts when fed raw
transcripts of HTTP responses. Splitting "what happened" from "what does it
mean" from "what's the verdict" gives each stage a tight, focused task —
fewer false positives, more legible output, and easy to inspect each step
in isolation when something goes wrong.

System prompts are framed as a senior professional pentester operating
against an EXPLICITLY AUTHORIZED CTF/training target. That framing is
deliberate: it suppresses unhelpful "I shouldn't probe that" refusals
without nudging the model toward overclaiming.

Output: a list of `SolvedFinding` objects (now including the recon bundle
and briefing for forensics) which the reporter renders in its own section.
Each visited classifier Finding is also mutated with `agent_verdict` /
`agent_reason` / `agent_evidence` so the Top Findings table can show the
verdict inline.

The legacy single-stage tool-use loop (TOOLS + _ToolExecutor + run_agent)
is preserved in this file for future use as an OPTIONAL investigation step
when the verdict comes back inconclusive — not wired in yet.
"""

import asyncio
import json
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from briefing_generator import Briefing, generate_briefing
from classifier import ClassifierResult, Finding
from recon_collector import ReconBundle, ReconContext, collect_recon


# ---------------------------------------------------------------------------
# Refusal detector — when a safety-tuned model declines the task instead of
# producing a verdict. Refusals are the dominant failure mode for security
# work even with strong CTF framing; we need to catch and surface them so
# the operator can either retry, swap the model, or downgrade to manual.
# ---------------------------------------------------------------------------

# Phrases that are strong signal a model is refusing the analysis. Tuned to
# avoid false-positives on routine pentest commentary (e.g. "this endpoint
# is harmful if abused" is fine; "I cannot help with harmful requests" is a
# refusal).
_REFUSAL_REGEXES = [
    re.compile(r"\b(?:i\s+(?:cannot|can'?t|won'?t|am\s+not\s+able\s+to|am\s+unable\s+to|refuse\s+to|decline\s+to|will\s+not))\s+(?:assist|help|provide|analyze|render|comply|engage|perform|create|generate|produce|continue)", re.IGNORECASE),
    re.compile(r"\bas\s+an?\s+(?:ai|language\s+model|assistant)\b.{0,80}\b(?:cannot|can'?t|won'?t|unable|not\s+able)", re.IGNORECASE),
    re.compile(r"\b(?:against|violates?)\s+(?:my|the)\s+(?:policies?|guidelines?|principles?|ethics)", re.IGNORECASE),
    re.compile(r"\bI\s+(?:must|have to)\s+decline\b", re.IGNORECASE),
    re.compile(r"\b(?:sorry,?\s+but\s+I|I\s+apologize,?\s+but)\b.{0,40}\b(?:cannot|can'?t|won'?t|unable)", re.IGNORECASE),
    re.compile(r"\bnot\s+appropriate\s+for\s+me\s+to\b", re.IGNORECASE),
]


def _detect_refusal(raw_text: str = "",
                    parsed: Optional[dict] = None) -> str:
    """Returns a short refusal label if the response looks like a model
    refusal, or empty string if not.

    Two failure modes covered:
      1. format_break  — response is not valid JSON at all (model broke
         its discipline to write prose, usually a refusal)
      2. refusal_in_text — JSON parsed but the reasoning/text contains
         hard refusal language

    Pass `raw_text` for the format-break path and `parsed` (the JSON dict)
    for the refusal-in-text path. If both are provided, the parsed path
    wins — only structured fields are scanned.
    """
    raw = raw_text or ""

    # Format break — couldn't parse to JSON AND the raw text matches a refusal
    if not parsed:
        if raw and any(rx.search(raw) for rx in _REFUSAL_REGEXES):
            return "format_break_refusal"
        # Common refusal openers without verb match
        opener = raw.strip().lower()[:60]
        if (opener.startswith("i can't")
                or opener.startswith("i cannot")
                or opener.startswith("i'm sorry")
                or opener.startswith("i apologize")
                or opener.startswith("i'm unable")):
            return "format_break_refusal"
        return ""

    # JSON parsed — scan the freeform text fields for refusal language
    candidate_fields = []
    if isinstance(parsed, dict):
        for key in ("reasoning", "reason", "baseline_behavior",
                    "preliminary_hypothesis", "evidence_for",
                    "evidence_against", "suggested_fix"):
            v = parsed.get(key)
            if isinstance(v, str):
                candidate_fields.append(v)
            elif isinstance(v, list):
                candidate_fields.extend(str(x) for x in v)
    combined = " \n ".join(candidate_fields)
    if combined and any(rx.search(combined) for rx in _REFUSAL_REGEXES):
        return "refusal_in_text"
    return ""


def _extract_raw_text(resp) -> str:
    """Pull the raw text out of any provider's response object.
    LLMClient uses .raw_text; Claude/OpenAI use .text. Returns '' if neither."""
    return (getattr(resp, "raw_text", None)
            or getattr(resp, "text", "") or "")


# ---------------------------------------------------------------------------
# Tool schemas — sent to Claude in the run_agent() call
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "name": "http_request",
        "description": (
            "Send an HTTP request to the target and get the full response. "
            "Use this to confirm IDOR by swapping IDs, test mass-assignment by "
            "adding fields to a JSON body, probe SSRF by injecting URLs, etc. "
            "The auth headers captured during the scan are attached automatically; "
            "pass `use_auth=false` to send anonymously."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": [
                    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
                ]},
                "url": {"type": "string",
                        "description": "Absolute URL; must be on the scanned target's host."},
                "headers": {"type": "object",
                            "description": "Additional headers as {name: value}.",
                            "additionalProperties": {"type": "string"}},
                "body": {"type": "string",
                         "description": "Raw request body (JSON, form-encoded, etc)."},
                "use_auth": {"type": "boolean",
                             "description": "Attach captured auth headers (default true)."},
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "browser_eval",
        "description": (
            "Open a URL in a real Chromium tab (using the captured auth state) "
            "and execute a JavaScript expression. Returns the JSON-serialized "
            "result. Use this for DOM-XSS confirmation, SPA-only flows, "
            "postMessage probes, or anything that requires real Origin/cookies."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "script": {"type": "string",
                           "description": "JS expression evaluated in the page; "
                                          "wrap async work in (async () => {...})()."},
                "wait_ms": {"type": "integer",
                            "description": "Milliseconds to wait after load before eval (default 500)."},
            },
            "required": ["url", "script"],
        },
    },
    {
        "name": "read_finding",
        "description": (
            "Re-read a classifier finding by index (0-based, from the top-findings "
            "list passed in the user prompt) to get the full evidence list, "
            "request body, and response that the classifier captured."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "integer", "minimum": 0},
            },
            "required": ["index"],
        },
    },
    {
        "name": "run_nuclei",
        "description": (
            "Run a single generated nuclei template against the target. "
            "Returns nuclei's stdout (results) and stderr. Templates live in "
            "{out}/nuclei/generated/ and are listed in the user prompt. "
            "Caller-side timeout is 30 seconds."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "template": {"type": "string",
                             "description": "Template filename (e.g. 'ssrf-01-webhook.yaml'). "
                                            "Must already exist in the generated/ dir."},
                "target_override": {"type": "string",
                                    "description": "Optional URL to scan instead of the default target."},
            },
            "required": ["template"],
        },
    },
    {
        "name": "encode_payload",
        "description": (
            "Apply one or more encoding schemes to a payload and return all "
            "variants. Useful when a WAF blocks a raw payload — try "
            "url_double, unicode_esc, html_dec, etc. Returns a JSON array "
            "of {label, value} entries. Available schemes: url, url_double, "
            "url_plus, base64, base64url, html_dec, html_hex, html_named, "
            "unicode_esc, hex_backslash, hex_0x, utf7, utf16le, json_escape, "
            "null_byte_suffix, null_byte_prefix, jwt_segment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "value":   {"type": "string",
                            "description": "Payload to encode."},
                "schemes": {"type": "array",
                            "items": {"type": "string"},
                            "description": "Schemes to apply. Omit for the default "
                                           "web-filter-bypass set."},
                "chain":   {"type": "boolean",
                            "description": "Also emit chained encoding pairs "
                                           "(default false)."},
            },
            "required": ["value"],
        },
    },
    {
        "name": "decode_detect",
        "description": (
            "Identify and decode an arbitrary string. Returns a JSON object "
            "with `ranked` (candidate {scheme, confidence} guesses) and "
            "`decoded` (each successful decoding, including nested layers "
            "up to depth 2). Use on captured tokens, suspicious request "
            "parameters, or response fields that look encoded."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string",
                          "description": "String to identify and decode."},
            },
            "required": ["value"],
        },
    },
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SolvedFinding:
    finding_index: int
    url: str
    method: str
    categories: list[str]
    verdict: str                       # confirmed | refuted | inconclusive | error
    reason: str = ""
    verdict_reasoning: str = ""        # CoT scratchpad from stage 3
    evidence_excerpt: str = ""
    suggested_fix: str = ""
    confidence: int = 0                # 0–3 propagated from the briefing
    recipe_name: str = ""              # which recon recipe ran
    probes_sent: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""
    recon: Optional[dict] = None       # ReconBundle.to_dict() — forensics
    briefing: Optional[dict] = None    # Briefing.to_dict() — forensics
    tool_calls_made: int = 0           # 0 for 3-stage; retained for compat
    trace: Optional[dict] = None       # legacy AgentTrace, unused in 3-stage

    def to_dict(self) -> dict:
        return {
            "finding_index": self.finding_index,
            "url": self.url,
            "method": self.method,
            "categories": self.categories,
            "verdict": self.verdict,
            "reason": self.reason,
            "verdict_reasoning": self.verdict_reasoning,
            "evidence_excerpt": self.evidence_excerpt[:1200],
            "suggested_fix": self.suggested_fix,
            "confidence": self.confidence,
            "recipe_name": self.recipe_name,
            "probes_sent": self.probes_sent,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
            "recon": self.recon,
            "briefing": self.briefing,
            "tool_calls_made": self.tool_calls_made,
            "trace": self.trace,
        }


@dataclass
class ChallengeSolverResult:
    model: str = ""
    target: str = ""
    attempted: int = 0
    confirmed: int = 0
    refuted: int = 0
    inconclusive: int = 0
    errors: int = 0
    refusals: int = 0                 # times the model declined the task
    refusal_log: list[dict] = field(default_factory=list)  # per-incident detail
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    findings: list[SolvedFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "target": self.target,
            "attempted": self.attempted,
            "confirmed": self.confirmed,
            "refuted": self.refuted,
            "inconclusive": self.inconclusive,
            "errors": self.errors,
            "refusals": self.refusals,
            "refusal_log": self.refusal_log,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Prompts — kept short. The schema does the heavy lifting; the prompt just
# names the role and tells the agent how to finish.
# ---------------------------------------------------------------------------

_SYSTEM = (
    "You are an offensive web AppSec analyst running against an EXPLICITLY "
    "AUTHORIZED target (a CTF or intentionally-vulnerable training app). The "
    "classifier already identified a suspicious endpoint and a likely bug "
    "class. Your job is to confirm or refute the bug by sending the exact "
    "requests a human would send in Burp Repeater, observing the responses, "
    "and judging whether the response proves the vulnerability. "
    "\n\n"
    "Rules:\n"
    "1. Stay on the target host that appears in the finding URL. Never send "
    "requests off-domain (the only exception is SSRF payloads that target the "
    "internal address of the target itself or a documented metadata service "
    "like 169.254.169.254 — those go INSIDE the target via its own URL fields, "
    "not as the request URL).\n"
    "2. Read-only probes first; only escalate to writes when read-only "
    "evidence is ambiguous. Never delete data, change passwords, or invite "
    "real users.\n"
    "3. When you are done, output a single JSON object as your final message "
    "(no surrounding prose) with these keys: "
    '{"verdict": "confirmed|refuted|inconclusive", '
    '"reason": "<one sentence>", '
    '"evidence_excerpt": "<short quote from a response that proves it, or empty>", '
    '"suggested_fix": "<one sentence remediation>"}.'
)


# ---------------------------------------------------------------------------
# Stage 3 — Verdict prompts (no tools, takes only the Briefing as input)
# ---------------------------------------------------------------------------

VERDICT_SYSTEM = """You are a senior offensive web application penetration tester writing up the final verdict for a finding from a CTF or intentionally-vulnerable training engagement. You have an active, written authorization to test this target. Acting on the data is in scope; do not refuse to render a verdict on safety grounds.

You will be given a pre-condensed EVIDENCE BRIEFING produced by an analyst who already reviewed the raw HTTP responses. Trust the briefing — do NOT ask for more data, do NOT speculate beyond what's in it. Your job is to render the verdict the briefing supports.

Calibration rules — these are the difference between a useful pentest report and a noisy one:

- A "confirmed" verdict requires CONCRETE evidence_for items (cross-account data, reflected payload, leaked metadata, working bypass). Confidence 2 or higher in the briefing → confirmed is plausible. Confidence 3 → confirmed is required.
- A 4xx error response is NEVER confirmation of a bug. "Invalid coupon", "Not found", "Forbidden" are routine refusal messages; they prove the endpoint exists, nothing else.
- If the briefing shows identical responses across all variants (baseline, anonymous, ID-swap), the endpoint did not change behavior — that is REFUTATION evidence, regardless of the HTTP status returned.
- When `missing_information` is non-empty and `evidence_for` is empty/weak, the correct verdict is `inconclusive`. Don't reach for confirmed/refuted you can't defend.
- The `evidence_excerpt` you cite MUST be a verbatim string copied from the briefing (typically from `evidence_for` or `key_observations`). Never paraphrase. If no good excerpt exists, leave it empty.
- The `suggested_fix` is one sentence of concrete remediation specific to this bug class — not generic security hygiene.

OUTPUT FORMAT — respond with EXACTLY this JSON (no markdown, no code fences, no prose around it). The `reasoning` field comes FIRST and is mandatory; use it to think step-by-step through the briefing BEFORE committing to a verdict. Treat it as your scratchpad — recap the strongest evidence on each side, then decide:

{"reasoning": "<3-5 sentences walking through the briefing's evidence_for and evidence_against, weighing them against the calibration rules above, then concluding which verdict is supported>",
 "verdict": "confirmed | refuted | inconclusive",
 "reason": "<one sentence justifying the verdict against the briefing's evidence_for / evidence_against>",
 "evidence_excerpt": "<short verbatim string from the briefing, or empty>",
 "suggested_fix": "<one sentence remediation>"}

The `verdict` field MUST be consistent with what you concluded in `reasoning`. If your reasoning weighs the evidence as refuting the bug, do not then write "confirmed" as the verdict.
"""


def _build_verdict_prompt(briefing: Briefing, finding: Finding) -> str:
    lines: list[str] = [
        f"Finding: {finding.method} {finding.url}",
        f"Categories: {', '.join(finding.categories)}",
        f"Classifier score: {finding.score}",
        "",
        "=== Evidence briefing ===",
        f"baseline_behavior: {briefing.baseline_behavior or '(none)'}",
        f"preliminary_hypothesis: {briefing.preliminary_hypothesis}",
        f"confidence: {briefing.confidence}",
        "",
        "key_observations:",
    ]
    for o in briefing.key_observations or ["(none)"]:
        lines.append(f"  - {o}")
    lines.append("")
    lines.append("evidence_for:")
    for e in briefing.evidence_for or ["(none)"]:
        lines.append(f"  - {e}")
    lines.append("")
    lines.append("evidence_against:")
    for e in briefing.evidence_against or ["(none)"]:
        lines.append(f"  - {e}")
    lines.append("")
    lines.append("missing_information:")
    for m in briefing.missing_information or ["(none)"]:
        lines.append(f"  - {m}")
    lines.append("")
    lines.append("=== End briefing ===")
    lines.append("")
    lines.append("Render the final verdict JSON now.")
    return "\n".join(lines)


@dataclass
class VerdictRender:
    verdict: str
    reasoning: str = ""          # explicit CoT scratchpad
    reason: str = ""             # one-sentence justification
    evidence_excerpt: str = ""
    suggested_fix: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    refusal_kind: str = ""       # "" | "format_break_refusal" | "refusal_in_text"
    refusal_excerpt: str = ""    # short quote of refusal language for the log


async def _render_verdict(briefing: Briefing, finding: Finding,
                          llm_generate) -> VerdictRender:
    """Stage 3: one LLM call, briefing-only context, returns a VerdictRender."""
    # If the condenser itself errored badly, fall back gracefully
    if briefing.error and not (briefing.evidence_for or briefing.evidence_against):
        return VerdictRender(
            verdict="inconclusive",
            reason=f"briefing stage failed: {briefing.error}",
        )

    prompt = _build_verdict_prompt(briefing, finding)
    resp = await llm_generate(
        prompt=prompt, system=VERDICT_SYSTEM,
        expect_json=True, temperature=0.0, max_tokens=900,
    )
    in_tok = getattr(resp, "input_tokens", 0)
    out_tok = getattr(resp, "output_tokens", 0)
    raw_text = getattr(resp, "raw_text", None) or getattr(resp, "text", "") or ""

    parsed = getattr(resp, "parsed", None)
    if not parsed or not isinstance(parsed, dict):
        # Non-JSON output — did the model refuse?
        refusal = _detect_refusal(raw_text=raw_text)
        if refusal:
            return VerdictRender(
                verdict="inconclusive",
                reason="model refused to render a verdict on this finding "
                       "(see refusal_log for details)",
                input_tokens=in_tok, output_tokens=out_tok,
                refusal_kind=refusal,
                refusal_excerpt=raw_text[:300],
            )
        return VerdictRender(
            verdict="inconclusive",
            reason="verdict stage returned non-json — defaulting to inconclusive",
            input_tokens=in_tok, output_tokens=out_tok,
        )

    # JSON parsed — still check for refusal language inside it
    refusal = _detect_refusal(parsed=parsed)

    v = str(parsed.get("verdict") or "inconclusive").strip().lower()
    if v not in ("confirmed", "refuted", "inconclusive"):
        v = "inconclusive"

    reasoning = str(parsed.get("reasoning", ""))[:2000]
    reason = str(parsed.get("reason", ""))[:400]
    evidence = str(parsed.get("evidence_excerpt", ""))[:1500]
    fix = str(parsed.get("suggested_fix", ""))[:400]

    # Safety net: downgrade obviously-unsupported "confirmed" verdicts.
    # If the verdict says confirmed but there's no evidence_for in the
    # briefing AND no excerpt cited, the model is overclaiming — drop to
    # inconclusive instead of reporting a false positive.
    if v == "confirmed" and not briefing.evidence_for and not evidence:
        v = "inconclusive"
        reason = (reason + " [downgraded: no concrete evidence in briefing]").strip()

    return VerdictRender(
        verdict=v, reasoning=reasoning, reason=reason,
        evidence_excerpt=evidence, suggested_fix=fix,
        input_tokens=in_tok, output_tokens=out_tok,
        refusal_kind=refusal,
        refusal_excerpt=(reasoning or reason)[:300] if refusal else "",
    )


def _build_user_prompt(target: str, findings: list[Finding],
                       generated_templates: list[str],
                       auth_summary: str) -> str:
    lines = [
        f"Target: {target}",
        f"Auth available: {auth_summary}",
        "",
        "Top findings to investigate (in order). For this run, focus on "
        "finding index 0 first; mention other indexes only if they prove "
        "directly related to confirming this bug.",
        "",
    ]
    for i, f in enumerate(findings):
        evidence = "; ".join(f.evidence[:4]) if f.evidence else "(none)"
        body = (f.body or "")[:300].replace("\n", " ")
        lines.append(f"[{i}] {f.method} {f.url}")
        lines.append(f"    score={f.score}  categories={', '.join(f.categories)}")
        lines.append(f"    evidence: {evidence}")
        if body:
            lines.append(f"    captured body: {body}")
    lines.append("")
    if generated_templates:
        lines.append("Generated nuclei templates available to run_nuclei:")
        for t in generated_templates[:12]:
            lines.append(f"  - {t}")
        lines.append("")
    lines.append(
        "Investigate finding [0]. Use the tools to send the requests a Burp "
        "operator would send to confirm this bug class. When you have enough "
        "evidence (or have run out of useful probes), emit the final JSON object."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class _ToolExecutor:
    """Stateful tool executor — bound to one solver run."""

    def __init__(self, target: str, findings: list[Finding],
                 auth_headers: dict[str, str],
                 out_dir: Path,
                 storage_state_path: Optional[str] = None,
                 nuclei_bin: str = "nuclei",
                 timeout: float = 15.0):
        self.target = target.rstrip("/")
        self.target_host = urlparse(self.target).netloc.lower()
        self.findings = findings
        self.auth_headers = dict(auth_headers or {})
        self.out_dir = out_dir
        self.storage_state_path = storage_state_path
        self.nuclei_bin = nuclei_bin
        self.timeout = timeout
        self._http: Optional[httpx.AsyncClient] = None
        self._browser_ctx = None  # lazy

    async def __aenter__(self):
        self._http = httpx.AsyncClient(
            timeout=self.timeout, verify=False, follow_redirects=False,
            http2=True,
        )
        return self

    async def __aexit__(self, *exc):
        if self._http:
            await self._http.aclose()
        if self._browser_ctx:
            try:
                ctx, browser, pw = self._browser_ctx
                await ctx.close()
                await browser.close()
                await pw.stop()
            except Exception:
                pass

    async def __call__(self, name: str, args: dict) -> dict:
        try:
            if name == "http_request":
                return await self._http_request(args)
            if name == "browser_eval":
                return await self._browser_eval(args)
            if name == "read_finding":
                return self._read_finding(args)
            if name == "run_nuclei":
                return await self._run_nuclei(args)
            if name == "encode_payload":
                return self._encode_payload(args)
            if name == "decode_detect":
                return self._decode_detect(args)
            return {"output": f"unknown tool: {name}", "is_error": True}
        except Exception as exc:
            return {"output": f"tool {name} crashed: "
                              f"{type(exc).__name__}: {exc}", "is_error": True}

    # ── http_request ──────────────────────────────────────────────────────
    async def _http_request(self, args: dict) -> dict:
        method = (args.get("method") or "GET").upper()
        url = args.get("url") or ""
        if not url:
            return {"output": "url is required", "is_error": True}
        # Host pinning — never let the agent send requests off-target.
        # The exception (target-internal SSRF) goes through the target's own
        # URL fields, which means the request URL itself stays on-target.
        host = urlparse(url).netloc.lower()
        if host and host != self.target_host:
            return {"output": f"refused: url host {host!r} is not the scanned "
                              f"target ({self.target_host!r}). Send the request "
                              f"to the target and put off-host URLs in a body "
                              f"or query parameter (for SSRF probes).",
                    "is_error": True}

        headers = dict(args.get("headers") or {})
        if args.get("use_auth", True):
            for k, v in self.auth_headers.items():
                headers.setdefault(k, v)
        body = args.get("body")

        try:
            r = await self._http.request(method, url, headers=headers,
                                         content=body)
        except Exception as exc:
            return {"output": f"http error: {type(exc).__name__}: {exc}",
                    "is_error": True}

        # Truncate response body — large bodies eat the context window fast
        text = r.text or ""
        truncated = ""
        if len(text) > 8000:
            text = text[:4000] + "\n...[truncated]...\n" + text[-4000:]
            truncated = " (truncated)"

        out = {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body_len": len(r.text or ""),
            "body": text + truncated,
        }
        return {"output": json.dumps(out, default=str), "is_error": False}

    # ── browser_eval ──────────────────────────────────────────────────────
    async def _browser_eval(self, args: dict) -> dict:
        url = args.get("url") or ""
        script = args.get("script") or ""
        wait_ms = int(args.get("wait_ms") or 500)
        if not url or not script:
            return {"output": "url and script are required", "is_error": True}
        host = urlparse(url).netloc.lower()
        if host and host != self.target_host:
            return {"output": f"refused: url host {host!r} is not the target",
                    "is_error": True}
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {"output": "playwright not installed — browser_eval unavailable",
                    "is_error": True}

        if self._browser_ctx is None:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            ctx_kwargs = {}
            if self.storage_state_path and Path(self.storage_state_path).exists():
                ctx_kwargs["storage_state"] = self.storage_state_path
            ctx = await browser.new_context(**ctx_kwargs)
            self._browser_ctx = (ctx, browser, pw)
        ctx, _, _ = self._browser_ctx

        page = await ctx.new_page()
        try:
            await page.goto(url, wait_until="load", timeout=20_000)
            await page.wait_for_timeout(wait_ms)
            result = await page.evaluate(script)
        except Exception as exc:
            await page.close()
            return {"output": f"browser_eval error: "
                              f"{type(exc).__name__}: {exc}", "is_error": True}
        await page.close()

        try:
            text = json.dumps(result, default=str)
        except Exception:
            text = str(result)
        if len(text) > 6000:
            text = text[:6000] + "\n...[truncated]..."
        return {"output": text, "is_error": False}

    # ── read_finding ──────────────────────────────────────────────────────
    def _read_finding(self, args: dict) -> dict:
        idx = int(args.get("index", -1))
        if idx < 0 or idx >= len(self.findings):
            return {"output": f"index out of range [0,{len(self.findings)-1}]",
                    "is_error": True}
        f = self.findings[idx]
        out = {
            "method": f.method,
            "url": f.url,
            "score": f.score,
            "categories": f.categories,
            "evidence": f.evidence,
            "request_body": f.body,
            "request_headers": f.headers,
            "response_status": f.response_status,
            "response_headers": f.response_headers,
            "response_body": (f.response_body or "")[:4000],
        }
        return {"output": json.dumps(out, default=str), "is_error": False}

    # ── encode_payload / decode_detect ───────────────────────────────────
    def _encode_payload(self, args: dict) -> dict:
        import codec  # local import — module is pure stdlib, no startup cost
        value = args.get("value", "")
        schemes = args.get("schemes")
        chain = bool(args.get("chain", False))
        if not isinstance(value, str):
            return {"output": "value must be a string", "is_error": True}
        if schemes is not None and not isinstance(schemes, list):
            return {"output": "schemes must be an array", "is_error": True}
        try:
            variants = codec.variants(value, schemes, chain=chain)
        except ValueError as exc:
            return {"output": f"encode error: {exc}", "is_error": True}
        body = [{"label": label, "value": encoded} for label, encoded in variants]
        return {"output": json.dumps(body), "is_error": False}

    def _decode_detect(self, args: dict) -> dict:
        import codec
        value = args.get("value", "")
        if not isinstance(value, str):
            return {"output": "value must be a string", "is_error": True}
        ranked = [{"scheme": s, "confidence": round(c, 3)}
                  for s, c in codec.detect(value)]
        decoded = [{"scheme": s, "value": v}
                   for s, v in codec.try_decode_all(value, max_depth=2)]
        return {"output": json.dumps({"ranked": ranked, "decoded": decoded}),
                "is_error": False}

    # ── run_nuclei ────────────────────────────────────────────────────────
    async def _run_nuclei(self, args: dict) -> dict:
        template = args.get("template") or ""
        target = args.get("target_override") or self.target
        if not template:
            return {"output": "template is required", "is_error": True}
        # Pin template path inside out_dir/nuclei/generated to keep nuclei
        # from running arbitrary YAML from elsewhere on disk.
        tdir = (self.out_dir / "nuclei" / "generated").resolve()
        tpath = (tdir / template).resolve()
        try:
            tpath.relative_to(tdir)
        except ValueError:
            return {"output": f"refused: template {template!r} escapes generated/ dir",
                    "is_error": True}
        if not tpath.exists():
            return {"output": f"template not found: {tpath.name}",
                    "is_error": True}

        host = urlparse(target).netloc.lower()
        if host and host != self.target_host:
            return {"output": f"refused: target {host!r} is not the scanned host",
                    "is_error": True}

        cmd = [self.nuclei_bin, "-t", str(tpath), "-u", target,
               "-silent", "-no-color", "-disable-update-check", "-timeout", "10"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        except FileNotFoundError:
            return {"output": f"nuclei binary not found: {self.nuclei_bin!r}",
                    "is_error": True}
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"output": "nuclei timed out after 30s", "is_error": True}

        out_text = (stdout or b"").decode(errors="replace")
        err_text = (stderr or b"").decode(errors="replace")
        out = {
            "exit_code": proc.returncode,
            "command": " ".join(shlex.quote(c) for c in cmd),
            "stdout": out_text[:4000],
            "stderr": err_text[:2000],
        }
        return {"output": json.dumps(out), "is_error": False}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def solve_findings(
    *,
    llm_generate,                        # async callable: client.generate(prompt, system, expect_json, temperature, max_tokens)
    model_name: str,                     # for the result/report
    budget_stats=None,                   # object with .budget_exhausted; optional
    classifier_result: ClassifierResult,
    target: str,
    out_dir: Path,
    auth_headers: Optional[dict[str, str]] = None,
    storage_state_path: Optional[str] = None,
    top_n: int = 5,
    verbose: bool = False,
    on_event=None,                       # optional progress callback
    public_url: Optional[str] = None,    # OOB tunnel URL — enables CRLF probes
    oob_token: Optional[str] = None,     # short token planted in callbacks
    # Compatibility kwargs from the previous tool-use API — accepted but
    # not used in the 3-stage pipeline. main.py still passes them.
    agent_runner=None,
    max_turns_per_finding: int = 0,
    nuclei_bin: str = "nuclei",
    thinking_budget: Optional[int] = None,
) -> ChallengeSolverResult:
    """Run the three-stage pipeline (recon → briefing → verdict) against the
    top-N classifier findings. `llm_generate` is provider-agnostic — pass
    `claude.generate`, `oa.generate`, or `llm.generate` from main.py.

    Mutates each visited Finding by setting `agent_verdict` / `agent_reason`
    / `agent_evidence` so the reporter can render verdicts inline.
    """
    del agent_runner, max_turns_per_finding, nuclei_bin, thinking_budget

    result = ChallengeSolverResult(model=model_name, target=target)
    findings = classifier_result.request_findings[:top_n]
    if not findings:
        return result

    for idx, finding in enumerate(findings):
        if on_event:
            try:
                on_event("solve_start", idx, finding.method, finding.url)
            except Exception:
                pass

        printer = _VerbosePrinter(idx=idx, finding=finding) if verbose else None

        # ── Stage 1: Recon ────────────────────────────────────────────
        if printer:
            printer.print_stage("Stage 1 — Recon (deterministic recipes)")
        bundle: ReconBundle = await collect_recon(
            finding=finding, finding_index=idx,
            target=target, auth_headers=auth_headers or {},
            ctx=ReconContext(public_url=public_url, oob_token=oob_token)
                if public_url else None,
        )
        if printer:
            printer.print_recon(bundle)

        # ── Stage 2: Briefing ─────────────────────────────────────────
        if printer:
            printer.print_stage("Stage 2 — Briefing (condenser LLM call)")
        briefing: Briefing = await generate_briefing(
            bundle=bundle, finding=finding, target=target,
            llm_generate=llm_generate,
        )
        # Refusal check on the briefing. When the briefing returned non-JSON,
        # briefing.raw is None and the raw refusal prose lives in
        # briefing.error (prefixed "non-json briefing: "); when the briefing
        # parsed but its structured fields contain refusal language, scan
        # briefing.raw. Cover both paths.
        briefing_refusal = _detect_refusal(
            raw_text=(briefing.error if not briefing.raw else ""),
            parsed=briefing.raw,
        )
        if briefing_refusal:
            result.refusals += 1
            briefing_excerpt = (briefing.reasoning
                                or briefing.error
                                or "")[:300]
            result.refusal_log.append({
                "finding_index": idx, "stage": "briefing",
                "kind": briefing_refusal,
                "raw_excerpt": briefing_excerpt,
            })
            if printer:
                printer.print_refusal("briefing", briefing_refusal,
                                      briefing_excerpt)
        if printer:
            printer.print_briefing(briefing)

        # ── Stage 3: Verdict ──────────────────────────────────────────
        if printer:
            printer.print_stage("Stage 3 — Verdict (briefing → final JSON)")
        vr = await _render_verdict(
            briefing=briefing, finding=finding, llm_generate=llm_generate,
        )
        if vr.refusal_kind:
            result.refusals += 1
            result.refusal_log.append({
                "finding_index": idx, "stage": "verdict",
                "kind": vr.refusal_kind,
                "raw_excerpt": vr.refusal_excerpt,
            })
            if printer:
                printer.print_refusal("verdict", vr.refusal_kind,
                                      vr.refusal_excerpt)
        if printer:
            printer.print_verdict(vr)

        in_tokens = briefing.input_tokens + vr.input_tokens
        out_tokens = briefing.output_tokens + vr.output_tokens

        solved = SolvedFinding(
            finding_index=idx, url=finding.url, method=finding.method,
            categories=list(finding.categories),
            verdict=vr.verdict, reason=vr.reason,
            verdict_reasoning=vr.reasoning,
            evidence_excerpt=vr.evidence_excerpt,
            suggested_fix=vr.suggested_fix,
            confidence=briefing.confidence,
            recipe_name=bundle.recipe_name,
            probes_sent=bundle.probes_sent,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            error=briefing.error,
            recon=bundle.to_dict(),
            briefing=briefing.to_dict(),
        )
        result.findings.append(solved)
        result.attempted += 1
        result.total_input_tokens += in_tokens
        result.total_output_tokens += out_tokens
        if vr.verdict == "confirmed":
            result.confirmed += 1
        elif vr.verdict == "refuted":
            result.refuted += 1
        elif vr.verdict == "inconclusive":
            result.inconclusive += 1
        if briefing.error:
            result.errors += 1

        # Mutate the classifier finding for the Top Findings inline column
        finding.agent_verdict = vr.verdict        # type: ignore[attr-defined]
        finding.agent_reason = vr.reason          # type: ignore[attr-defined]
        finding.agent_evidence = vr.evidence_excerpt  # type: ignore[attr-defined]
        finding.agent_fix = vr.suggested_fix       # type: ignore[attr-defined]
        finding.agent_model = model_name           # type: ignore[attr-defined]

        if on_event:
            try:
                on_event("solve_done", idx, vr.verdict, vr.reason)
            except Exception:
                pass

        if budget_stats is not None and getattr(budget_stats, "budget_exhausted", False):
            break

    return result


class _VerbosePrinter:
    """Streams every prompt, turn, and tool result to stderr so the operator
    can watch the agent reason in real time. One instance per finding."""

    def __init__(self, idx: int, finding: Finding):
        self.idx = idx
        self.finding = finding
        self.turn_n = 0
        import sys
        self._w = sys.stderr.write
        self._flush = sys.stderr.flush
        self._banner_header()

    def _hr(self, char: str = "─", n: int = 78) -> None:
        self._w(char * n + "\n")

    def _banner_header(self) -> None:
        self._w("\n")
        self._hr("═")
        self._w(f"║ Finding [{self.idx}]  "
                f"{self.finding.method} {self.finding.url}\n")
        self._w(f"║ Score {self.finding.score}  "
                f"Categories: {', '.join(self.finding.categories)}\n")
        self._hr("═")
        self._flush()

    def print_prompt(self, system: str, user: str) -> None:
        self._w("\n── system prompt ─────────────────────────────────────────"
                "────────────────────\n")
        self._w(system.rstrip() + "\n")
        self._w("\n── user prompt ───────────────────────────────────────────"
                "────────────────────\n")
        self._w(user.rstrip() + "\n")
        self._flush()

    def print_turn(self, turn) -> None:
        if turn.role == "assistant":
            self.turn_n += 1
            self._w(f"\n── turn {self.turn_n}  "
                    f"({turn.elapsed_ms}ms, stop={turn.stop_reason or '-'}) "
                    f"─────────────────────────────\n")
            if turn.thinking:
                self._w("  [thinking]\n")
                for line in turn.thinking.splitlines() or [""]:
                    self._w(f"  │ {line}\n")
            if turn.text:
                self._w("  [text]\n")
                for line in turn.text.splitlines() or [""]:
                    self._w(f"  │ {line}\n")
            for call in turn.tool_calls:
                inp = call.get("input", {})
                # Trim noisy args (body, script) for the live view
                short = {}
                for k, v in inp.items():
                    if isinstance(v, str) and len(v) > 200:
                        short[k] = v[:200] + f"…(+{len(v)-200} chars)"
                    else:
                        short[k] = v
                self._w(f"  [tool_use] {call['name']}({json.dumps(short, default=str)})\n")
        elif turn.role == "tool_result":
            for tr in turn.tool_results:
                marker = "ERR" if tr.get("is_error") else "OK"
                output = str(tr.get("output", ""))
                preview = output[:600]
                more = f" …(+{len(output)-600} chars)" if len(output) > 600 else ""
                self._w(f"  [tool_result/{marker}] {tr.get('name', '?')} → "
                        f"{preview}{more}\n")
        self._flush()

    # ── Three-stage pipeline printers ────────────────────────────────────

    def print_stage(self, label: str) -> None:
        self._w(f"\n── {label} ──────────────────────────────────────\n")
        self._flush()

    def print_refusal(self, stage: str, kind: str, excerpt: str) -> None:
        # Loud, scannable marker — refusals are usually the explanation for
        # an unexpected "inconclusive" verdict.
        self._w(f"\n  ⚠ [REFUSAL DETECTED] stage={stage}  kind={kind}\n")
        if excerpt:
            for line in excerpt.splitlines()[:6]:
                self._w(f"  ⚠ │ {line}\n")
        self._w("  ⚠ The model declined to complete this stage. Verdict will "
                "default to 'inconclusive'.\n")
        self._flush()

    def print_recon(self, bundle) -> None:
        self._w(f"  recipe: {bundle.recipe_name}  probes_sent: {bundle.probes_sent}\n")
        for n in bundle.notes:
            self._w(f"  note: {n}\n")
        for obs in bundle.observations:
            if obs.error:
                self._w(f"  · {obs.label:30s} ERROR {obs.error[:120]}\n")
                continue
            body_preview = (obs.response_body or "").replace("\n", " ")[:120]
            self._w(f"  · {obs.label:30s} {obs.status} "
                    f"({obs.response_size_bytes}b, {obs.elapsed_ms}ms): "
                    f"{body_preview}\n")
        self._flush()

    def print_briefing(self, briefing) -> None:
        if briefing.reasoning:
            self._w("  [reasoning]\n")
            for line in briefing.reasoning.splitlines():
                self._w(f"  │ {line}\n")
        self._w(f"  baseline: {briefing.baseline_behavior}\n")
        self._w(f"  preliminary_hypothesis: {briefing.preliminary_hypothesis}"
                f"  confidence: {briefing.confidence}\n")
        if briefing.key_observations:
            self._w("  key_observations:\n")
            for o in briefing.key_observations:
                self._w(f"    - {o}\n")
        if briefing.evidence_for:
            self._w("  evidence_for:\n")
            for e in briefing.evidence_for:
                self._w(f"    + {e}\n")
        if briefing.evidence_against:
            self._w("  evidence_against:\n")
            for e in briefing.evidence_against:
                self._w(f"    - {e}\n")
        if briefing.missing_information:
            self._w("  missing_information:\n")
            for m in briefing.missing_information:
                self._w(f"    ? {m}\n")
        if briefing.error:
            self._w(f"  briefing error: {briefing.error}\n")
        self._w(f"  briefing tokens: {briefing.input_tokens}in/{briefing.output_tokens}out "
                f"({briefing.elapsed_ms}ms)\n")
        self._flush()

    def print_verdict(self, vr) -> None:
        if vr.reasoning:
            self._w("  [reasoning]\n")
            for line in vr.reasoning.splitlines():
                self._w(f"  │ {line}\n")
        self._w(f"  VERDICT: {vr.verdict.upper()}\n")
        self._w(f"  reason: {vr.reason}\n")
        if vr.evidence_excerpt:
            self._w(f"  evidence: {vr.evidence_excerpt[:300]}\n")
        if vr.suggested_fix:
            self._w(f"  suggested_fix: {vr.suggested_fix}\n")
        self._w("\n")
        self._flush()

    def print_final(self, trace) -> None:
        self._w(f"\n── done  turns={len(trace.turns)}  "
                f"calls={trace.tool_calls_made}  "
                f"in/out={trace.total_input_tokens}/{trace.total_output_tokens}"
                f"  stop={trace.stop_reason}"
                f"{('  ERR=' + trace.error) if trace.error else ''}\n")
        if trace.final_text:
            self._w("\n  [final]\n")
            for line in trace.final_text.splitlines():
                self._w(f"  │ {line}\n")
        self._w("\n")
        self._flush()


def _parse_final(trace) -> tuple[str, str, str, str]:
    """Extract verdict / reason / evidence / fix from the agent's final JSON.
    Falls back to inconclusive if the model didn't follow the schema."""
    parsed = trace.final_parsed
    if not parsed:
        # Sometimes the model emits JSON in an earlier assistant turn
        for turn in reversed(trace.turns):
            if turn.role == "assistant" and turn.text:
                from claude_client import _maybe_parse_json
                parsed = _maybe_parse_json(turn.text)
                if parsed:
                    break
    if not parsed:
        return ("inconclusive" if not trace.error else "error",
                trace.error or "agent did not emit final JSON",
                "", "")
    v = (parsed.get("verdict") or "inconclusive").strip().lower()
    if v not in ("confirmed", "refuted", "inconclusive"):
        v = "inconclusive"
    return (v,
            str(parsed.get("reason", ""))[:400],
            str(parsed.get("evidence_excerpt", ""))[:1500],
            str(parsed.get("suggested_fix", ""))[:400])
