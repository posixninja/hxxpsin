"""
briefing_generator.py — Stage 2 of the agentic solver pipeline.

Takes the raw ReconBundle produced by stage 1 and asks the LLM to condense
it into a structured "briefing" — the evidence-for/evidence-against split,
key observations, missing info, preliminary hypothesis. NO verdict is made
here; the goal is to give the verdict stage (stage 3) a clean, decision-
ready summary instead of a transcript of raw HTTP responses.

This stage is a SINGLE LLM call (no tools, no loop) with strict JSON output.
Even on a 7B model the output is dramatically more useful than the same
model trying to interpret raw responses in a multi-turn agent loop — the
prompt is tightly scoped and the input is already pre-organized by the
deterministic recipe.

System-prompt framing is deliberate: the model is told it's a senior
professional pentester analyzing recon data from an explicitly-authorized
CTF target. That framing reduces "I shouldn't speculate" type refusals
without nudging it toward overclaiming.
"""

import json
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from classifier import Finding
from recon_collector import ReconBundle


# Operator override — when set, the next briefing prompt prepends this text so
# the analyst LLM gets a steering note from the TUI ("skip the captcha flow",
# "focus on the X endpoint"). Read-once: cleared after consumption so a single
# override doesn't permanently colour every subsequent finding.
_pending_override: list[str] = []


def push_override(msg: str) -> None:
    """Queue an operator note for the next briefing call. Idempotent for
    duplicate messages within the same queue. Safe to call from the TUI."""
    msg = (msg or "").strip()
    if not msg:
        return
    if msg in _pending_override:
        return
    _pending_override.append(msg)


def _consume_override() -> str:
    if not _pending_override:
        return ""
    msg = _pending_override.pop(0)
    return msg


def format_stage_context(stage_timings: list[dict] | None, stage_errors: list[str] | None = None) -> str:
    """Compact pipeline timing summary for LLM briefing prompts."""
    lines: list[str] = []
    if stage_timings:
        lines.append("Pipeline stages (ms):")
        for t in sorted(stage_timings, key=lambda x: -x.get("elapsed_ms", 0))[:20]:
            lines.append(
                f"  - {t.get('name', '?')}: {t.get('status', '?')} "
                f"({t.get('elapsed_ms', 0):.0f}ms)"
            )
    if stage_errors:
        lines.append("Stage errors:")
        for e in stage_errors[:10]:
            lines.append(f"  - {e}")
    return "\n".join(lines) if lines else ""


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

@dataclass
class Briefing:
    reasoning: str = ""                      # explicit CoT before the structured fields
    baseline_behavior: str = ""              # one-line description of normal response
    key_observations: list[str] = field(default_factory=list)
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    preliminary_hypothesis: str = "inconclusive"  # confirmed | refuted | inconclusive
    confidence: int = 0                      # 0–3 from the condenser
    raw: Optional[dict] = None
    elapsed_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "reasoning": self.reasoning,
            "baseline_behavior": self.baseline_behavior,
            "key_observations": self.key_observations,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "missing_information": self.missing_information,
            "preliminary_hypothesis": self.preliminary_hypothesis,
            "confidence": self.confidence,
            "elapsed_ms": self.elapsed_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Prompts — heavy on framing, light on length so even 7B context fits cleanly
# ---------------------------------------------------------------------------

CONDENSER_SYSTEM = """You are a senior offensive web application penetration tester analyzing reconnaissance data captured during an EXPLICITLY AUTHORIZED engagement against an intentionally-vulnerable training target (a CTF box, Juice Shop, WebGoat, OWASP demo app, or equivalent training environment). You have written permission to probe this target. Acting on the data is in scope.

Your role at this stage is the EVIDENCE ANALYST. You did not run the probes — another module already executed a category-specific probe recipe and captured the raw HTTP responses. Your job is to read those responses, line them up against each other, and produce a structured EVIDENCE BRIEFING that a verdict-rendering analyst will use to decide whether the bug is confirmed, refuted, or inconclusive.

Discipline you MUST follow:

1. Do NOT render a verdict in this stage. Your `preliminary_hypothesis` is a HUNCH meant to guide the verdict step, not a decision. Bias toward "inconclusive" unless the evidence is concrete.
2. Treat HTTP status codes as weak signals, not strong ones. A 404 is not refutation; a 500 is not confirmation. What matters is the BODY CONTENT — does it leak another user's data? does it reflect our payload? does it expand a template?
3. Compare the variants against the baseline. The whole point of recon is the diff. If three variants returned the same response as baseline, that's an observation. If one variant returned something materially different, that's the signal.
4. When you cite evidence, quote the SHORTEST verbatim fragment from the response body that establishes the point — not a paraphrase.
5. If the recon was thin (only 1–2 probes, lots of errors, fallback recipe used), say so in `missing_information` and lean inconclusive.

OUTPUT FORMAT — respond with EXACTLY this JSON object (no markdown, no code fences, no surrounding prose). The `reasoning` field comes FIRST and is mandatory; use it to think step-by-step through the recon data BEFORE filling in the structured fields. Treat it as your scratchpad — walk through the variants, compare against baseline, decide what the evidence supports:

{
  "reasoning": "<3-6 sentences of step-by-step thinking. Walk through: what was the baseline response? How did each variant differ? Which differences are concrete bug signals vs noise? What does the evidence support?>",
  "baseline_behavior": "<one sentence describing the normal response to the captured request>",
  "key_observations": ["<observation 1>", "<observation 2>", ...],
  "evidence_for": ["<concrete signal supporting the vuln, with quoted excerpt>", ...],
  "evidence_against": ["<concrete signal refuting the vuln>", ...],
  "missing_information": ["<what data we would need to be sure>", ...],
  "preliminary_hypothesis": "confirmed | refuted | inconclusive",
  "confidence": 0
}

`confidence` is 0 (no clear signal), 1 (weak signal), 2 (strong signal — clear behavioral diff), or 3 (definitive — response contains data that proves the bug, e.g. another user's record, a reflected payload, an EC2 metadata document).

The structured fields after `reasoning` must be CONSISTENT with what you said in `reasoning`. If your reasoning concluded the bug is refuted, do not then set preliminary_hypothesis to confirmed — that's a sign of broken thinking.
"""


def _build_condense_prompt(bundle: ReconBundle, finding: Finding,
                           target: str) -> str:
    lines: list[str] = [
        f"Target: {target}",
        f"Finding: [{bundle.finding_index}] {finding.method} {finding.url}",
        f"Categories: {', '.join(bundle.finding_categories)}",
        f"Classifier score: {finding.score}",
        f"Classifier evidence: {'; '.join(finding.evidence[:5]) or '(none)'}",
        f"Recon recipe used: {bundle.recipe_name}",
        "",
    ]
    if bundle.notes:
        lines.append("Recipe guidance (what counts as confirmation for this category):")
        for n in bundle.notes:
            lines.append(f"  - {n}")
        lines.append("")
    lines.append("=== Raw reconnaissance observations ===")
    for obs in bundle.observations:
        lines.append("")
        lines.append(f"-- {obs.label} --")
        if obs.error:
            lines.append(f"  ERROR: {obs.error}")
            continue
        lines.append(f"  {obs.method} {obs.url}")
        if obs.request_body:
            body_preview = obs.request_body[:300].replace("\n", " ")
            lines.append(f"  request body: {body_preview}")
        if obs.request_headers_subset:
            lines.append(f"  request headers: {obs.request_headers_subset}")
        lines.append(f"  status: {obs.status}  size: {obs.response_size_bytes} bytes"
                     + ("  (truncated)" if obs.response_truncated else ""))
        if obs.response_headers:
            lines.append(f"  response headers: {obs.response_headers}")
        body = obs.response_body or ""
        if body:
            lines.append("  response body:")
            for bl in body.splitlines()[:60]:
                lines.append(f"    {bl}")
        else:
            lines.append("  response body: (empty)")
    lines.append("")
    lines.append("=== End of reconnaissance ===")
    lines.append("")
    lines.append("Produce the JSON briefing now.")
    return "\n".join(lines)


# Caller-supplied LLM call: (system, user, expect_json, temperature, max_tokens) -> response-like obj
LLMCall = Callable[..., Awaitable[object]]


async def generate_briefing(
    bundle: ReconBundle, finding: Finding, target: str,
    llm_generate: LLMCall,
    *, temperature: float = 0.0, max_tokens: int = 1500,
    stage_timings: list[dict] | None = None,
    stage_errors: list[str] | None = None,
) -> Briefing:
    """Send the recon bundle through the condenser LLM call and return a
    Briefing. The caller provides `llm_generate`, which must accept the
    standard (prompt, system, expect_json, temperature, max_tokens) kwargs
    and return an object with .raw_text, .parsed, .input_tokens,
    .output_tokens, .elapsed_ms, .error — same shape every provider already
    returns from its generate() method."""
    prompt = _build_condense_prompt(bundle, finding, target)
    stage_ctx = format_stage_context(stage_timings, stage_errors)
    if stage_ctx:
        prompt = stage_ctx + "\n\n" + prompt
    override = _consume_override()
    if override:
        prompt = (
            "OPERATOR NOTE (from TUI): "
            + override.replace("\n", " ")
            + "\n\n"
            + prompt
        )

    resp = await llm_generate(
        prompt=prompt, system=CONDENSER_SYSTEM,
        expect_json=True, temperature=temperature, max_tokens=max_tokens,
    )

    elapsed_ms = getattr(resp, "elapsed_ms", 0)
    in_tok = getattr(resp, "input_tokens", 0)
    out_tok = getattr(resp, "output_tokens", 0)
    error = getattr(resp, "error", "") or ""

    parsed = getattr(resp, "parsed", None)
    if not parsed or not isinstance(parsed, dict):
        return Briefing(
            preliminary_hypothesis="inconclusive",
            error=error or f"non-json briefing: {getattr(resp, 'raw_text', '')[:200]}",
            elapsed_ms=elapsed_ms, input_tokens=in_tok, output_tokens=out_tok,
        )

    hypothesis = str(parsed.get("preliminary_hypothesis") or "inconclusive").strip().lower()
    if hypothesis not in ("confirmed", "refuted", "inconclusive"):
        hypothesis = "inconclusive"

    def _strlist(v) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x)[:500] for x in v[:10]]

    return Briefing(
        reasoning=str(parsed.get("reasoning") or "")[:2000],
        baseline_behavior=str(parsed.get("baseline_behavior") or "")[:500],
        key_observations=_strlist(parsed.get("key_observations")),
        evidence_for=_strlist(parsed.get("evidence_for")),
        evidence_against=_strlist(parsed.get("evidence_against")),
        missing_information=_strlist(parsed.get("missing_information")),
        preliminary_hypothesis=hypothesis,
        confidence=max(0, min(3, int(parsed.get("confidence") or 0))),
        raw=parsed,
        elapsed_ms=elapsed_ms,
        input_tokens=in_tok, output_tokens=out_tok,
        error=error,
    )


# ---------------------------------------------------------------------------
# Quick brief — TUI-driven, no recon stage. Takes whatever fields already
# exist on a finding dict (verdict, evidence, payload, response_snippet, …)
# and asks the LLM to produce a Briefing-shaped summary. Cheaper and faster
# than re-running recon; useful when the operator wants a second opinion
# on an existing finding from the Findings tab.
# ---------------------------------------------------------------------------

async def quick_brief_finding(
    finding: dict, target: str, llm_generate: LLMCall,
    *, temperature: float = 0.0, max_tokens: int = 1200,
) -> Briefing:
    if not isinstance(finding, dict):
        return Briefing(error="quick_brief: finding is not a dict")

    lines: list[str] = [
        f"Target: {target}",
        f"Finding: {finding.get('method', 'GET')} {finding.get('url', '')}",
    ]
    for k in (
        "category", "categories", "verdict", "confidence",
        "test_kind", "attack", "payload", "injected",
        "source", "sink", "evidence", "response_snippet",
        "bypass_source", "original_status", "new_status",
    ):
        v = finding.get(k)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, dict)):
            v = json.dumps(v, default=str)[:400]
        else:
            v = str(v)[:400]
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("Produce the JSON briefing now.")
    prompt = "\n".join(lines)

    override = _consume_override()
    if override:
        prompt = (
            "OPERATOR NOTE (from TUI): "
            + override.replace("\n", " ")
            + "\n\n"
            + prompt
        )

    resp = await llm_generate(
        prompt=prompt, system=CONDENSER_SYSTEM,
        expect_json=True, temperature=temperature, max_tokens=max_tokens,
    )

    elapsed_ms = getattr(resp, "elapsed_ms", 0)
    in_tok = getattr(resp, "input_tokens", 0)
    out_tok = getattr(resp, "output_tokens", 0)
    error = getattr(resp, "error", "") or ""

    parsed = getattr(resp, "parsed", None)
    if not parsed or not isinstance(parsed, dict):
        return Briefing(
            preliminary_hypothesis="inconclusive",
            error=error or f"non-json briefing: {getattr(resp, 'raw_text', '')[:200]}",
            elapsed_ms=elapsed_ms, input_tokens=in_tok, output_tokens=out_tok,
        )

    def _strlist2(v) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x)[:500] for x in v[:10]]

    hypothesis = str(parsed.get("preliminary_hypothesis") or "inconclusive").strip().lower()
    if hypothesis not in ("confirmed", "refuted", "inconclusive"):
        hypothesis = "inconclusive"

    return Briefing(
        reasoning=str(parsed.get("reasoning") or "")[:2000],
        baseline_behavior=str(parsed.get("baseline_behavior") or "")[:500],
        key_observations=_strlist2(parsed.get("key_observations")),
        evidence_for=_strlist2(parsed.get("evidence_for")),
        evidence_against=_strlist2(parsed.get("evidence_against")),
        missing_information=_strlist2(parsed.get("missing_information")),
        preliminary_hypothesis=hypothesis,
        confidence=max(0, min(3, int(parsed.get("confidence") or 0))),
        raw=parsed,
        elapsed_ms=elapsed_ms,
        input_tokens=in_tok, output_tokens=out_tok,
        error=error,
    )
