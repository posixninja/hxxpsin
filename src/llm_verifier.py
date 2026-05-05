"""
llm_verifier.py — Use a local LLM to verify "likely" findings the heuristic
probes couldn't conclusively confirm.

Pipeline position: after every probe has run + after the heuristic verdict
is set, but BEFORE the report is written. The LLM verdict is *additive* —
it never overrides the heuristic. Each finding gets `llm_verdict` and
`llm_reason` fields appended; the report shows them side-by-side.

Three verification tasks:

  1. **IDOR `likely` → confirmed/refuted/inconclusive**
     Inputs: URL, A's body, B's body, anon body, status codes.
     Question: is account A reading data they don't own?

  2. **ActiveScanner `likely` (SQLi/SSTI/XSS reflection)**
     Inputs: probe URL, request body, response body, payload sent.
     Question: does the response indicate code execution / injection success?

  3. **Auth-bypass `likely`**
     Inputs: payload, response, session indicators.
     Question: does the response prove a successful authentication bypass?

Designed for 3-7B local models — short prompts, structured JSON output, single
turn, no chain-of-thought (small models hallucinate badly with CoT).
"""

import json
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Prompt templates — kept tight for small models. Each template:
#   1. Names the model's role (security analyst, terse)
#   2. Lists the SPECIFIC fields it must return as JSON
#   3. Provides the inputs as labelled blocks
#   4. Forbids extra prose
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a senior web AppSec analyst. You only ever respond with valid "
    "JSON. You never write explanations outside the JSON. Your verdict must "
    "be one of: confirmed, refuted, inconclusive."
)


def _truncate(s: str, n: int = 1500) -> str:
    """Truncate a string for prompt inclusion, preserving start + end."""
    if not s:
        return ""
    if len(s) <= n:
        return s
    half = (n - 20) // 2
    return s[:half] + "\n…[truncated]…\n" + s[-half:]


def prompt_verify_idor(url: str, method: str,
                       body_a: str, body_b: str, body_anon: str,
                       status_a: int, status_b: int, status_anon: int,
                       account_a_label: str = "A",
                       account_b_label: str = "B") -> str:
    return f"""Decide whether the request below proves a Broken Object Level Authorization (IDOR/BOLA) vulnerability.

Endpoint: {method} {url}

Anonymous fetch returned status: {status_anon}
Account {account_a_label} (logged in) returned status: {status_a}
Account {account_b_label} (logged in) returned status: {status_b}

Anonymous response body (first 1500 chars):
---
{_truncate(body_anon)}
---

Account {account_a_label} response body (first 1500 chars):
---
{_truncate(body_a)}
---

Account {account_b_label} response body (first 1500 chars):
---
{_truncate(body_b)}
---

Reply with ONLY this JSON object (no markdown, no extra text):
{{"verdict": "confirmed|refuted|inconclusive", "reason": "<one sentence>", "evidence_field": "<which JSON path or response feature gave it away, or empty>"}}
"""


def prompt_verify_injection(url: str, method: str, payload: str,
                            response_body: str, response_status: int,
                            attack_type: str) -> str:
    return f"""Decide whether the response indicates a successful {attack_type} attack.

Endpoint: {method} {url}
Payload sent: {payload!r}
Response status: {response_status}

Response body (first 1500 chars):
---
{_truncate(response_body)}
---

Common confirmation signals:
- SQLi: SQL syntax error mentioning the payload, UNION-injected columns, time-delay artefacts
- SSTI: payload was evaluated (e.g. {{7*7}} → 49 visible in body, ${{...}} expansions)
- Command Injection: command output (uid=, /etc/passwd lines, ipconfig output) in body
- XSS reflection: payload appears unencoded inside HTML/JS context where it would execute

Reply with ONLY this JSON object (no markdown, no extra text):
{{"verdict": "confirmed|refuted|inconclusive", "reason": "<one sentence>", "evidence_excerpt": "<short quote from response that proves it, or empty>"}}
"""


def prompt_verify_auth_bypass(login_url: str, payload: str, field: str,
                              response_body: str, response_status: int,
                              set_cookie: str = "") -> str:
    return f"""Decide whether the login attempt below succeeded — i.e., whether the auth-bypass payload worked.

Login endpoint: POST {login_url}
Field attacked: {field}
Payload sent: {payload!r}
Response status: {response_status}
Set-Cookie header: {set_cookie or '(none)'}

Response body (first 1500 chars):
---
{_truncate(response_body)}
---

A successful auth bypass typically shows: a JWT token in the body, a session cookie set, a "user" or "profile" object, or an HTTP redirect to /home or /dashboard. A failed attempt shows: error message, 401, "invalid credentials".

Reply with ONLY this JSON object (no markdown, no extra text):
{{"verdict": "confirmed|refuted|inconclusive", "reason": "<one sentence>", "leaked_token": "<the token if visible, or empty>"}}
"""


# ---------------------------------------------------------------------------
# Verifier — runs the prompts against an LLMClient and decorates findings
# ---------------------------------------------------------------------------

@dataclass
class LLMVerdict:
    verdict: str          # confirmed | refuted | inconclusive | error | budget_exhausted
    reason: str = ""
    evidence: str = ""
    cached: bool = False
    elapsed_ms: int = 0
    model: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "reason": self.reason,
            "evidence": self.evidence, "cached": self.cached,
            "elapsed_ms": self.elapsed_ms, "model": self.model,
        }


@dataclass
class LLMVerificationResult:
    idor_verified: int = 0
    injection_verified: int = 0
    auth_bypass_verified: int = 0
    promoted_to_confirmed: int = 0   # heuristic=likely → llm=confirmed
    refuted: int = 0
    inconclusive: int = 0
    errors: int = 0
    findings: list = field(default_factory=list)   # per-finding (kind, url, verdict)
    model: str = ""
    host: str = ""

    def to_dict(self) -> dict:
        return {
            "model": self.model, "host": self.host,
            "idor_verified": self.idor_verified,
            "injection_verified": self.injection_verified,
            "auth_bypass_verified": self.auth_bypass_verified,
            "promoted_to_confirmed": self.promoted_to_confirmed,
            "refuted": self.refuted, "inconclusive": self.inconclusive,
            "errors": self.errors,
            "findings": self.findings,
        }


class LLMVerifier:
    def __init__(self, llm_client):
        self.llm = llm_client
        self.result = LLMVerificationResult(model=llm_client.model,
                                             host=llm_client.host)

    async def verify_idor(self, idor_result, account_a, account_b) -> None:
        """Run the LLM over each 'likely' IDORFinding. Mutates each finding
        in-place by adding an `llm_verdict` attribute."""
        if not idor_result or not idor_result.likely:
            return
        for f in idor_result.likely[:25]:
            prompt = prompt_verify_idor(
                url=f.url, method=f.method,
                body_a=f.response_a or "", body_b=f.response_b or "",
                body_anon="(not captured)",
                status_a=200, status_b=200, status_anon=0,
                account_a_label=account_a.label if account_a else "A",
                account_b_label=account_b.label if account_b else "B",
            )
            verdict = await self._ask(prompt)
            self._apply(f, verdict, kind="idor")
            self.result.idor_verified += 1

    async def verify_active_scan(self, active_result) -> None:
        """Verify ActiveScanner 'likely' SQLi/SSTI/XSS findings."""
        if not active_result:
            return
        likely = [f for f in active_result.findings if f.verdict == "likely"]
        for f in likely[:25]:
            attack = getattr(f, "category", None) or getattr(f, "attack", None) or "injection"
            prompt = prompt_verify_injection(
                url=f.url, method=getattr(f, "method", "GET"),
                payload=getattr(f, "payload", ""),
                response_body=getattr(f, "response_snippet", "") or getattr(f, "evidence", ""),
                response_status=getattr(f, "response_status", 0) or 0,
                attack_type=attack,
            )
            verdict = await self._ask(prompt)
            self._apply(f, verdict, kind="active_scan")
            self.result.injection_verified += 1

    async def verify_auth_bypass(self, auth_bypass_result) -> None:
        if not auth_bypass_result:
            return
        likely = [f for f in auth_bypass_result.findings if f.verdict == "likely"]
        for f in likely[:25]:
            prompt = prompt_verify_auth_bypass(
                login_url=f.endpoint, payload=f.payload, field=f.field,
                response_body=getattr(f, "response_snippet", "") or "",
                response_status=getattr(f, "response_status", 0) or 0,
            )
            verdict = await self._ask(prompt)
            self._apply(f, verdict, kind="auth_bypass")
            self.result.auth_bypass_verified += 1

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    async def _ask(self, prompt: str) -> LLMVerdict:
        resp = await self.llm.generate(
            prompt=prompt, system=_SYSTEM_PROMPT,
            expect_json=True, temperature=0.0, max_tokens=256,
        )
        if not resp.ok:
            self.result.errors += 1
            return LLMVerdict(
                verdict="budget_exhausted" if "budget" in resp.error else "error",
                reason=resp.error,
                cached=resp.cached, elapsed_ms=resp.elapsed_ms,
                model=self.llm.model,
            )
        if not resp.parsed:
            self.result.errors += 1
            return LLMVerdict(
                verdict="error", reason=f"non-json: {resp.raw_text[:120]}",
                cached=resp.cached, elapsed_ms=resp.elapsed_ms,
                model=self.llm.model,
            )
        v = (resp.parsed.get("verdict") or "inconclusive").strip().lower()
        if v not in ("confirmed", "refuted", "inconclusive"):
            v = "inconclusive"
        evidence = (resp.parsed.get("evidence_field")
                    or resp.parsed.get("evidence_excerpt")
                    or resp.parsed.get("leaked_token") or "")
        return LLMVerdict(
            verdict=v,
            reason=str(resp.parsed.get("reason", ""))[:300],
            evidence=str(evidence)[:300],
            cached=resp.cached, elapsed_ms=resp.elapsed_ms,
            model=self.llm.model,
        )

    def _apply(self, finding, verdict: LLMVerdict, kind: str) -> None:
        # Attach to finding object — Reporter will pick it up
        finding.llm_verdict = verdict.verdict
        finding.llm_reason = verdict.reason
        finding.llm_evidence = verdict.evidence
        finding.llm_model = verdict.model
        # Track for the verification summary
        self.result.findings.append({
            "kind": kind, "url": getattr(finding, "url", "")
                or getattr(finding, "endpoint", ""),
            "heuristic": getattr(finding, "verdict", ""),
            "llm": verdict.verdict, "reason": verdict.reason[:200],
        })
        if verdict.verdict == "confirmed" and getattr(finding, "verdict", "") == "likely":
            self.result.promoted_to_confirmed += 1
        elif verdict.verdict == "refuted":
            self.result.refuted += 1
        elif verdict.verdict == "inconclusive":
            self.result.inconclusive += 1
