"""
confidence.py — Unified confidence / severity model for classifier + verifier.

Maps heuristic scores and probe verdicts to a consistent 0.0–1.0 confidence
and normalized severity for reporting and deduplication.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NOT_CONFIRMED = "not_confirmed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ConfidenceLabel:
    confidence: float
    severity: Severity
    verdict: Verdict

    def to_dict(self) -> dict:
        return {
            "confidence": round(self.confidence, 3),
            "severity": self.severity.value,
            "verdict": self.verdict.value,
        }


def score_to_severity(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


def score_to_confidence(score: int) -> float:
    return min(1.0, max(0.0, score / 100.0))


def from_classifier_score(score: int) -> ConfidenceLabel:
    conf = score_to_confidence(score)
    sev = score_to_severity(score)
    verdict = Verdict.LIKELY if score >= 35 else Verdict.NOT_CONFIRMED
    return ConfidenceLabel(confidence=conf, severity=sev, verdict=verdict)


def from_verifier_verdict(verdict: str, confidence: float) -> ConfidenceLabel:
    v = Verdict(verdict) if verdict in Verdict._value2member_map_ else Verdict.NOT_CONFIRMED
    conf = max(0.0, min(1.0, confidence))
    if v == Verdict.CONFIRMED:
        sev = Severity.HIGH if conf >= 0.85 else Severity.MEDIUM
    elif v == Verdict.LIKELY:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW
    return ConfidenceLabel(confidence=conf, severity=sev, verdict=v)


def promote_verdict(label: ConfidenceLabel, oob_hit: bool = False) -> ConfidenceLabel:
    """Promote likely → confirmed when OOB or strong oracle fires."""
    if oob_hit and label.verdict in (Verdict.LIKELY, Verdict.NOT_CONFIRMED):
        return ConfidenceLabel(
            confidence=max(label.confidence, 0.9),
            severity=Severity.HIGH,
            verdict=Verdict.CONFIRMED,
        )
    return label


@dataclass
class EvidenceBundle:
    """Standard evidence shape for reporter dedup."""

    url: str
    method: str
    categories: list[str]
    verdict: str
    confidence: float
    severity: str
    evidence: str
    request_snippet: str = ""
    response_snippet: str = ""
    screenshot_path: str = ""
    oob_correlated: bool = False

    @property
    def dedup_key(self) -> str:
        return f"{self.method}:{self.url}:{','.join(sorted(self.categories))}"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "categories": self.categories,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence": self.evidence,
            "request_snippet": self.request_snippet,
            "response_snippet": self.response_snippet,
            "screenshot_path": self.screenshot_path,
            "oob_correlated": self.oob_correlated,
        }


def evidence_from_verify_result(r) -> EvidenceBundle:
    label = from_verifier_verdict(r.verdict, r.confidence)
    return EvidenceBundle(
        url=r.url,
        method=r.method,
        categories=list(r.categories),
        verdict=label.verdict.value,
        confidence=label.confidence,
        severity=label.severity.value,
        evidence=r.evidence,
        request_snippet=getattr(r, "request_snippet", "") or "",
        response_snippet=getattr(r, "response_snippet", "") or "",
    )


def dedupe_evidence(bundles: list[EvidenceBundle]) -> list[EvidenceBundle]:
    seen: dict[str, EvidenceBundle] = {}
    for b in bundles:
        k = b.dedup_key
        if k not in seen or b.confidence > seen[k].confidence:
            seen[k] = b
    return sorted(seen.values(), key=lambda x: -x.confidence)
