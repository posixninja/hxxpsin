"""Unified confidence model tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from confidence import (
    from_classifier_score, from_verifier_verdict, promote_verdict,
    dedupe_evidence, EvidenceBundle, Verdict,
)


def test_classifier_score_maps_to_likely():
    label = from_classifier_score(50)
    assert label.verdict == Verdict.LIKELY
    assert label.confidence == 0.5


def test_oob_promotion():
    label = from_verifier_verdict("likely", 0.6)
    promoted = promote_verdict(label, oob_hit=True)
    assert promoted.verdict == Verdict.CONFIRMED


def test_dedupe_evidence_keeps_higher_confidence():
    a = EvidenceBundle("http://x", "GET", ["x"], "likely", 0.5, "medium", "a")
    b = EvidenceBundle("http://x", "GET", ["x"], "confirmed", 0.9, "high", "b")
    out = dedupe_evidence([a, b])
    assert len(out) == 1
    assert out[0].confidence == 0.9
