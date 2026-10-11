"""Evidence-based confidence model.

Confidence is not a cosmetic label: it records how strong the evidence behind
a finding is. Rather than hard-coding ``high`` everywhere, each scanner states
the *kind* of evidence it observed and this module maps it to a confidence
level. This keeps results honest — a definitive header absence is ``high``,
while an inferred signal that may have a benign explanation is ``medium``.

Levels
------
- DEFINITIVE: the exact fact was observed directly and unambiguously
  (e.g. a response header is present/absent, a certificate field was parsed,
  a TCP connection was accepted).
- STRONG: directly observed, but interpretation needs a specific signature
  (e.g. a 200 that matches an artifact-specific marker).
- MODERATE: observed, yet a benign explanation is plausible
  (e.g. a 200 that could be a soft-404 catch-all).
- WEAK: heuristic or the probe itself failed, so the result is uncertain.
"""

from __future__ import annotations

from enum import Enum

from app.models import Confidence


class Evidence(str, Enum):
    DEFINITIVE = "definitive"
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


_EVIDENCE_TO_CONFIDENCE: dict[Evidence, Confidence] = {
    Evidence.DEFINITIVE: Confidence.HIGH,
    Evidence.STRONG: Confidence.HIGH,
    Evidence.MODERATE: Confidence.MEDIUM,
    Evidence.WEAK: Confidence.LOW,
}


def confidence_for(evidence: Evidence) -> Confidence:
    """Map an :class:`Evidence` level to a :class:`Confidence` value."""

    return _EVIDENCE_TO_CONFIDENCE[evidence]
