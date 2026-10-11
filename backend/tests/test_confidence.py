"""Evidence-to-confidence mapping."""

from __future__ import annotations

from app.models import Confidence
from app.scoring.confidence import Evidence, confidence_for


def test_definitive_and_strong_are_high():
    assert confidence_for(Evidence.DEFINITIVE) is Confidence.HIGH
    assert confidence_for(Evidence.STRONG) is Confidence.HIGH


def test_moderate_is_medium():
    assert confidence_for(Evidence.MODERATE) is Confidence.MEDIUM


def test_weak_is_low():
    assert confidence_for(Evidence.WEAK) is Confidence.LOW
