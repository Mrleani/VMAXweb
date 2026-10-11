"""Security Health Score (0-100) and letter grade."""

from __future__ import annotations

from app.models import Finding, Severity

# Penalty applied per finding, weighted by severity.
_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 18,
    Severity.WARNING: 6,
    Severity.INFO: 1,
    Severity.PASSED: 0,
}

# (minimum_score, grade, label)
_GRADE_BANDS: tuple[tuple[int, str, str], ...] = (
    (90, "A", "LOW RISK"),
    (80, "B", "MODERATE RISK"),
    (70, "C", "ELEVATED RISK"),
    (60, "D", "HIGH RISK"),
    (0, "F", "CRITICAL RISK"),
)


def score_findings(findings: list[Finding]) -> int:
    """Return a 0-100 health score where 100 is fully hardened."""

    score = 100
    for finding in findings:
        score -= _PENALTIES.get(finding.severity, 0)
    return max(0, min(100, score))


def grade_for(score: int) -> tuple[str, str]:
    """Map a numeric score to ``(grade, label)``."""

    for minimum, grade, label in _GRADE_BANDS:
        if score >= minimum:
            return grade, label
    return "F", "CRITICAL RISK"
