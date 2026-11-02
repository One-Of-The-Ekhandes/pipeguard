"""A 0-100 security score and letter grade, so teams can track improvement over time."""
from __future__ import annotations

from .models import Finding, Severity

PENALTY = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(PENALTY[f.severity] for f in findings))


def grade(value: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if value >= threshold:
            return letter
    return "F"
