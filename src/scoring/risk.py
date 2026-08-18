"""
Turns a list of Finding objects into a single 0-100 Security Score
plus a letter grade. The model is intentionally simple and documented
so it's easy to defend/explain (e.g. in an interview):

    score = 100 - sum(severity weight for each non-INFO finding)
    floor at 0, weights defined in models.Severity.weight

Diminishing returns are NOT applied - repeated criticals genuinely
should tank the score, since each represents a real independent risk.
"""

from __future__ import annotations
from ..models import Finding, Severity


def calculate_score(findings: list[Finding]) -> int:
    score = 100
    for f in findings:
        score -= f.severity.weight
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def severity_counts(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
