"""
Turns a list of Finding objects into a single 0-100 score plus a letter
grade. Kept this simple on purpose - no weighting curves or diminishing
returns - so the math is just:

    score = 100 - sum(severity weight for each non-INFO finding)
    floor at 0, weights defined in models.Severity.weight

I didn't add diminishing returns for repeated criticals (e.g. 3 criticals
only counting as slightly worse than 2). Each one is a real, independent
risk, so they should each cost the full 25 points.
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
