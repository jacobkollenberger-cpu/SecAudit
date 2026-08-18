from ..models import AuditReport, Severity
from ..scoring.risk import severity_counts

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_text(report: AuditReport) -> str:
    lines = []
    lines.append("SECURITY AUDIT REPORT")
    lines.append("=" * 40)
    lines.append(f"Target: {report.target}")
    lines.append(f"Date:   {report.finished_at}")
    lines.append(f"Modules run: {', '.join(report.modules_run)}")
    lines.append("")
    lines.append(f"Security Score: {report.score}/100  (Grade: {report.grade})")
    lines.append("")

    by_sev = {s: [] for s in SEV_ORDER}
    for f in report.findings:
        by_sev[f.severity].append(f)

    for sev in SEV_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        header = sev.value
        lines.append(header)
        lines.append("-" * len(header))
        for f in items:
            lines.append(f"[{f.finding_id}] {f.title}")
            lines.append(f"  Target: {f.target}")
            lines.append(f"  {f.description}")
            lines.append(f"  Recommendation: {f.recommendation}")
            if f.evidence:
                lines.append(f"  Evidence: {f.evidence}")
            lines.append("")
        lines.append("")

    counts = severity_counts(report.findings)
    lines.append("SUMMARY")
    lines.append("-------")
    lines.append(f"Critical: {counts['CRITICAL']}")
    lines.append(f"High:     {counts['HIGH']}")
    lines.append(f"Medium:   {counts['MEDIUM']}")
    lines.append(f"Low:      {counts['LOW']}")
    lines.append(f"Info:     {counts['INFO']}")
    return "\n".join(lines)


def write_text(report: AuditReport, path: str) -> None:
    with open(path, "w") as f:
        f.write(render_text(report))
