from ..models import AuditReport, Severity
from ..scoring.risk import severity_counts

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEV_COLORS = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#4b5563",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecAudit Report - {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
         background: #0f172a; color: #e2e8f0; }}
  .card {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 2rem; }}
  h1 {{ margin-top: 0; }}
  .score {{ font-size: 3rem; font-weight: 700; }}
  .grade {{ font-size: 1.5rem; opacity: 0.8; }}
  .meta {{ color: #94a3b8; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }}
  .pill {{ padding: 0.4rem 0.8rem; border-radius: 999px; font-weight: 600; font-size: 0.85rem; color: white; }}
  section {{ margin-top: 2rem; }}
  section h2 {{ border-bottom: 2px solid #334155; padding-bottom: 0.4rem; }}
  .finding {{ background: #0f172a; border-left: 4px solid; border-radius: 6px; padding: 1rem; margin: 0.75rem 0; }}
  .finding h3 {{ margin: 0 0 0.4rem 0; font-size: 1rem; }}
  .finding .id {{ color: #94a3b8; font-size: 0.8rem; }}
  .finding .rec {{ color: #86efac; margin-top: 0.5rem; }}
  .finding .evidence {{ font-family: monospace; font-size: 0.8rem; color: #94a3b8; margin-top: 0.4rem;
                        background: #020617; padding: 0.4rem; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
<div class="card">
  <h1>SecAudit Report</h1>
  <div class="meta">Target: {target} &middot; Generated: {finished_at} &middot; Modules: {modules}</div>
  <div class="score">{score}/100 <span class="grade">Grade {grade}</span></div>
  <div class="summary">{pills}</div>
  {sections}
</div>
</body>
</html>
"""


def render_html(report: AuditReport) -> str:
    counts = severity_counts(report.findings)
    pills = "".join(
        f'<span class="pill" style="background:{SEV_COLORS[s]}">{s.value}: {counts[s.value]}</span>'
        for s in SEV_ORDER
    )

    by_sev = {s: [] for s in SEV_ORDER}
    for f in report.findings:
        by_sev[f.severity].append(f)

    sections = []
    for sev in SEV_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        block = [f"<section><h2 style='color:{SEV_COLORS[sev]}'>{sev.value} ({len(items)})</h2>"]
        for f in items:
            evidence_html = f'<div class="evidence">{_escape(f.evidence)}</div>' if f.evidence else ""
            block.append(f"""
            <div class="finding" style="border-color:{SEV_COLORS[sev]}">
              <div class="id">{f.finding_id} &middot; {f.category} &middot; {f.target}</div>
              <h3>{_escape(f.title)}</h3>
              <div>{_escape(f.description)}</div>
              <div class="rec">Recommendation: {_escape(f.recommendation)}</div>
              {evidence_html}
            </div>""")
        block.append("</section>")
        sections.append("".join(block))

    return TEMPLATE.format(
        target=_escape(report.target),
        finished_at=report.finished_at,
        modules=", ".join(report.modules_run),
        score=report.score,
        grade=report.grade,
        pills=pills,
        sections="".join(sections),
    )


def _escape(text) -> str:
    if text is None:
        return ""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def write_html(report: AuditReport, path: str) -> None:
    with open(path, "w") as f:
        f.write(render_html(report))
