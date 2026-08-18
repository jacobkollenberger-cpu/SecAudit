import csv
from ..models import AuditReport

FIELDS = ["finding_id", "severity", "category", "title", "target",
          "description", "recommendation", "evidence", "cve"]


def write_csv(report: AuditReport, path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for finding in sorted(report.findings, key=lambda x: x.severity.rank):
            row = finding.to_dict()
            writer.writerow({k: row.get(k, "") for k in FIELDS})
