import json
from ..models import AuditReport


def write_json(report: AuditReport, path: str) -> None:
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
