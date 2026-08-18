"""
Core data model for SecAudit.

Every check in the project (local system checks, network checks, etc.)
returns a list of Finding objects. Keeping one shared shape means the
scoring engine and every report writer (JSON/CSV/TXT/HTML) only need to
know about this one class.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import itertools


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        # Points deducted from 100 per finding of this severity.
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        # Lower = more severe. Used for sorting.
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


_id_counter = itertools.count(1)


@dataclass
class Finding:
    category: str          # e.g. "firewall", "network", "permissions"
    title: str              # short human summary
    severity: Severity
    description: str
    recommendation: str
    target: str = "localhost"
    evidence: Optional[str] = None    # raw data backing the finding
    cve: Optional[str] = None
    finding_id: str = field(default="")

    def __post_init__(self):
        if not self.finding_id:
            prefix = {
                Severity.CRITICAL: "CRIT",
                Severity.HIGH: "HIGH",
                Severity.MEDIUM: "MED",
                Severity.LOW: "LOW",
                Severity.INFO: "INFO",
            }[self.severity]
            self.finding_id = f"{prefix}-{next(_id_counter):03d}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AuditReport:
    target: str
    findings: list
    started_at: str
    finished_at: str
    score: int = 0
    grade: str = ""
    modules_run: list = field(default_factory=list)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "modules_run": self.modules_run,
            "security_score": self.score,
            "grade": self.grade,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
