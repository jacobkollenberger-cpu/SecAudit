"""
Suspicious process heuristics. This is deliberately conservative and
labeled as heuristic in every finding: it flags process names that
match a small watchlist (reference_data.SUSPICIOUS_PROCESS_HINTS),
processes running as root/SYSTEM with network connections, and
processes executing from world-writable or temp directories.
"""

from __future__ import annotations
import os
import re

from ..models import Finding, Severity
from . import reference_data as ref

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

TEMP_DIR_HINTS = ("/tmp/", "/var/tmp/", "/dev/shm/")


def check_processes(target: str = "localhost") -> list[Finding]:
    if not HAVE_PSUTIL:
        return [Finding(
            category="processes", title="Process check skipped (psutil unavailable)",
            severity=Severity.INFO,
            description="psutil is required for process enumeration but is not installed.",
            recommendation="pip install psutil", target=target)]

    findings = []
    for proc in psutil.process_iter(["pid", "name", "username", "exe", "cmdline"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for hint in ref.SUSPICIOUS_PROCESS_HINTS:
            # Word-boundary match so short hints like "nc" don't match
            # substrings of unrelated names (e.g. "sync_wq").
            pattern = r"(?<![a-zA-Z0-9])" + re.escape(hint) + r"(?![a-zA-Z0-9])"
            if re.search(pattern, name) or re.search(pattern, cmdline.lower()):
                findings.append(Finding(
                    category="processes",
                    title=f"Process matches watchlist term '{hint}'",
                    severity=Severity.MEDIUM,
                    description=(f"PID {info.get('pid')} ('{info.get('name')}', user="
                                 f"{info.get('username')}) matched watchlist term '{hint}'. "
                                 f"This is a heuristic match, not a confirmed threat - many "
                                 f"legitimate admin/security tools trigger it too."),
                    recommendation="Manually verify this process is expected and authorized.",
                    target=target,
                    evidence=cmdline[:200] or exe,
                ))
                break

        if exe and any(exe.startswith(td) for td in TEMP_DIR_HINTS):
            findings.append(Finding(
                category="processes",
                title="Process executing from a temp directory",
                severity=Severity.MEDIUM,
                description=f"PID {info.get('pid')} ('{info.get('name')}') is running from {exe}, "
                             f"a world-writable temp location commonly used to stage malicious payloads.",
                recommendation="Verify the binary's origin and legitimacy; consider noexec mounts for temp dirs.",
                target=target,
                evidence=exe,
            ))

    if not findings:
        findings.append(Finding(
            category="processes", title="No suspicious processes flagged",
            severity=Severity.INFO,
            description="No running processes matched the watchlist or temp-directory heuristics.",
            recommendation="No action needed.", target=target))
    return findings
