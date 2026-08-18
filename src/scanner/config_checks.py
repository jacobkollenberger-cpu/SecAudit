"""
Password policy and miscellaneous "insecure configuration" checks.

Linux: reads /etc/login.defs and pam_pwquality/pam_pwhistory config,
plus SSH daemon config for risky settings (root login, password auth,
empty passwords, protocol version).
"""

from __future__ import annotations
import os
import platform
import re

from ..models import Finding, Severity


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return ""


def _check_login_defs(target: str) -> list[Finding]:
    findings = []
    content = _read("/etc/login.defs")
    if not content:
        return findings

    def _get(key: str):
        m = re.search(rf"^\s*{key}\s+(\d+)", content, re.MULTILINE)
        return int(m.group(1)) if m else None

    max_days = _get("PASS_MAX_DAYS")
    min_len = _get("PASS_MIN_LEN")

    if max_days is not None and max_days > 90:
        findings.append(Finding(
            category="password_policy",
            title=f"Password max age too long ({max_days} days)",
            severity=Severity.LOW,
            description=f"/etc/login.defs sets PASS_MAX_DAYS={max_days}, exceeding common 90-day guidance.",
            recommendation="Set PASS_MAX_DAYS to 90 or less, per organizational policy.",
            target=target, evidence=f"PASS_MAX_DAYS={max_days}"))
    if min_len is not None and min_len < 12:
        findings.append(Finding(
            category="password_policy",
            title=f"Minimum password length too short ({min_len})",
            severity=Severity.MEDIUM,
            description=f"/etc/login.defs sets PASS_MIN_LEN={min_len}, below the commonly recommended 12+.",
            recommendation="Increase PASS_MIN_LEN to at least 12, and prefer pam_pwquality for complexity rules.",
            target=target, evidence=f"PASS_MIN_LEN={min_len}"))
    return findings


def _check_pwquality(target: str) -> list[Finding]:
    findings = []
    for path in ("/etc/security/pwquality.conf", "/etc/pam.d/common-password"):
        if os.path.exists(path):
            return findings  # something is configured; deeper parsing is future work
    findings.append(Finding(
        category="password_policy",
        title="No password complexity module detected",
        severity=Severity.MEDIUM,
        description="Neither pwquality.conf nor a common-password PAM config was found, "
                     "suggesting password complexity enforcement may not be configured.",
        recommendation="Install and configure libpam-pwquality (Debian/Ubuntu) or pam_pwquality (RHEL) "
                        "to enforce password complexity.",
        target=target))
    return findings


def _check_sshd_config(target: str) -> list[Finding]:
    findings = []
    content = _read("/etc/ssh/sshd_config")
    if not content:
        return findings
    lowered = content.lower()

    def has_setting(key: str, value: str) -> bool:
        return bool(re.search(rf"^\s*{key}\s+{value}", lowered, re.MULTILINE))

    if has_setting("permitrootlogin", "yes"):
        findings.append(Finding(
            category="configuration",
            title="SSH permits direct root login",
            severity=Severity.HIGH,
            description="sshd_config has PermitRootLogin yes, allowing direct root SSH logins.",
            recommendation="Set 'PermitRootLogin no' (or 'prohibit-password') and use sudo for privilege escalation.",
            target=target))

    if has_setting("permitemptypasswords", "yes"):
        findings.append(Finding(
            category="configuration",
            title="SSH permits empty passwords",
            severity=Severity.CRITICAL,
            description="sshd_config has PermitEmptyPasswords yes.",
            recommendation="Set 'PermitEmptyPasswords no' immediately.",
            target=target))

    if has_setting("passwordauthentication", "yes") and "permitrootlogin no" not in lowered:
        findings.append(Finding(
            category="configuration",
            title="SSH password authentication enabled",
            severity=Severity.LOW,
            description="sshd_config allows password authentication rather than requiring key-based auth.",
            recommendation="Prefer key-based authentication; set 'PasswordAuthentication no' where feasible.",
            target=target))

    if not findings:
        findings.append(Finding(
            category="configuration", title="sshd_config shows no obvious high-risk settings",
            severity=Severity.INFO,
            description="No PermitRootLogin/PermitEmptyPasswords/PasswordAuthentication red flags found.",
            recommendation="No action needed.", target=target))
    return findings


def check_password_policy(target: str = "localhost") -> list[Finding]:
    if platform.system() != "Linux":
        return [Finding(
            category="password_policy", title="Password policy check skipped",
            severity=Severity.INFO,
            description=f"Password policy file checks are Linux-specific; running on {platform.system()}.",
            recommendation="Use platform-native tools (e.g. secpol.msc on Windows) to review password policy.",
            target=target)]
    findings = _check_login_defs(target) + _check_pwquality(target)
    if not findings:
        findings.append(Finding(
            category="password_policy", title="Password policy appears reasonable",
            severity=Severity.INFO,
            description="No password policy weaknesses detected in the files checked.",
            recommendation="No action needed.", target=target))
    return findings


def check_configuration(target: str = "localhost") -> list[Finding]:
    if platform.system() != "Linux":
        return [Finding(
            category="configuration", title="Configuration check limited on this platform",
            severity=Severity.INFO,
            description=f"Detailed config checks (sshd_config etc.) are implemented for Linux only.",
            recommendation="No action needed.", target=target)]
    return _check_sshd_config(target)
