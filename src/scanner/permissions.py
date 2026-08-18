"""
File permission checks. Focuses on the handful of files where a
permission mistake has outsized security impact: shadow/passwd,
SSH private keys, sudoers, and world-writable files in common
system directories.
"""

from __future__ import annotations
import os
import stat
import platform

from ..models import Finding, Severity

SENSITIVE_FILES = {
    "/etc/shadow": 0o640,   # should not be world-readable
    "/etc/passwd": 0o644,
    "/etc/sudoers": 0o440,
}

WORLD_WRITABLE_SCAN_DIRS = ["/etc", "/usr/local/bin", "/opt"]


def _mode_str(mode: int) -> str:
    return stat.filemode(mode)


def _check_sensitive_files(target: str) -> list[Finding]:
    findings = []
    for path, max_mode in SENSITIVE_FILES.items():
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
        except (PermissionError, OSError):
            continue
        actual = stat.S_IMODE(st.st_mode)
        world_readable = bool(actual & stat.S_IROTH)
        world_writable = bool(actual & stat.S_IWOTH)

        if path.endswith("shadow") and world_readable:
            findings.append(Finding(
                category="permissions",
                title=f"{path} is world-readable",
                severity=Severity.CRITICAL,
                description=f"{path} has mode {_mode_str(st.st_mode)}; password hashes are exposed to all local users.",
                recommendation=f"chmod 640 {path} (owner root, group shadow).",
                target=target, evidence=oct(actual)))
        if world_writable:
            findings.append(Finding(
                category="permissions",
                title=f"{path} is world-writable",
                severity=Severity.CRITICAL,
                description=f"{path} has mode {_mode_str(st.st_mode)}; any local user can modify it.",
                recommendation=f"Remove world-write: chmod o-w {path}.",
                target=target, evidence=oct(actual)))
    return findings


def _check_ssh_keys(target: str) -> list[Finding]:
    findings = []
    ssh_dir = os.path.expanduser("~/.ssh")
    if not os.path.isdir(ssh_dir):
        return findings
    for name in os.listdir(ssh_dir):
        if name.endswith(".pub") or name in ("known_hosts", "config", "authorized_keys"):
            continue
        path = os.path.join(ssh_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        actual = stat.S_IMODE(st.st_mode)
        if actual & (stat.S_IRWXG | stat.S_IRWXO):
            findings.append(Finding(
                category="permissions",
                title=f"SSH private key has loose permissions: {name}",
                severity=Severity.HIGH,
                description=f"{path} has mode {_mode_str(st.st_mode)}, readable/writable beyond the owner.",
                recommendation=f"chmod 600 {path}",
                target=target, evidence=oct(actual)))
    return findings


def _check_world_writable(target: str, max_files: int = 5000) -> list[Finding]:
    findings = []
    hits = []
    scanned = 0
    for base in WORLD_WRITABLE_SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            # skip obviously irrelevant / huge trees
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for name in files:
                scanned += 1
                if scanned > max_files:
                    break
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if stat.S_IMODE(st.st_mode) & stat.S_IWOTH:
                    hits.append(path)
            if scanned > max_files:
                break
        if scanned > max_files:
            break

    if hits:
        findings.append(Finding(
            category="permissions",
            title=f"{len(hits)} world-writable file(s) found in system directories",
            severity=Severity.MEDIUM,
            description=("Files writable by any local user were found under " +
                          ", ".join(WORLD_WRITABLE_SCAN_DIRS) + "."),
            recommendation="Review and remove world-write bit (chmod o-w) unless explicitly required.",
            target=target,
            evidence="; ".join(hits[:10]) + (" ..." if len(hits) > 10 else ""),
        ))
    return findings


def check_permissions(target: str = "localhost") -> list[Finding]:
    if platform.system() == "Windows":
        return [Finding(
            category="permissions", title="Permission check skipped on Windows",
            severity=Severity.INFO,
            description="POSIX-style permission checks are not applicable on Windows.",
            recommendation="Use icacls / Get-Acl based checks for Windows ACL auditing (not yet implemented).",
            target=target)]

    findings = []
    findings += _check_sensitive_files(target)
    findings += _check_ssh_keys(target)
    findings += _check_world_writable(target)

    if not findings:
        findings.append(Finding(
            category="permissions", title="No permission issues found",
            severity=Severity.INFO,
            description="Sensitive files, SSH keys, and scanned directories showed no obvious permission problems.",
            recommendation="No action needed.", target=target))
    return findings
