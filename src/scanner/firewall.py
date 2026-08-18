"""
Firewall status check. Tries, in order of likelihood, ufw -> firewalld
-> nftables -> iptables on Linux, pfctl on macOS, and netsh on Windows.
Reports CRITICAL if nothing indicates an active firewall was found.
"""

from __future__ import annotations
import platform
import shutil
import subprocess

from ..models import Finding, Severity


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout + p.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, ""


def _check_linux(target: str) -> list[Finding]:
    findings = []

    if shutil.which("ufw"):
        rc, out = _run(["ufw", "status"])
        if "Status: active" in out:
            return [Finding(
                category="firewall", title="UFW firewall active", severity=Severity.INFO,
                description="UFW reports status active.", recommendation="No action needed.",
                target=target, evidence=out.strip().splitlines()[0] if out else None)]
        elif "Status: inactive" in out:
            findings.append(Finding(
                category="firewall", title="UFW installed but inactive", severity=Severity.CRITICAL,
                description="UFW is installed but not currently enabled, leaving the host firewall disabled.",
                recommendation="Enable UFW: `sudo ufw enable` after reviewing rules.",
                target=target, evidence=out.strip()))
            return findings

    if shutil.which("firewall-cmd"):
        rc, out = _run(["firewall-cmd", "--state"])
        if "running" in out.lower():
            return [Finding(
                category="firewall", title="firewalld active", severity=Severity.INFO,
                description="firewalld reports state running.", recommendation="No action needed.",
                target=target)]
        else:
            findings.append(Finding(
                category="firewall", title="firewalld not running", severity=Severity.CRITICAL,
                description="firewalld is installed but not running.",
                recommendation="Start and enable firewalld: `sudo systemctl enable --now firewalld`.",
                target=target, evidence=out.strip()))
            return findings

    if shutil.which("nft"):
        rc, out = _run(["nft", "list", "ruleset"])
        if out.strip():
            return [Finding(
                category="firewall", title="nftables ruleset present", severity=Severity.INFO,
                description="nftables has an active, non-empty ruleset.",
                recommendation="No action needed; periodically review ruleset.",
                target=target)]

    if shutil.which("iptables"):
        rc, out = _run(["iptables", "-S"])
        rules = [l for l in out.splitlines() if l.strip() and not l.startswith("-P")]
        if rules:
            return [Finding(
                category="firewall", title="iptables rules present", severity=Severity.INFO,
                description=f"iptables has {len(rules)} active rule(s) beyond default policies.",
                recommendation="No action needed; periodically review rules.",
                target=target)]
        else:
            findings.append(Finding(
                category="firewall", title="No active firewall rules detected", severity=Severity.CRITICAL,
                description="iptables is present but has no rules beyond default chain policies, and no "
                             "ufw/firewalld/nftables ruleset was found either.",
                recommendation="Enable a host firewall (ufw/firewalld) and define default-deny inbound rules.",
                target=target))
            return findings

    findings.append(Finding(
        category="firewall", title="No firewall tooling detected", severity=Severity.CRITICAL,
        description="None of ufw, firewalld, nftables, or iptables were found/usable on this host.",
        recommendation="Install and enable a host firewall (ufw recommended for most Linux distros).",
        target=target))
    return findings


def _check_macos(target: str) -> list[Finding]:
    rc, out = _run(["/usr/sbin/pfctl", "-s", "info"])
    if "Status: Enabled" in out:
        return [Finding(category="firewall", title="pf firewall enabled", severity=Severity.INFO,
                         description="macOS pf reports Status: Enabled.", recommendation="No action needed.",
                         target=target)]
    rc2, out2 = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if "enabled" in out2.lower():
        return [Finding(category="firewall", title="Application firewall enabled", severity=Severity.INFO,
                         description="macOS Application Firewall is enabled.", recommendation="No action needed.",
                         target=target)]
    return [Finding(category="firewall", title="Firewall appears disabled", severity=Severity.CRITICAL,
                     description="Neither pf nor the Application Firewall reported an enabled state.",
                     recommendation="Enable the firewall in System Settings > Network > Firewall.",
                     target=target)]


def _check_windows(target: str) -> list[Finding]:
    rc, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if not out:
        return [Finding(category="firewall", title="Could not query Windows Firewall", severity=Severity.INFO,
                         description="netsh advfirewall query returned no output.",
                         recommendation="Manually verify firewall state via Windows Security.", target=target)]
    lowered = out.lower()
    if "state                                 off" in lowered or "state off" in lowered:
        return [Finding(category="firewall", title="A Windows Firewall profile is OFF", severity=Severity.CRITICAL,
                         description="At least one firewall profile (domain/private/public) is disabled.",
                         recommendation="Enable Windows Defender Firewall for all profiles.",
                         target=target, evidence=out.strip()[:500])]
    return [Finding(category="firewall", title="Windows Firewall profiles enabled", severity=Severity.INFO,
                     description="All queried profiles report State ON.", recommendation="No action needed.",
                     target=target)]


def check_firewall(target: str = "localhost") -> list[Finding]:
    system = platform.system()
    try:
        if system == "Linux":
            return _check_linux(target)
        elif system == "Darwin":
            return _check_macos(target)
        elif system == "Windows":
            return _check_windows(target)
    except Exception as e:
        return [Finding(category="firewall", title="Firewall check failed", severity=Severity.INFO,
                         description=f"Error while checking firewall status: {e}",
                         recommendation="Run the tool with elevated privileges and retry.", target=target)]

    return [Finding(category="firewall", title="Unsupported platform for firewall check", severity=Severity.INFO,
                     description=f"No firewall check implemented for platform '{system}'.",
                     recommendation="Manually verify firewall configuration.", target=target)]
