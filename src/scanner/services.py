"""
Lightweight service enumeration: for a set of open ports, try to grab
a banner or send a minimal protocol probe so the report can say "this
is nginx 1.18" rather than just "port 80 is open". Best-effort only -
this is not a fingerprinting engine like nmap -sV, just a small
enhancement layer used by the network checks.
"""

from __future__ import annotations
import socket
import subprocess
import platform
from typing import Optional

from ..models import Finding, Severity

# Services that are commonly unnecessary on a general-purpose server
# and worth flagging for review if active.
UNNECESSARY_SERVICE_HINTS = [
    "telnet", "rsh", "rlogin", "tftp", "xinetd", "avahi-daemon",
    "cups", "nfs-server", "rpcbind",
]


def list_running_services_linux() -> list[str]:
    try:
        out = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return []
        names = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if parts:
                names.append(parts[0].removesuffix(".service"))
        return names
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def check_running_services(target: str = "localhost") -> list[Finding]:
    if platform.system() != "Linux":
        return [Finding(
            category="services", title="Running-services enumeration skipped",
            severity=Severity.INFO,
            description=f"systemctl-based service enumeration is Linux-specific; host is {platform.system()}.",
            recommendation="Use platform-native tooling (services.msc, launchctl) to review running services.",
            target=target)]

    services = list_running_services_linux()
    if not services:
        return [Finding(
            category="services", title="Could not enumerate running services",
            severity=Severity.INFO,
            description="systemctl returned no data (may require systemd or elevated privileges).",
            recommendation="Run with sufficient privileges on a systemd-based host.",
            target=target)]

    findings = []
    for svc in services:
        for hint in UNNECESSARY_SERVICE_HINTS:
            if hint in svc.lower():
                findings.append(Finding(
                    category="services",
                    title=f"Potentially unnecessary service running: {svc}",
                    severity=Severity.MEDIUM,
                    description=f"'{svc}' is active and matches a commonly-unneeded-service pattern ('{hint}').",
                    recommendation=f"Disable {svc} if not required: `sudo systemctl disable --now {svc}`.",
                    target=target))
                break

    if not findings:
        findings.append(Finding(
            category="services", title=f"{len(services)} service(s) running, none flagged",
            severity=Severity.INFO,
            description="No running services matched the unnecessary-service watchlist.",
            recommendation="No action needed.", target=target,
            evidence=", ".join(sorted(services)[:20])))
    return findings


def grab_banner(host: str, port: int, timeout: float = 1.5) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080, 8000, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            data = s.recv(256)
            if data:
                return data.decode(errors="replace").strip().split("\n")[0][:200]
    except OSError:
        return None
    return None


def enumerate_services(host: str, open_ports: list[int]) -> list[Finding]:
    """Grab banners for a list of already-known-open ports and flag
    anything that leaks a version string (info disclosure) or matches
    a known end-of-life / high-risk product."""
    findings = []
    for port in open_ports:
        banner = grab_banner(host, port)
        if not banner:
            continue
        findings.append(Finding(
            category="services",
            title=f"Service banner on {host}:{port}",
            severity=Severity.LOW,
            description=f"Service on port {port} responded with a banner that may disclose version info.",
            recommendation="Suppress or minimize version banners where possible to reduce recon value for attackers.",
            target=host,
            evidence=banner,
        ))

        lowered = banner.lower()
        eol_hints = ["iis/6.0", "apache/2.2", "openssh_5", "openssh_6", "vsftpd 2.3.4"]
        for hint in eol_hints:
            if hint in lowered:
                findings.append(Finding(
                    category="services",
                    title=f"Potentially outdated/EOL service on port {port}",
                    severity=Severity.HIGH,
                    description=f"Banner matched known-old signature '{hint}': {banner}",
                    recommendation="Upgrade this service to a current, supported version.",
                    target=host,
                    evidence=banner,
                ))
    return findings
