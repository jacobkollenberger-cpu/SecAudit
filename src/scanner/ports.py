"""
Port scanning.

Two distinct capabilities live here:

1. local_listening_ports()  -> what's listening on THIS machine, read
   from the OS (via psutil if available, falling back to `ss`/`netstat`).
   This powers the "system security checks" side of the tool and never
   touches the network.

2. scan_remote_host()       -> a plain TCP-connect scan against a
   caller-supplied host/port list. This powers the "network checks"
   side of the tool (auditing a target you specify, e.g. a lab VM).

Both return Finding objects, using reference_data.py to decide severity.
"""

from __future__ import annotations
import socket
import subprocess
import concurrent.futures
from typing import Iterable, Optional

from ..models import Finding, Severity
from . import reference_data as ref

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


# --------------------------------------------------------------------
# Local listening ports (system check)
# --------------------------------------------------------------------

def _local_ports_psutil():
    rows = []
    for c in psutil.net_connections(kind="inet"):
        if c.status == psutil.CONN_LISTEN and c.laddr:
            proc = None
            if c.pid:
                try:
                    proc = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = None
            rows.append({
                "address": c.laddr.ip,
                "port": c.laddr.port,
                "pid": c.pid,
                "process": proc,
            })
    return rows


def _local_ports_ss():
    """Fallback for systems without psutil: parse `ss -tulnp` / `netstat`."""
    rows = []
    for cmd in (["ss", "-tulnp"], ["netstat", "-tulnp"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if out.returncode != 0:
            continue
        for line in out.stdout.splitlines():
            parts = line.split()
            if not parts or parts[0].lower() not in ("tcp", "tcp6", "udp", "udp6"):
                continue
            local = parts[3] if cmd[0] == "ss" else parts[3]
            if ":" not in local:
                continue
            addr, _, port = local.rpartition(":")
            if not port.isdigit():
                continue
            rows.append({"address": addr.strip("[]") or "0.0.0.0",
                          "port": int(port), "pid": None, "process": None})
        if rows:
            break
    return rows


def local_listening_ports() -> list[dict]:
    """Best-effort list of {address, port, pid, process} for this host."""
    if HAVE_PSUTIL:
        try:
            return _local_ports_psutil()
        except Exception:
            pass
    return _local_ports_ss()


ANY_ADDRESSES = ("0.0.0.0", "::", "*")


def _dedupe_dual_stack(rows: list[dict]) -> list[dict]:
    """A service bound to 'all interfaces' shows up twice on dual-stack
    hosts - once for its IPv4-any binding (0.0.0.0) and once for
    IPv6-any (:::). That's really one exposure, not two, so collapse
    those into a single row per port before turning them into findings.
    (Found this the hard way running against my own Windows machine -
    SMB/RPC were both getting reported twice. See docs/sample-scan-windows.md.)
    """
    by_port: dict = {}
    for row in rows:
        by_port.setdefault(row["port"], []).append(row)

    deduped = []
    for port, group in by_port.items():
        any_rows = [r for r in group if r["address"] in ANY_ADDRESSES]
        other_rows = [r for r in group if r["address"] not in ANY_ADDRESSES]

        if len(any_rows) >= 2:
            rep = dict(any_rows[0])
            rep["address"] = "0.0.0.0" if any(r["address"] == "0.0.0.0" for r in any_rows) else any_rows[0]["address"]
            deduped.append(rep)
        else:
            deduped.extend(any_rows)

        deduped.extend(other_rows)

    return deduped


def check_local_ports(target: str = "localhost") -> list[Finding]:
    findings = []
    rows = local_listening_ports()

    if not rows:
        findings.append(Finding(
            category="ports",
            title="Unable to enumerate listening ports",
            severity=Severity.INFO,
            description=("Could not read the local listening-socket table. "
                          "This usually means neither psutil nor ss/netstat "
                          "were usable (permissions or missing tools)."),
            recommendation="Run with sufficient privileges, or install psutil.",
            target=target,
        ))
        return findings

    rows = _dedupe_dual_stack(rows)

    for row in rows:
        port, addr = row["port"], row["address"]
        exposed = addr in ("0.0.0.0", "::", "*")
        svc_name = ref.COMMON_SERVICE_NAMES.get(port, row["process"] or "unknown")
        evidence = f"{addr}:{port} (pid={row['pid']}, proc={row['process']})"

        if port in ref.DANGEROUS_PORTS:
            name, base_sev, exposed_sev = ref.DANGEROUS_PORTS[port]
            sev = exposed_sev if exposed else base_sev
            findings.append(Finding(
                category="ports",
                title=f"{name} service listening on port {port}",
                severity=sev,
                description=(f"{name} was found listening on {addr}:{port}. "
                              f"This service is commonly targeted or "
                              f"transmits data insecurely."),
                recommendation=(f"Disable {name} if unused, or restrict it to "
                                 f"localhost/trusted networks and require "
                                 f"strong authentication and encryption."),
                target=target,
                evidence=evidence,
            ))
        elif port in ref.SENSITIVE_PORTS:
            name, base_sev, exposed_sev = ref.SENSITIVE_PORTS[port]
            sev = exposed_sev if exposed else base_sev
            if sev != Severity.INFO:
                findings.append(Finding(
                    category="ports",
                    title=f"{name} exposed on {addr}:{port}",
                    severity=sev,
                    description=(f"{name} is listening on {'all interfaces' if exposed else addr} "
                                 f"port {port}."),
                    recommendation=(f"Restrict {name} to trusted source IPs "
                                     f"(firewall rule / bind address), and confirm "
                                     f"strong authentication is enforced."),
                    target=target,
                    evidence=evidence,
                ))

    if not findings:
        findings.append(Finding(
            category="ports",
            title=f"{len(rows)} listening port(s) found, none flagged",
            severity=Severity.INFO,
            description="No listening ports matched the dangerous or sensitive port watchlists.",
            recommendation="No action needed.",
            target=target,
        ))

    return findings


# --------------------------------------------------------------------
# Remote scanning (network check)
# --------------------------------------------------------------------

DEFAULT_PORT_LIST = sorted(set(ref.DANGEROUS_PORTS) | set(ref.SENSITIVE_PORTS) |
                            {53, 110, 143, 389, 993, 995, 8080, 8443})


def _connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def scan_remote_host(host: str, ports: Optional[Iterable[int]] = None,
                      timeout: float = 1.0, max_workers: int = 50) -> list[dict]:
    """TCP-connect scan. Returns list of {port, open} for ports checked."""
    port_list = list(ports) if ports else DEFAULT_PORT_LIST
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_connect, host, p, timeout): p for p in port_list}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            results.append({"port": p, "open": fut.result()})
    return sorted(results, key=lambda r: r["port"])


def check_remote_host(host: str, ports: Optional[Iterable[int]] = None,
                       timeout: float = 1.0, results: Optional[list[dict]] = None) -> list[Finding]:
    findings = []
    if results is None:
        results = scan_remote_host(host, ports, timeout)
    open_ports = [r["port"] for r in results if r["open"]]

    if not open_ports:
        findings.append(Finding(
            category="network",
            title="No scanned ports open",
            severity=Severity.INFO,
            description=f"None of the {len(results)} ports checked on {host} responded as open.",
            recommendation="No action needed for this scan set.",
            target=host,
        ))
        return findings

    for port in open_ports:
        if port in ref.DANGEROUS_PORTS:
            name, _, exposed_sev = ref.DANGEROUS_PORTS[port]
            findings.append(Finding(
                category="network",
                title=f"{name} exposed to network on port {port}",
                severity=exposed_sev,
                description=f"{host}:{port} ({name}) accepted a TCP connection from the scanning host.",
                recommendation=(f"Firewall {name} off from untrusted networks; disable it "
                                 f"entirely if it isn't required."),
                target=host,
                evidence=f"TCP connect succeeded on {host}:{port}",
            ))
        elif port in ref.SENSITIVE_PORTS:
            name, _, exposed_sev = ref.SENSITIVE_PORTS[port]
            findings.append(Finding(
                category="network",
                title=f"{name} reachable on port {port}",
                severity=exposed_sev,
                description=f"{host}:{port} ({name}) is reachable from the network.",
                recommendation=(f"Confirm {name} exposure is intentional; restrict via "
                                 f"security group / firewall rules and enforce strong auth."),
                target=host,
                evidence=f"TCP connect succeeded on {host}:{port}",
            ))
        else:
            svc = ref.COMMON_SERVICE_NAMES.get(port, "unknown service")
            findings.append(Finding(
                category="network",
                title=f"Port {port} open ({svc})",
                severity=Severity.LOW,
                description=f"{host}:{port} is open and accepting connections.",
                recommendation="Confirm this service is intentionally exposed.",
                target=host,
                evidence=f"TCP connect succeeded on {host}:{port}",
            ))

    return findings
