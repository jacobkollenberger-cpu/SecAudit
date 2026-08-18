#!/usr/bin/env python3
"""
SecAudit - a security auditing CLI for local systems and remote hosts.

Examples:
    # Full local system audit, human-readable report to stdout
    python main.py --local

    # Local audit + write JSON/HTML reports
    python main.py --local --output json,html --outdir reports/

    # Audit a remote host's network exposure only
    python main.py --remote 192.168.1.10 --ports 21,22,23,80,443,3389

    # CI/CD usage: fail the build if score < 70 or any CRITICAL finding
    python main.py --local --fail-under 70 --fail-on CRITICAL
"""

from __future__ import annotations
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.models import AuditReport, Severity
from src.scoring.risk import calculate_score, grade_for_score, severity_counts
from src.reporting.text_report import render_text, write_text
from src.reporting.json_report import write_json
from src.reporting.csv_report import write_csv
from src.reporting.html_report import write_html

from src.scanner import ports, services, firewall, permissions, processes, config_checks


LOCAL_MODULES = [
    ("ports", lambda t: ports.check_local_ports(t)),
    ("services", lambda t: services.check_running_services(t)),
    ("firewall", lambda t: firewall.check_firewall(t)),
    ("permissions", lambda t: permissions.check_permissions(t)),
    ("processes", lambda t: processes.check_processes(t)),
    ("password_policy", lambda t: config_checks.check_password_policy(t)),
    ("configuration", lambda t: config_checks.check_configuration(t)),
]


def run_local_audit(target: str, selected: list[str] | None) -> AuditReport:
    started = AuditReport.now()
    all_findings = []
    modules_run = []
    for name, func in LOCAL_MODULES:
        if selected and name not in selected:
            continue
        try:
            all_findings.extend(func(target))
            modules_run.append(name)
        except Exception as e:
            print(f"[!] Module '{name}' failed: {e}", file=sys.stderr)

    finished = AuditReport.now()
    score = calculate_score(all_findings)
    report = AuditReport(target=target, findings=all_findings, started_at=started,
                          finished_at=finished, score=score, grade=grade_for_score(score),
                          modules_run=modules_run)
    return report


def run_remote_audit(host: str, port_list: list[int] | None, timeout: float) -> AuditReport:
    started = AuditReport.now()
    scan_results = ports.scan_remote_host(host, port_list, timeout)
    open_ports = [r["port"] for r in scan_results if r["open"]]
    findings = ports.check_remote_host(host, port_list, timeout, results=scan_results)

    try:
        findings.extend(services.enumerate_services(host, open_ports))
    except Exception as e:
        print(f"[!] Service enumeration failed: {e}", file=sys.stderr)

    finished = AuditReport.now()
    score = calculate_score(findings)
    return AuditReport(target=host, findings=findings, started_at=started, finished_at=finished,
                        score=score, grade=grade_for_score(score), modules_run=["network", "services"])


def write_reports(report: AuditReport, formats: list[str], outdir: str, basename: str):
    os.makedirs(outdir, exist_ok=True)
    written = []
    if "json" in formats:
        p = os.path.join(outdir, f"{basename}.json")
        write_json(report, p); written.append(p)
    if "csv" in formats:
        p = os.path.join(outdir, f"{basename}.csv")
        write_csv(report, p); written.append(p)
    if "html" in formats:
        p = os.path.join(outdir, f"{basename}.html")
        write_html(report, p); written.append(p)
    if "txt" in formats:
        p = os.path.join(outdir, f"{basename}.txt")
        write_text(report, p); written.append(p)
    return written


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secaudit", description="SecAudit - security audit CLI")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true", help="Audit the local system.")
    mode.add_argument("--remote", metavar="HOST", help="Audit a remote host's network exposure.")

    p.add_argument("--modules", help="Comma-separated local module subset "
                    "(ports,services,firewall,permissions,processes,password_policy,configuration).")
    p.add_argument("--ports", help="Comma-separated port list for --remote (default: common port set).")
    p.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds for --remote.")

    p.add_argument("--output", default="txt", help="Comma-separated formats: txt,json,csv,html (default: txt).")
    p.add_argument("--outdir", default="reports", help="Directory to write report files (default: reports/).")
    p.add_argument("--basename", default="secaudit_report", help="Base filename for written reports.")
    p.add_argument("--quiet", action="store_true", help="Suppress the console text report (still writes files).")

    p.add_argument("--fail-under", type=int, default=None, metavar="N",
                    help="Exit non-zero if the security score is below N (for CI/CD).")
    p.add_argument("--fail-on", default=None, metavar="SEVERITY",
                    help="Exit non-zero if any finding at or above this severity is present "
                         "(CRITICAL,HIGH,MEDIUM,LOW).")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    formats = [f.strip().lower() for f in args.output.split(",") if f.strip()]

    if args.local:
        selected = [m.strip() for m in args.modules.split(",")] if args.modules else None
        report = run_local_audit("localhost", selected)
    else:
        port_list = [int(p) for p in args.ports.split(",")] if args.ports else None
        report = run_remote_audit(args.remote, port_list, args.timeout)

    if not args.quiet:
        print(render_text(report))

    written = write_reports(report, formats, args.outdir, args.basename)
    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}", file=sys.stderr)

    exit_code = 0
    if args.fail_under is not None and report.score < args.fail_under:
        print(f"[!] Score {report.score} is below threshold {args.fail_under}", file=sys.stderr)
        exit_code = 1
    if args.fail_on:
        threshold = Severity(args.fail_on.upper())
        if any(f.severity.rank <= threshold.rank for f in report.findings):
            print(f"[!] Found finding(s) at or above severity {threshold.value}", file=sys.stderr)
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
