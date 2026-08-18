# SecAudit

A Python CLI that audits a local system or a remote host's network exposure,
flags common security misconfigurations, scores overall risk, and produces
human-readable and machine-readable reports.

```
SECURITY AUDIT REPORT
========================================
Target: localhost
Date:   2026-08-13 02:11:04 UTC
Modules run: ports, services, firewall, permissions, processes, password_policy, configuration

Security Score: 72/100  (Grade: C)

CRITICAL
--------
[CRIT-001] No active firewall rules detected
  Target: localhost
  iptables is present but has no rules beyond default chain policies...
  Recommendation: Enable a host firewall (ufw/firewalld) and define default-deny inbound rules.
...
SUMMARY
-------
Critical: 1
High:     1
Medium:   2
Low:      1
Info:     4
```

## Why this exists

Built as a hands-on security engineering project: it exercises networking
fundamentals (ports/services/protocols), system hardening (firewalls, file
permissions, password policy, SSH config), scripting/automation, and
DevSecOps practices (CI, exit codes, scheduled scans), then ties it all
together against a real, disposable AWS lab environment provisioned with
Terraform.

## Features

**Local system checks**
- Listening ports + what's bound to them, flagged by risk (FTP/Telnet/SMB/RDP/etc.)
- Running services, flagged against a common "unnecessary service" watchlist
- Host firewall status (ufw / firewalld / nftables / iptables / pf / Windows Firewall)
- Password policy (`/etc/login.defs`, PAM pwquality presence)
- SSH daemon configuration (root login, empty passwords, password auth)
- Sensitive file permissions (`/etc/shadow`, `/etc/passwd`, SSH private keys,
  world-writable files)
- Heuristic suspicious-process detection

**Network checks**
- Multi-threaded TCP connect scan of a target host
- Dangerous-port flagging (FTP, Telnet, SMB, RDP, databases, etc.) with
  higher severity when exposed broadly
- Lightweight banner grabbing / service enumeration
- EOL/known-old service signature matching

**Scoring**
- 0–100 Security Score with letter grade, derived from finding severities
  (see `src/scoring/risk.py` for the exact, documented formula)

**Reporting**
- Text (console + `.txt`), JSON, CSV, and a styled HTML report

**Automation / DevSecOps**
- `--fail-under N` and `--fail-on SEVERITY` flags for CI/CD gating
- GitHub Actions workflow: runs unit tests, self-audits the runner on
  every push and nightly on a schedule, uploads reports as artifacts
- Terraform module that stands up a deliberately vulnerable AWS
  EC2 + S3 lab target to demonstrate the network-audit path end-to-end

## Installation

```bash
git clone https://github.com/<you>/SecAudit.git
cd SecAudit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Full local audit, printed to console
python main.py --local

# Local audit, write JSON + HTML reports
python main.py --local --output json,html --outdir reports/

# Run only specific local modules
python main.py --local --modules firewall,permissions,ports

# Audit a remote host's exposed ports/services
python main.py --remote 192.168.1.10 --ports 21,22,23,80,443,445,3389

# CI/CD gate: fail the build if score < 70 or any CRITICAL finding exists
python main.py --local --fail-under 70 --fail-on CRITICAL
```

Run `python main.py --help` for the full flag list.

## Project layout

```
SecAudit/
├── main.py                  # CLI entry point
├── src/
│   ├── models.py             # Finding / AuditReport data model
│   ├── scanner/
│   │   ├── ports.py           # local listening ports + remote TCP scan
│   │   ├── services.py        # running services + banner grabbing
│   │   ├── firewall.py        # firewall status (multi-platform)
│   │   ├── permissions.py     # sensitive file / SSH key permissions
│   │   ├── processes.py       # suspicious process heuristics
│   │   ├── config_checks.py   # password policy + sshd_config checks
│   │   └── reference_data.py  # dangerous-port table, watchlists
│   ├── scoring/
│   │   └── risk.py            # 0-100 score + letter grade
│   └── reporting/
│       ├── text_report.py
│       ├── json_report.py
│       ├── csv_report.py
│       └── html_report.py
├── tests/                    # pytest unit tests
├── terraform/aws-lab/        # deliberately vulnerable AWS target (Phase 5)
├── .github/workflows/security.yml   # CI: tests + self-audit
├── SECURITY.md
└── CHANGELOG.md
```

## How scoring works

Every finding has a severity (`CRITICAL/HIGH/MEDIUM/LOW/INFO`), each with a
fixed point deduction (25/15/7/3/0). The score starts at 100 and every
non-INFO finding subtracts its weight, floored at 0. See
`src/scoring/risk.py` - it's short and deliberately easy to explain.

## Roadmap

- [x] Phase 1: CLI, port/service detection, config checks, JSON output
- [x] Phase 2: severity ratings, scoring, remediation text
- [ ] Phase 2.5: live CVE lookups (NVD API) for banner-matched service versions
- [x] Phase 3: exit codes for CI/CD; GitHub Actions scheduling
- [ ] Phase 3.5: Slack/email alerting on findings above a threshold
- [x] Phase 4: GitHub Actions self-audit on every push
- [x] Phase 5: Terraform-provisioned vulnerable AWS lab target

## Disclaimer

Only run the `--remote` network-scanning functionality against hosts you
own or have explicit written authorization to test. Unauthorized port
scanning may violate laws (e.g. the U.S. Computer Fraud and Abuse Act) or
your ISP/cloud provider's acceptable use policy.

## License

MIT - see `LICENSE`.
