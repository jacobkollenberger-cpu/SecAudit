# SecAudit

A Python CLI that audits a local machine or a remote host's network exposure, flags common security misconfigurations, scores overall risk, and spits out a report you can actually read (or hand to someone else).

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

## Why I built this

I wanted a project that actually looked like what a SOC/security analyst deals with day to day, not just another script that pings a few ports and calls it done. So this checks the stuff that actually shows up in real hardening checklists: firewall status, file permissions, SSH config, password policy, running services, and suspicious processes on the local box, plus a basic network scan for auditing a remote target (like a lab VM).

It also gave me an excuse to practice things I don't get much hands-on time with otherwise: writing pytest tests, wiring up a GitHub Actions workflow that runs the tool against itself on every push, and standing up a deliberately-vulnerable AWS target with Terraform so I'd have something real to point the network-scanning side at.

## What it checks

**On the local machine**
- Listening ports and what's bound to them, flagged if they're something risky (FTP/Telnet/SMB/RDP/etc.)
- Running services, checked against a small "probably shouldn't be running" list
- Whether a host firewall is actually active (ufw / firewalld / nftables / iptables / pf / Windows Firewall)
- Password policy (`/etc/login.defs`, whether pam_pwquality is even configured)
- SSH daemon config (root login allowed? empty passwords allowed? password auth instead of keys?)
- Permissions on sensitive files (`/etc/shadow`, `/etc/passwd`, SSH private keys, anything world-writable)
- A basic "does this look like a sketchy process" heuristic

**Against a remote target**
- Multi-threaded TCP connect scan
- Same dangerous-port flagging as the local check, but weighted higher since it's reachable over the network
- Basic banner grabbing to catch obviously outdated service versions

**Scoring**
- Starts at 100, subtracts points per finding based on severity, floors at 0. Nothing fancy - see `src/scoring/risk.py` if you want the exact numbers.

**Reports**
- Plain text (console or `.txt`), JSON, CSV, or a dark-mode HTML report

**CI stuff**
- `--fail-under N` and `--fail-on SEVERITY` so it can gate a CI pipeline
- A GitHub Actions workflow that runs the test suite and audits the runner itself, on every push and nightly
- A Terraform module that spins up an intentionally misconfigured AWS EC2 instance + S3 bucket so the `--remote` path has something real to scan

## Setup

```bash
git clone https://github.com/jacobkollenberger-cpu/SecAudit.git
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

# Run only specific local checks
python main.py --local --modules firewall,permissions,ports

# Audit a remote host's exposed ports/services
python main.py --remote 192.168.1.10 --ports 21,22,23,80,443,445,3389

# CI gate: fail the build if score < 70 or any CRITICAL finding exists
python main.py --local --fail-under 70 --fail-on CRITICAL
```

`python main.py --help` for the full flag list.

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
├── terraform/aws-lab/        # deliberately vulnerable AWS target
├── .github/workflows/security.yml   # CI: tests + self-audit
├── SECURITY.md
└── CHANGELOG.md
```

## How scoring works

Every finding has a severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), each with a fixed point deduction (25/15/7/3/0). Score starts at 100, every non-INFO finding subtracts its weight, floored at 0. Full breakdown in `src/scoring/risk.py`.

## Things I've fixed after actually using it

Running this against my own machines turned up a few real bugs that unit tests alone didn't catch:

- **Finding IDs were numbered wrong.** All findings shared a single counter regardless of severity, so a report's only CRITICAL finding could show up labeled `CRIT-004` just because some INFO findings happened to get created first in that run. Each severity now numbers independently.
- **Duplicate findings on dual-stack hosts.** Running this against my Windows machine, SMB and RPC each got reported twice - once for the IPv4-any binding (`0.0.0.0`), once for IPv6-any (`:::`) - which is really one exposure, not two. See `docs/sample-scan-windows.md` for the real scan output and how it's fixed now.
- The local ports check didn't report anything when nothing matched a watchlist, unlike every other module, which was just inconsistent. Fixed.

## What's next

- Live CVE lookups (NVD API) for banner-matched service versions
- Slack/email alerting when findings above a threshold show up
- A `--host-role server|workstation` flag, since the severity table currently treats things like SMB exposure as CRITICAL regardless of whether it's a server or just someone's laptop on a home network (see the Windows sample scan doc for why that came up)
- Windows-native permission/password-policy checks (`icacls`/`Get-Acl`, `secpol.msc`) instead of skipping those checks on Windows entirely

## Disclaimer

Only run `--remote` against hosts you own or have explicit permission to test. Scanning something you don't own can be illegal depending on where you are (in the US, this falls under the Computer Fraud and Abuse Act) and is against basically every cloud provider's terms of service.

## License

MIT - see `LICENSE`.
