# Changelog

Notes on what's changed, roughly in the order I made the changes.

## Sept 2026 - bug fixes from actually using the tool

Running SecAudit against my own machines (Linux box + a Windows workstation) turned up a few real problems the unit tests didn't catch:

- Finding IDs (`CRIT-001`, `LOW-003`, etc.) were sharing one global counter across every severity, so a report's only CRITICAL finding could end up numbered `CRIT-004` just because some unrelated INFO findings got created first. Each severity now numbers on its own.
- A service bound to all network interfaces was getting reported twice - once for its IPv4 binding (`0.0.0.0`) and once for IPv6 (`:::`) - double-counting what's really a single exposure. Found this running against my Windows machine (see `docs/sample-scan-windows.md`). Fixed with a dedup step + regression tests.
- The local ports check didn't report anything when nothing matched a watchlist, which was inconsistent with every other check module always saying *something*. Fixed.
- The Terraform lab's README referenced a `terraform.tfvars.example` file that didn't actually exist in the repo. Added it.
- The Terraform module's comment claimed it created an over-permissive IAM user, but that resource was never actually added. Fixed.
- Fixed a wrong GitHub username in the README's clone instructions.

Added tests for all of the above.

## Aug 2026 - first working version

- Local system audit: ports, services, firewall, permissions, processes, password policy, SSH config
- Remote network audit: TCP connect scan + basic banner grabbing
- 0-100 scoring engine with a letter grade
- Text, JSON, CSV, and HTML report output
- `--fail-under` / `--fail-on` flags so it can gate a CI pipeline
- GitHub Actions workflow: runs the tests + a self-audit on every push
- Terraform module for a deliberately misconfigured AWS lab target
- First pytest tests for the scoring engine and port scanning
