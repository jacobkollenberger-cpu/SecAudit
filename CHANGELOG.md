# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-08-13
### Added
- Initial release: local system audit (ports, services, firewall,
  permissions, processes, password policy, sshd config) and remote
  network audit (TCP connect scan + banner grabbing).
- 0-100 security scoring engine with letter grade.
- Text, JSON, CSV, and HTML report writers.
- CLI with `--fail-under` / `--fail-on` flags for CI/CD gating.
- GitHub Actions workflow: unit tests + scheduled self-audit.
- Terraform module for a deliberately vulnerable AWS EC2/S3 lab target.
- pytest unit tests for scoring engine and port-scanning logic.
