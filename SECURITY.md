# Security Policy

## Scope and intended use

SecAudit is a defensive auditing tool intended for use against systems and
networks you own or are explicitly authorized to test (your own machines,
lab environments, or environments covered by a signed pentest/bug-bounty
authorization). The `--remote` scanning functionality performs active TCP
connection attempts; running it against third-party infrastructure without
authorization may be illegal in your jurisdiction.

## Reporting a vulnerability in SecAudit itself

If you find a security issue in this tool (e.g. a flaw that could let a
scanned target compromise the machine running SecAudit), please open a
private security advisory on GitHub rather than a public issue, or email
the maintainer directly. Include:

- A description of the issue and its impact
- Steps to reproduce
- Affected version/commit

Please allow a reasonable window to address the issue before public
disclosure.

## Supported versions

| Version | Supported |
|---------|-----------|
| main    | yes       |

This is a personal/portfolio project without a formal LTS policy; the
`main` branch is the only supported line.
