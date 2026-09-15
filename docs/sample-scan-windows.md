# Sample Scan: Windows Workstation (Local Audit)

This is a real `--local` scan run against a Windows 10/11 machine, included
here as an example of SecAudit's output and to document a couple of design
decisions surfaced by running it against a real target.

```
python main.py --local --output json,html,csv --outdir reports
```

**Target:** localhost (Windows)
**Date:** 2026-08-18
**Modules run:** ports, services, firewall, permissions, processes, password\_policy, configuration

> \\\*\\\*Note:\\\*\\\* Private/link-local IP addresses in this report have been
> tokenized (e.g. `192.168.1.XXX`) since this is a real scan of a home
> network shared publicly. `0.0.0.0` and `:::` are left as-is since
> they're meaningful values (a service bound to \\\*all\\\* interfaces),
> not identifying addresses.

## Result

|Metric|Value|
|-|-|
|**Security Score**|0 / 100|
|**Grade**|F|
|Critical|4|
|High|4|
|Medium|0|
|Low|0|
|Info|6|

## Findings

### Critical

|ID|Finding|Detail|
|-|-|-|
|CRIT-001|MS-RPC listening on port 135|`:::135` (svchost.exe)|
|CRIT-003|SMB listening on port 445|`0.0.0.0:445` (System)|
|CRIT-005|MS-RPC listening on port 135|`0.0.0.0:135` (svchost.exe)|
|CRIT-006|SMB listening on port 445|`:::445` (System)|

### High

|ID|Finding|Detail|
|-|-|-|
|HIGH-002|NetBIOS-SSN/SMB on port 139|`169.254.XXX.XXX:139`|
|HIGH-004|NetBIOS-SSN/SMB on port 139|`192.168.56.XXX:139`|
|HIGH-007|NetBIOS-SSN/SMB on port 139|`192.168.1.XXX:139`|
|HIGH-008|NetBIOS-SSN/SMB on port 139|`169.254.YYY.YYY:139`|

### Info

|ID|Finding|
|-|-|
|INFO-009|Running-services enumeration skipped (Linux-specific check)|
|INFO-010|Windows Firewall profiles enabled|
|INFO-011|Permission check skipped on Windows|
|INFO-012|No suspicious processes flagged|
|INFO-013|Password policy check skipped (Linux-specific check)|
|INFO-014|Configuration check limited on this platform|

## Interpretation

SMB (445), NetBIOS (139), and MS-RPC (135) are enabled by default on
Windows for file/printer sharing and are bound to all interfaces
(`0.0.0.0` / `:::`), not just localhost. This isn't evidence of
compromise but it is real attack
surface: these ports are reachable from whatever network the machine is
connected to unless the Windows network profile is set to **Private**
and/or a host firewall rule restricts them.

Verified this machine's network profile:

```powershell
Get-NetConnectionProfile
```

## Two things this run surfaced about the tool itself

1. **Severity model is workstation-naive.** SecAudit's current severity
table treats SMB/RPC exposure as CRITICAL regardless of host role.
That's the right posture for a server, but arguably too aggressive
for a default Windows desktop on a private home network. A future
improvement: add a `--host-role server|workstation` flag that adjusts
severity weight for these specific services.
2. **Duplicate findings across interface families.** The port scanner
reports each dual-stack listener twice — once for its IPv4 binding
(`0.0.0.0`) and once for IPv6-any (`:::`) — inflating the finding
count for what is really a single exposure (see CRIT-003/CRIT-006).
Planned fix: dedupe by port when a service is bound to "all
interfaces" on both address families.

## Windows platform coverage

Several modules (`firewall.py`, `permissions.py`, `config\\\_checks.py`)
were written against Linux tooling (`ufw`/`iptables`, `/etc/shadow`,
`sshd\\\_config`) and correctly report "not applicable" on Windows rather
than silently failing. Full Windows parity (ACL-based permission checks
via `icacls`/`Get-Acl`, `secpol.msc`-based password policy) is on the
roadmap.

