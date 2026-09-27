# Sample Scan: My Windows Machine

I ran a `--local` scan against my own Windows 10/11 machine and figured it was worth keeping as a real example, since it actually surfaced a couple of bugs in the tool itself.

```
python main.py --local --output json,html,csv --outdir reports
```

**Target:** localhost (Windows)
**Date:** 2026-08-18
**Modules run:** ports, services, firewall, permissions, processes, password_policy, configuration

> **Note:** I tokenized private/link-local IPs in this report (e.g. `192.168.1.XXX`) since it's a real scan of my home network and I'm posting it publicly. `0.0.0.0` and `:::` are left as-is since they just mean "bound to all interfaces," not an identifying address.

## Result

| Metric | Value |
|-|-|
| **Security Score** | 0 / 100 |
| **Grade** | F |
| Critical | 4 |
| High | 4 |
| Medium | 0 |
| Low | 0 |
| Info | 6 |

## Findings

### Critical

| ID | Finding | Detail |
|-|-|-|
| CRIT-001 | MS-RPC listening on port 135 | `:::135` (svchost.exe) |
| CRIT-002 | SMB listening on port 445 | `0.0.0.0:445` (System) |
| CRIT-003 | MS-RPC listening on port 135 | `0.0.0.0:135` (svchost.exe) |
| CRIT-004 | SMB listening on port 445 | `:::445` (System) |

### High

| ID | Finding | Detail |
|-|-|-|
| HIGH-001 | NetBIOS-SSN/SMB on port 139 | `169.254.XXX.XXX:139` |
| HIGH-002 | NetBIOS-SSN/SMB on port 139 | `192.168.56.XXX:139` |
| HIGH-003 | NetBIOS-SSN/SMB on port 139 | `192.168.1.XXX:139` |
| HIGH-004 | NetBIOS-SSN/SMB on port 139 | `169.254.YYY.YYY:139` |

### Info

| ID | Finding |
|-|-|
| INFO-001 | Running-services enumeration skipped (Linux-specific check) |
| INFO-002 | Windows Firewall profiles enabled |
| INFO-003 | Permission check skipped on Windows |
| INFO-004 | No suspicious processes flagged |
| INFO-005 | Password policy check skipped (Linux-specific check) |
| INFO-006 | Configuration check limited on this platform |

*(IDs above use the current per-severity numbering. When I first ran this, the tool actually numbered these as `CRIT-001, CRIT-003, CRIT-005, CRIT-006` etc. because of a bug - all severities were sharing one global ID counter. Fixed now, see the changelog.)*

## What this told me

SMB (445), NetBIOS (139), and MS-RPC (135) are on by default on Windows for file/printer sharing, and they're bound to all interfaces (`0.0.0.0` / `:::`), not just localhost. Doesn't mean anything's compromised, but it is real attack surface - those ports are reachable from whatever network the machine is on unless the Windows network profile is set to **Private** and/or a firewall rule blocks them.

I checked my own network profile to confirm:

```powershell
Get-NetConnectionProfile
```

## Two bugs this run actually caught

1. **The severity table doesn't know it's looking at a workstation.** SecAudit treats SMB/RPC exposure as CRITICAL no matter what, which makes sense for a server but is arguably too harsh for a normal home Windows desktop. Something like a `--host-role server|workstation` flag that adjusts severity for these specific services would make sense - it's on my list.
2. **Duplicate findings across IPv4/IPv6 - now fixed.** Notice CRIT-001/CRIT-003 are the same underlying thing (port 135 bound to all interfaces), just reported once for the IPv6-any binding and once for IPv4-any. Same with CRIT-002/CRIT-004 on port 445. That was a real bug - a dual-stack listener was getting double-counted as two separate exposures instead of one. Fixed it in `src/scanner/ports.py` with a dedup step, and added regression tests so it doesn't come back. Running this exact scan again today would report 2 CRITICAL findings here instead of 4.

## Windows coverage

`firewall.py`, `permissions.py`, and `config_checks.py` were all written against Linux tooling (`ufw`/`iptables`, `/etc/shadow`, `sshd_config`), so on Windows they correctly say "not applicable" instead of just crashing or silently doing nothing. Full Windows parity (ACL checks via `icacls`/`Get-Acl`, password policy via `secpol.msc`) is still on the to-do list.
