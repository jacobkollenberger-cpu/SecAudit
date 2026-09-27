# Sample Scan: My Windows Machine

I ran a `--local` scan against my own Windows 10/11 machine and figured it was worth keeping as a real example, since it actually surfaced a couple of bugs in the tool itself.

```
python main.py --local --output json,html,csv,txt --outdir reports
```

**Target:** localhost (Windows)
**Date:** 2026-09-27
**Modules run:** ports, services, firewall, permissions, processes, password_policy, configuration

> **Note:** I tokenized private/link-local IPs in this report (e.g. `192.168.1.XXX`) since it's a real scan of my home network and I'm posting it publicly. `0.0.0.0` is left as-is since it just means "bound to all interfaces," not an identifying address.

## Result

| Metric | Value |
|-|-|
| **Security Score** | 0 / 100 |
| **Grade** | F |
| Critical | 2 |
| High | 5 |
| Medium | 0 |
| Low | 0 |
| Info | 6 |

## Findings

### Critical

| ID | Finding | Detail |
|-|-|-|
| CRIT-001 | SMB listening on port 445 | `0.0.0.0:445` (System) |
| CRIT-002 | MS-RPC listening on port 135 | `0.0.0.0:135` (svchost.exe) |

### High

| ID | Finding | Detail |
|-|-|-|
| HIGH-001 | NetBIOS-SSN/SMB on port 139 | `192.168.1.XXX:139` |
| HIGH-002 | NetBIOS-SSN/SMB on port 139 | `192.168.220.XXX:139` |
| HIGH-003 | NetBIOS-SSN/SMB on port 139 | `192.168.51.XXX:139` |
| HIGH-004 | NetBIOS-SSN/SMB on port 139 | `192.168.109.XXX:139` |
| HIGH-005 | NetBIOS-SSN/SMB on port 139 | `192.168.56.XXX:139` |

### Info

| ID | Finding |
|-|-|
| INFO-001 | Running-services enumeration skipped (Linux-specific check) |
| INFO-002 | Windows Firewall profiles enabled |
| INFO-003 | Permission check skipped on Windows |
| INFO-004 | No suspicious processes flagged |
| INFO-005 | Password policy check skipped (Linux-specific check) |
| INFO-006 | Configuration check limited on this platform |

## What this told me

SMB (445) and MS-RPC (135) are on by default on Windows for file/printer sharing, and they're bound to all interfaces (`0.0.0.0`), which is real attack surface - reachable from whatever network the machine is on unless the Windows network profile is set to **Private** and/or a firewall rule blocks them.

The five NetBIOS (139) findings aren't five different networks I'm actually on - they're one per virtual network adapter on this machine (VPN client, VirtualBox/VMware host-only adapters, that kind of thing all create their own `192.168.x.1`-style gateway address). Worth remembering when reading results on a dev machine: a pile of NetBIOS findings can just mean "you have a lot of virtual NICs," not "you're on five networks."

I checked my own network profile to confirm:

```powershell
Get-NetConnectionProfile
```

## Two bugs this run helped me catch (now fixed)

1. **Finding IDs weren't numbered per severity.** All findings shared one global counter regardless of severity, so a run could produce something like `CRIT-001, CRIT-003, CRIT-005` with gaps where other severities had grabbed a number in between. Fixed in `src/models.py` so each severity (`CRIT-`, `HIGH-`, etc.) now counts up independently, and added a regression test for it.
2. **Duplicate findings across IPv4/IPv6 - now fixed.** On an earlier run, a dual-stack listener (bound to both the IPv4-any and IPv6-any address on the same port) was getting reported twice instead of once - e.g. port 445 showed up as both `0.0.0.0:445` and `:::445`, counted as two separate Critical findings for what's really one exposure. I fixed this with a dedup step in `src/scanner/ports.py` and added tests for it. This run above is the proof it works: SMB and RPC each show up exactly once now instead of twice, so Critical dropped from what would've been 4 down to the correct 2.

One thing still on my list: **the severity table doesn't know it's looking at a workstation.** SecAudit treats SMB/RPC exposure as CRITICAL no matter what, which makes sense for a server but is arguably too harsh for a normal home Windows desktop. Something like a `--host-role server|workstation` flag that adjusts severity for these specific services would make sense.

## Windows coverage

`firewall.py`, `permissions.py`, and `config_checks.py` were all written against Linux tooling (`ufw`/`iptables`, `/etc/shadow`, `sshd_config`), so on Windows they correctly say "not applicable" instead of just crashing or silently doing nothing. Full Windows parity (ACL checks via `icacls`/`Get-Acl`, password policy via `secpol.msc`) is still on the to-do list.
