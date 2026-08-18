"""
Static reference data: well-known ports, "dangerous" services, and the
severity we assign when they're found exposed. This is intentionally a
plain Python dict so it's trivial to extend later (or eventually swap
for a live CVE/API feed in Phase 2).
"""

from .. import models

Severity = models.Severity

# port -> (service name, base severity if found LISTENING AT ALL,
#          base severity if found exposed on 0.0.0.0 / all interfaces)
DANGEROUS_PORTS = {
    21:    ("FTP",              Severity.HIGH,     Severity.CRITICAL),
    23:    ("Telnet",           Severity.CRITICAL, Severity.CRITICAL),
    25:    ("SMTP",             Severity.MEDIUM,    Severity.HIGH),
    69:    ("TFTP",             Severity.HIGH,      Severity.CRITICAL),
    111:   ("RPCbind",          Severity.MEDIUM,    Severity.HIGH),
    135:   ("MS-RPC",           Severity.HIGH,      Severity.CRITICAL),
    137:   ("NetBIOS-NS",       Severity.MEDIUM,    Severity.HIGH),
    138:   ("NetBIOS-DGM",      Severity.MEDIUM,    Severity.HIGH),
    139:   ("NetBIOS-SSN/SMB",  Severity.HIGH,      Severity.CRITICAL),
    445:   ("SMB",              Severity.HIGH,      Severity.CRITICAL),
    512:   ("rexec",            Severity.HIGH,      Severity.CRITICAL),
    513:   ("rlogin",           Severity.HIGH,      Severity.CRITICAL),
    514:   ("rsh",              Severity.HIGH,      Severity.CRITICAL),
    1433:  ("MSSQL",            Severity.MEDIUM,    Severity.HIGH),
    1521:  ("Oracle DB",        Severity.MEDIUM,    Severity.HIGH),
    2049:  ("NFS",              Severity.MEDIUM,    Severity.HIGH),
    3306:  ("MySQL",            Severity.MEDIUM,    Severity.HIGH),
    3389:  ("RDP",              Severity.HIGH,      Severity.CRITICAL),
    5432:  ("PostgreSQL",       Severity.MEDIUM,    Severity.HIGH),
    5900:  ("VNC",              Severity.HIGH,      Severity.CRITICAL),
    6379:  ("Redis",            Severity.HIGH,      Severity.CRITICAL),
    9200:  ("Elasticsearch",    Severity.MEDIUM,    Severity.HIGH),
    27017: ("MongoDB",          Severity.HIGH,      Severity.CRITICAL),
}

# Ports that are common/expected but should still be reviewed if
# exposed broadly rather than restricted to trusted networks.
SENSITIVE_PORTS = {
    22:  ("SSH",   Severity.LOW, Severity.MEDIUM),
    80:  ("HTTP",  Severity.INFO, Severity.LOW),
    443: ("HTTPS", Severity.INFO, Severity.LOW),
    8080: ("HTTP-Alt", Severity.INFO, Severity.LOW),
}

COMMON_SERVICE_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# Process name fragments that are worth flagging when discovered on a
# host during the "suspicious processes" check. This is a heuristic
# list, not a signature database - false positives are expected and
# each finding says so.
SUSPICIOUS_PROCESS_HINTS = [
    "nc", "ncat", "netcat", "xmrig", "minerd", "cryptonight",
    "mimikatz", "meterpreter", "reverse_shell", "socat",
    "john", "hashcat", "hydra", "nmap",
]
