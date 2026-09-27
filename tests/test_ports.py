import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import ports


def test_scan_remote_host_closed_port():
    # Port 1 is virtually never open; loopback should refuse quickly.
    results = ports.scan_remote_host("127.0.0.1", ports=[1], timeout=0.3)
    assert results[0]["port"] == 1
    assert results[0]["open"] is False


def test_check_remote_host_reports_info_when_nothing_open():
    findings = ports.check_remote_host("127.0.0.1", ports=[1], timeout=0.3)
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"


def test_dangerous_ports_table_has_ftp_telnet_smb():
    assert 21 in ports.ref.DANGEROUS_PORTS
    assert 23 in ports.ref.DANGEROUS_PORTS
    assert 445 in ports.ref.DANGEROUS_PORTS


def test_dual_stack_binding_deduped_to_one_row():
    # Same port, bound to both 0.0.0.0 and ::: - that's one real
    # exposure, not two. Regression test for the double-counting I ran
    # into testing against my Windows machine (docs/sample-scan-windows.md).
    rows = [
        {"address": "0.0.0.0", "port": 445, "pid": 4, "process": "System"},
        {"address": "::", "port": 445, "pid": 4, "process": "System"},
    ]
    deduped = ports._dedupe_dual_stack(rows)
    assert len(deduped) == 1
    assert deduped[0]["port"] == 445


def test_distinct_addresses_on_same_port_not_merged():
    # Different real addresses on the same port are separate bindings
    # and shouldn't get collapsed by the dual-stack dedup.
    rows = [
        {"address": "192.168.1.5", "port": 139, "pid": 4, "process": "System"},
        {"address": "169.254.1.2", "port": 139, "pid": 4, "process": "System"},
    ]
    deduped = ports._dedupe_dual_stack(rows)
    assert len(deduped) == 2


def test_check_local_ports_reports_info_when_nothing_flagged(monkeypatch):
    monkeypatch.setattr(ports, "local_listening_ports", lambda: [
        {"address": "127.0.0.1", "port": 9999, "pid": 1, "process": "test"}
    ])
    findings = ports.check_local_ports("localhost")
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"
