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
