import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.sandbox.events import (  # noqa: E402
    FINDING_EXECUTION_TIMEOUT,
    FINDING_NETWORK_ATTEMPT,
    FINDING_PROCESS_CREATION,
    FINDING_RESOURCE_LIMIT,
    FINDING_SANDBOX_ERROR,
    FINDING_SANDBOX_INFO,
    FINDING_FILE_CREATION,
)
from app.analyzers.sandbox.normalizer import (  # noqa: E402
    execution_summary_findings,
    normalize_events,
)
from app.db.models import Severity  # noqa: E402

SRC = "sandbox"
VER = "test"


def test_normalizes_events_and_filters_system_noise():
    events = [
        {"type": "process_created", "pid": "10", "name": "sh", "command_line": "/bin/sh"},  # harness -> dropped
        {"type": "process_created", "pid": "11", "name": "sh", "command_line": "/bin/sh -c id"},  # child -> kept
        {"type": "file_created", "pid": "11", "path": "/tmp/payload.exe"},
        {"type": "network_attempt", "pid": "11", "destination": "203.0.113.9", "port": 4444},
        {"type": "file_accessed", "pid": "10", "path": "/lib/libc.so"},  # system noise
        {"type": "file_accessed", "pid": "10", "path": "/analysis/input/x.pdf"},  # input mount
    ]
    out = normalize_events(events, SRC, VER)
    types = [f.type for f in out]
    assert FINDING_PROCESS_CREATION in types
    assert FINDING_FILE_CREATION in types
    assert FINDING_NETWORK_ATTEMPT in types
    # only the second (child) process_created survived; harness launch dropped
    procs = [f for f in out if f.type == FINDING_PROCESS_CREATION]
    assert len(procs) == 1, procs
    assert procs[0].value == "/bin/sh -c id"
    # system/lib and input-mount noise must be dropped
    for f in out:
        assert f.type != "file_accessed"
    assert all(f.source == SRC for f in out)
    assert all(f.analyzer_version == VER for f in out)
    net = next(f for f in out if f.type == FINDING_NETWORK_ATTEMPT)
    assert net.severity == Severity.HIGH
    assert net.value == "203.0.113.9:4444"


def test_summary_timeout():
    findings = execution_summary_findings(
        {"status": "timeout", "exit_code": 124, "duration_ms": 3000, "exec_timeout_s": 3},
        SRC,
        VER,
    )
    types = [f.type for f in findings]
    assert FINDING_EXECUTION_TIMEOUT in types
    assert FINDING_SANDBOX_INFO in types
    to = next(f for f in findings if f.type == FINDING_EXECUTION_TIMEOUT)
    assert to.severity == Severity.MEDIUM


def test_summary_resource_limit():
    findings = execution_summary_findings(
        {"status": "resource_limit", "exit_code": 137},
        SRC,
        VER,
    )
    assert FINDING_RESOURCE_LIMIT in [f.type for f in findings]


def test_summary_error():
    findings = execution_summary_findings(
        {"status": "failed_to_start", "error": "boom", "exit_code": 1},
        SRC,
        VER,
    )
    assert FINDING_SANDBOX_ERROR in [f.type for f in findings]


def test_summary_normal_completed():
    findings = execution_summary_findings(
        {"status": "completed", "exit_code": 0, "duration_ms": 50},
        SRC,
        VER,
    )
    types = [f.type for f in findings]
    assert FINDING_SANDBOX_INFO in types
    assert FINDING_EXECUTION_TIMEOUT not in types
    assert FINDING_SANDBOX_ERROR not in types
    info = next(f for f in findings if f.type == FINDING_SANDBOX_INFO)
    assert info.severity == Severity.INFO


print("SANDBOX NORMALIZER TESTS PASSED")
