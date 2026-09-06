"""Normalize raw sandbox behavioral events -> canonical FindingSpec (M3).

Every sandbox detection uses the single existing Finding schema (source="sandbox").
This module NEVER produces a verdict - it only emits evidence findings. Risk/verdict
are derived downstream by the existing risk engine.

It also filters out sandbox-internal noise (e.g. dynamic-loader accesses of system
libraries), per the brief: "distinguish sandbox infrastructure activity from sample
behavior". Access to system library/loader paths is not treated as behavior.
"""

from __future__ import annotations

from app.analyzers.sandbox.events import (
    FINDING_FILE_CREATION,
    FINDING_FILE_DELETION,
    FINDING_FILE_MODIFICATION,
    FINDING_NETWORK_ATTEMPT,
    FINDING_PROCESS_CREATION,
    FINDING_RESOURCE_LIMIT,
    FINDING_SANDBOX_ERROR,
    FINDING_SANDBOX_INFO,
    FINDING_EXECUTION_TIMEOUT,
)
from app.db.models import Severity
from app.findings.schema import FindingSpec

# System loader/library paths whose reads/accesses are NOT sample behavior.
_SYSTEM_PREFIXES = (
    "/lib",
    "/usr/lib",
    "/usr/local/lib",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/dev/random",
    "/analysis/input",
)


def _is_system(path: str | None) -> bool:
    if not path:
        return False
    return any(path.startswith(p) for p in _SYSTEM_PREFIXES)


def _event_severity(event: dict) -> Severity:
    etype = event.get("type")
    return {
        "process_created": Severity.LOW,
        "file_created": Severity.MEDIUM,
        "file_modified": Severity.MEDIUM,
        "file_deleted": Severity.LOW,
        "file_accessed": Severity.INFO,
        "network_attempt": Severity.HIGH,
    }.get(etype, Severity.INFO)


def normalize_events(events: list[dict], source: str, analyzer_version: str) -> list[FindingSpec]:
    """Convert raw events into FindingSpec list, dropping system noise.

    The FIRST traced process is the sandbox harness launching the sample (e.g.
    `/bin/sh sample.sh` from the `#!` line). That is harness behavior, not sample
    behavior, so it is not emitted as a finding - the run itself is recorded in the
    sandbox_info finding. Only processes the sample spawns AFTER that initial
    launch (child processes) are reported per brief §9.
    """
    out: list[FindingSpec] = []
    first_process_seen = False

    for ev in events:
        etype = ev.get("type")
        path = ev.get("path")
        # Drop system loader/lib access and reads of the input mount itself.
        if etype in ("file_accessed", "file_created", "file_modified", "file_deleted"):
            if _is_system(path):
                continue

        if etype == "process_created":
            if not first_process_seen:
                # harness launch (top-level interpreter for the sample) - skip
                first_process_seen = True
                continue
            value = ev.get("command_line") or ev.get("name")
            finding_type = FINDING_PROCESS_CREATION
            severity = _event_severity(ev)
            confidence = 0.7
            out.append(
                FindingSpec(
                    type=finding_type,
                    value=value,
                    source=source,
                    analyzer_version=analyzer_version,
                    severity=severity,
                    confidence=confidence,
                    evidence=dict(ev),
                    tags=["sandbox", "process_created"],
                )
            )
            continue

        value = None
        if etype in ("file_created", "file_modified", "file_deleted"):
            value = path
        elif etype == "network_attempt":
            dst = ev.get("destination")
            port = ev.get("port")
            value = f"{dst}:{port}" if dst and port is not None else (dst or "unknown")

        confidence = 0.9 if etype == "network_attempt" else 0.7

        finding_type = {
            "file_created": FINDING_FILE_CREATION,
            "file_modified": FINDING_FILE_MODIFICATION,
            "file_deleted": FINDING_FILE_DELETION,
            "network_attempt": FINDING_NETWORK_ATTEMPT,
        }.get(etype)
        if finding_type is None:
            continue

        out.append(
            FindingSpec(
                type=finding_type,
                value=value,
                source=source,
                analyzer_version=analyzer_version,
                severity=_event_severity(ev),
                confidence=confidence,
                evidence=dict(ev),
                tags=["sandbox", etype],
            )
        )
    return out


def execution_summary_findings(
    result: dict, source: str, analyzer_version: str
) -> list[FindingSpec]:
    """Produce informational / state findings from the execution summary.

    Timeout and resource-limit are themselves evidence findings (severity per the
    design), but the sandbox does NOT decide the verdict - risk engine does.
    """
    out: list[FindingSpec] = []
    status = result.get("status")
    exit_code = result.get("exit_code")

    if status in ("timeout",):
        out.append(
            FindingSpec(
                type=FINDING_EXECUTION_TIMEOUT,
                value=f"execution exceeded {result.get('exec_timeout_s', '?')}s",
                source=source,
                analyzer_version=analyzer_version,
                severity=Severity.MEDIUM,
                confidence=0.9,
                evidence={"status": status, "duration_ms": result.get("duration_ms")},
                tags=["sandbox", "timeout"],
            )
        )
    elif status in ("resource_limit",):
        out.append(
            FindingSpec(
                type=FINDING_RESOURCE_LIMIT,
                source=source,
                analyzer_version=analyzer_version,
                severity=Severity.HIGH,
                confidence=0.9,
                evidence={"status": status, "exit_code": exit_code},
                tags=["sandbox", "resource"],
            )
        )

    # Operational info (source=sandbox, INFO) describing the run.
    out.append(
        FindingSpec(
            type=FINDING_SANDBOX_INFO,
            value=f"status_{status}",
            source=source,
            analyzer_version=analyzer_version,
            severity=Severity.INFO,
            confidence=1.0,
            evidence={
                "status": status,
                "exit_code": exit_code,
                "duration_ms": result.get("duration_ms"),
                "summary": result.get("summary"),
                "error": result.get("error"),
            },
        )
    )

    if result.get("error"):
        out.append(
            FindingSpec(
                type=FINDING_SANDBOX_ERROR,
                source=source,
                analyzer_version=analyzer_version,
                severity=Severity.MEDIUM,
                confidence=0.5,
                evidence={"error": result["error"][:500]},
                tags=["sandbox", "error"],
            )
        )
    return out
