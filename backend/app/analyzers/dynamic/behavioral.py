"""M5 behavioral signal enrichment (raw sandbox events -> extra findings).

M3's normalizer already emits process/file/network findings. This module adds the
M5 behavioral layer: shell execution, suspicious command lines and DNS attempts.
Like M3, it emits evidence findings ONLY - severity is observational, never a
verdict. The FIRST traced process is the sandbox harness (interpreter for the
sample shebang) and is skipped here exactly like the M3 normalizer does, so a
benign script stays clean.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.db.models import Severity
from app.findings.schema import FindingSpec

SHELL_NAMES = {
    "sh", "bash", "ash", "zsh", "dash", "ksh", "csh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "python", "python3", "perl", "ruby",
}

_SUSPICIOUS_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE), "reverse_shell_dev"),
    (re.compile(r"\bnc(\.exe|at)?\s+-e\b", re.IGNORECASE), "netcat_backdoor"),
    (re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)", re.IGNORECASE), "decoded_pipe_shell"),
    (re.compile(r"(curl|wget)[^\n|]*\|\s*(sh|bash)", re.IGNORECASE), "download_execute"),
    (re.compile(r"rm\s+-rf\s+/", re.IGNORECASE), "destructive_delete"),
    (re.compile(r"chmod\s+(\+x|777)", re.IGNORECASE), "privilege_change"),
    (re.compile(r"crontab\s+-", re.IGNORECASE), "persistence_schedule"),
)


def _argv_text(ev: dict) -> str:
    argv = ev.get("argv")
    if isinstance(argv, list) and argv:
        return " ".join(str(a) for a in argv[:16])
    return str(ev.get("command_line") or ev.get("name") or "")


def behavioral_findings(events: list[dict], source: str, analyzer_version: str) -> list[FindingSpec]:
    out: list[FindingSpec] = []
    first_process_seen = False

    for ev in events:
        etype = ev.get("type")
        if etype == "process_created":
            if not first_process_seen:
                first_process_seen = True  # harness launch - not sample behavior
                continue
            name = Path(str(ev.get("name") or "")).name.lower()
            if name in SHELL_NAMES:
                out.append(
                    FindingSpec(
                        type="shell_execution",
                        value=str(ev.get("command_line") or name)[:512],
                        source=source,
                        analyzer_version=analyzer_version,
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        evidence=dict(ev),
                        tags=["sandbox", "m5", "shell"],
                    )
                )
            cmd = _argv_text(ev)
            for pattern, label in _SUSPICIOUS_PATTERNS:
                if pattern.search(cmd):
                    out.append(
                        FindingSpec(
                            type="suspicious_command",
                            value=cmd[:512],
                            source=source,
                            analyzer_version=analyzer_version,
                            severity=Severity.HIGH,
                            confidence=0.8,
                            evidence={"pattern": label, "command_line": cmd[:512]},
                            tags=["sandbox", "m5", "suspicious_command"],
                        )
                    )
                    break
        elif etype == "network_attempt":
            if ev.get("port") == 53:
                dst = ev.get("destination") or "unknown"
                out.append(
                    FindingSpec(
                        type="dns_request",
                        value=f"{dst}:53",
                        source=source,
                        analyzer_version=analyzer_version,
                        severity=Severity.LOW,
                        confidence=0.7,
                        evidence=dict(ev),
                        tags=["sandbox", "m5", "dns"],
                    )
                )
    return out
