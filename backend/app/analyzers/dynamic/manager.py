"""M5 dynamic-analysis eligibility policy (pure decision, no side effects).

Two-tier policy (adjusted with client):
  1. Eligible by nature: executable/script signals (shebang, ELF/PE magic,
     detected elf/pe, script extensions) within size limits.
  2. Eligible by suspicion: non-executable documents are executed ONLY when M4
     (static/YARA) already produced a HIGH or CRITICAL finding.

Every skip is explicit and carries an observable reason. The manager never
executes anything itself - the DynamicAnalyzer owns execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.analyzers.dynamic.models import DynamicDecision

SCRIPT_EXTENSIONS = {
    ".sh", ".bash", ".py", ".js", ".bat", ".cmd", ".ps1", ".pl", ".rb", ".exe",
}

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"


@dataclass(frozen=True)
class Eligibility:
    decision: DynamicDecision
    reason: str


def is_executable(head: bytes, filename: str, detected_type: str | None) -> bool:
    if head.startswith(b"#!"):
        return True
    if head.startswith(ELF_MAGIC) or head.startswith(PE_MAGIC):
        return True
    if detected_type in ("elf", "pe"):
        return True
    return Path(filename or "").suffix.lower() in SCRIPT_EXTENSIONS


class DynamicAnalysisManager:
    def __init__(self) -> None:
        self.enabled = settings.dynamic_enabled
        self.max_file_mb = settings.dynamic_max_file_mb

    def decide(
        self,
        *,
        head: bytes,
        filename: str,
        detected_type: str | None,
        size_bytes: int,
        m4_high_finding: bool,
    ) -> Eligibility:
        if not self.enabled:
            return Eligibility(DynamicDecision.SKIPPED_BY_POLICY, "disabled")
        if size_bytes > self.max_file_mb * 1024 * 1024:
            return Eligibility(DynamicDecision.SKIPPED_BY_POLICY, "size_exceeded")
        if is_executable(head, filename, detected_type):
            return Eligibility(DynamicDecision.EXECUTED, "eligible")
        if m4_high_finding:
            return Eligibility(DynamicDecision.EXECUTED, "suspicion")
        return Eligibility(DynamicDecision.NOT_ELIGIBLE, "not_executable")
