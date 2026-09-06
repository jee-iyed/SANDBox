"""M5 DynamicAnalyzer: eligibility -> sandbox execution -> behavioral findings.

Reuses the validated M3 execution engine (SandboxRunner + SandboxPolicy + the
in-container strace entrypoint) - no execution code is duplicated. Adds the M5
layer: explicit eligibility policy, bounded monitoring and behavioral findings
(shell_execution / suspicious_command / dns_request).

Compatibility contract: analyzer name stays "sandbox" (finding source unchanged)
so existing M3/M1 tests and clients remain valid. Only evidence findings are
produced - the Risk Engine remains the single decision point.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.dynamic.behavioral import behavioral_findings
from app.analyzers.dynamic.manager import DynamicAnalysisManager
from app.analyzers.dynamic.models import DynamicAnalysisResult, DynamicDecision
from app.analyzers.sandbox.events import FINDING_SANDBOX_ERROR, FINDING_SANDBOX_INFO
from app.analyzers.sandbox.normalizer import execution_summary_findings, normalize_events
from app.analyzers.sandbox.policy import SandboxPolicy
from app.analyzers.sandbox.runner import SandboxError, SandboxRunner
from app.core.config import settings
from app.db.models import Finding, Scan, Severity
from app.findings.schema import FindingSpec


def has_m4_high_finding(db: Session, scan_id) -> bool:
    row = (
        db.query(Finding.id)
        .filter(
            Finding.scan_id == scan_id,
            Finding.severity.in_([Severity.HIGH, Severity.CRITICAL]),
        )
        .limit(1)
        .first()
    )
    return row is not None


def _policy_info() -> dict:
    return {
        "image": settings.sandbox_image,
        "network_disabled": True,
        "read_only_rootfs": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "non_root": True,
        "mem_limit": settings.sandbox_mem_limit,
        "nano_cpus": settings.sandbox_nano_cpus,
        "pids_limit": settings.sandbox_pids_limit,
        "timeout_s": settings.sandbox_timeout_s,
        "exec_timeout_s": settings.sandbox_exec_timeout_s,
        "max_events": settings.dynamic_max_events,
        "max_output_mb": settings.dynamic_max_output_mb,
    }


class DynamicAnalyzer(BaseAnalyzer):
    name = "sandbox"
    version = settings.ANALYZER_VERSIONS["sandbox"]

    def __init__(self) -> None:
        self.manager = DynamicAnalysisManager()
        self._payload: dict | None = None

    def get_payload(self) -> dict | None:
        return self._payload

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        self._payload = None
        if scan.file is None:
            return []
        sha256 = scan.file.sha256
        path: Path = settings.uploads_dir / f"{sha256}.bin"
        if not path.is_file():
            return []

        with path.open("rb") as fh:
            head = fh.read(16)

        eligibility = self.manager.decide(
            head=head,
            filename=scan.file.filename,
            detected_type=scan.file.detected_type,
            size_bytes=scan.file.size_bytes,
            m4_high_finding=has_m4_high_finding(db, scan.id),
        )

        if eligibility.decision in (DynamicDecision.NOT_ELIGIBLE, DynamicDecision.SKIPPED_BY_POLICY):
            return self._skip(eligibility)

        try:
            runner = SandboxRunner(SandboxPolicy.from_settings())
            result = runner.analyze_file(sha256, scan.file.filename)
        except SandboxError as exc:
            decision = DynamicDecision.SANDBOX_ERROR
            self._payload = DynamicAnalysisResult(
                decision=decision.value,
                reason=str(exc)[:300],
                policy=_policy_info(),
                error=str(exc)[:500],
            ).to_dict()
            return [
                FindingSpec(
                    type=FINDING_SANDBOX_ERROR,
                    source=self.name,
                    analyzer_version=self.version,
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    evidence={"error": str(exc)[:500]},
                    tags=["sandbox", "error"],
                )
            ]

        decision, reason = _map_status(result.status)
        findings = normalize_events(result.events, self.name, self.version)
        findings += behavioral_findings(result.events, self.name, self.version)
        summary_findings = execution_summary_findings(
            {
                "status": result.status,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "summary": result.summary,
                "error": result.error,
            },
            self.name,
            self.version,
        )
        for f in summary_findings:
            if f.type == FINDING_SANDBOX_INFO and f.evidence is not None:
                f.evidence["decision"] = decision.value
                f.evidence["reason"] = reason
                f.evidence["policy"] = _policy_info()
        findings += summary_findings

        self._payload = DynamicAnalysisResult(
            decision=decision.value,
            reason=reason,
            status=result.status,
            sandbox_id=result.sandbox_id,
            duration_ms=result.duration_ms,
            exit_code=result.exit_code,
            event_counts=dict(result.summary or {}),
            finding_counts={f.type: findings.count(f) for f in findings},
            policy=_policy_info(),
            error=result.error,
        ).to_dict()
        return findings

    def _skip(self, eligibility) -> list[FindingSpec]:
        payload = DynamicAnalysisResult(
            decision=eligibility.decision.value,
            reason=eligibility.reason,
            policy=_policy_info(),
        ).to_dict()
        self._payload = payload
        return [
            FindingSpec(
                type=FINDING_SANDBOX_INFO,
                value=f"status_{eligibility.decision.value}",
                source=self.name,
                analyzer_version=self.version,
                severity=Severity.INFO,
                confidence=1.0,
                evidence={
                    "decision": eligibility.decision.value,
                    "reason": eligibility.reason,
                    "policy": _policy_info(),
                },
            )
        ]


def _map_status(status: str) -> tuple[DynamicDecision, str]:
    if status == "timeout":
        return DynamicDecision.TIMEOUT, "exec_timeout"
    if status == "resource_limit":
        return DynamicDecision.EXECUTION_ERROR, "resource_limit"
    if status == "failed_to_start":
        return DynamicDecision.EXECUTION_ERROR, "failed_to_start"
    if status == "crashed":
        return DynamicDecision.EXECUTED, "crashed"
    return DynamicDecision.EXECUTED, "executed"
