from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.sandbox.events import FINDING_SANDBOX_ERROR
from app.analyzers.sandbox.normalizer import (
    execution_summary_findings,
    normalize_events,
)
from app.analyzers.sandbox.policy import SandboxPolicy
from app.analyzers.sandbox.runner import SandboxError, SandboxRunner, SandboxResult
from app.core.config import settings
from app.db.models import Scan, Severity
from app.findings.schema import FindingSpec


class SandboxAnalyzer(BaseAnalyzer):
    """M3 Dynamic Analysis: executes untrusted input in an isolated, hardened
    container under strict limits and converts runtime observations (process /
    filesystem / network / execution result) into normalized findings.

    This analyzer ONLY produces evidence (source="sandbox"); it never decides a
    verdict. Risk/verdict/action are derived by the existing pipeline.
    """

    name = "sandbox"
    version = settings.ANALYZER_VERSIONS["sandbox"]

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        if not settings.sandbox_enabled:
            return []
        if scan.file is None:
            return []
        sha256 = scan.file.sha256
        if not settings.uploads_dir.joinpath(f"{sha256}.bin").exists():
            return []

        runner = SandboxRunner(SandboxPolicy.from_settings())
        try:
            result: SandboxResult = runner.analyze_file(sha256, scan.file.filename)
        except SandboxError as exc:
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

        findings = normalize_events(result.events, self.name, self.version)
        findings += execution_summary_findings(
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
        return findings
