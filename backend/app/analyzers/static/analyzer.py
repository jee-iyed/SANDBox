"""M4 Static/Signature analyzer.

Inspects sample bytes/text for known suspicious static patterns WITHOUT ever
executing the sample. Emits only evidence findings (source="static_analysis");
it never decides a verdict - the Risk Engine (orchestrator/scanner.py) derives
risk -> verdict -> action from findings.

Safety: no subprocess, no network, no dynamic loading. Byte/regex matching only,
bounded by ``settings.static_max_scan_bytes``.
"""

from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.static.rule import match_rule
from app.analyzers.static.rules import RULES
from app.core.config import settings
from app.db.models import Scan, Severity
from app.findings.schema import FindingSpec


class StaticAnalyzer(BaseAnalyzer):
    name = "static_analysis"
    version = settings.ANALYZER_VERSIONS["static"]

    def _load_sample(self, scan: Scan) -> bytes | None:
        if scan.file is None:
            return None
        path: Path = settings.uploads_dir / f"{scan.file.sha256}.bin"
        if not path.exists():
            return None
        with path.open("rb") as fh:
            return fh.read(settings.static_max_scan_bytes)

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        data = self._load_sample(scan)
        if data is None:
            return []

        findings: list[FindingSpec] = []
        for rule in RULES:
            matches = match_rule(rule, data)
            if not matches:
                continue
            findings.append(
                FindingSpec(
                    type=rule.id,
                    value=_describe(rule, matches),
                    source=self.name,
                    analyzer_version=self.version,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence={
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "category": rule.category,
                        "match_count": len(matches),
                        "matches": matches,
                        "sample_bytes_read": len(data),
                    },
                    tags=list(rule.tags) + ["static_analysis", rule.category],
                )
            )
        return findings


def _describe(rule, matches: list[dict]) -> str:
    first = matches[0]
    detail = first.get("matched") or first.get("pattern") or ""
    return f"{rule.name}: {detail[:200]}"
