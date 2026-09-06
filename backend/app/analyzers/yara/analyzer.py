"""M4 YARA analyzer: bytes in, normalized evidence findings out."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.yara.engine import YaraEngine
from app.core.config import settings
from app.db.models import Scan, Severity
from app.findings.schema import FindingSpec


class YaraAnalyzer(BaseAnalyzer):
    name = "yara"

    def __init__(self) -> None:
        self.engine: YaraEngine | None = None
        self._payload: dict | None = None
        if settings.yara_enabled:
            self.engine = YaraEngine(timeout_s=settings.yara_timeout_s, max_matches=settings.yara_max_matches)
        self.version = self.engine.analyzer_version if self.engine else "yara:disabled"

    def get_payload(self) -> dict | None:
        return self._payload

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        self._payload = None
        if not settings.yara_enabled or self.engine is None or scan.file is None:
            return []
        path = settings.uploads_dir / f"{scan.file.sha256}.bin"
        if not path.is_file():
            return []
        data = path.read_bytes()[: settings.static_max_scan_bytes]
        matches, errors = self.engine.scan(data)
        findings = []
        for match in matches:
            severity = _severity(match.meta)
            evidence = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": _bounded_meta(match.meta),
                "category": match.category,
                "strings": match.strings,
                "ruleset_revision": self.engine.manager.revision,
            }
            locations = match.strings[:20]
            findings.append(FindingSpec(
                type="yara_match",
                value=match.rule[:512],
                source=self.name,
                analyzer_version=self.version,
                severity=severity,
                confidence=0.9 if severity != Severity.INFO else 0.7,
                location={"matches": locations} if locations else None,
                evidence=evidence,
                tags=["m4", "yara", match.category, *match.tags[:8]],
            ))
        self._payload = {
            "metadata": {"engine": "yara", "engine_version": self.version, "ruleset_revision": self.engine.manager.revision},
            "hashes": {"sha256": scan.file.sha256},
            "structure": {},
            "objects": [],
            "indicators": [{"rule": m.rule, "category": m.category} for m in matches[:100]],
            "features": {"bytes_inspected": len(data), "compile_errors": errors[:20]},
        }
        return findings


def _bounded_meta(meta: dict) -> dict:
    result = {}
    for key, value in list(meta.items())[:20]:
        result[str(key)[:64]] = str(value)[:512]
    return result


def _severity(meta: dict) -> Severity:
    value = str(meta.get("severity", "info")).lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(value, Severity.INFO)
