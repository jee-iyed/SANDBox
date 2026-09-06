from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.fast_scan.entropy import shannon_entropy
from app.analyzers.fast_scan.magic import detect, extension_of, type_mismatch
from app.analyzers.fast_scan.signatures import scan_sample
from app.core.config import settings
from app.db.models import Scan, Severity
from app.findings.schema import FindingSpec

# Bounded read: enough for type detection + sample entropy, keeps runtime quick.
FAST_SAMPLE_BYTES = 8192


class FastScanAnalyzer(BaseAnalyzer):
    """Cheap first-pass byte-level scan (magic bytes, entropy, signatures).

    M2 scope: *detect quickly*. Deep understanding is M4 (static/YARA).
    This analyzer only emits Findings - it never decides a verdict (the Risk
    Engine in orchestrator/scanner.py derives verdict+action from findings).
    """

    name = "fast_scan"
    version = settings.ANALYZER_VERSIONS["fast_scan"]

    def _load_sample(self, scan: Scan) -> bytes | None:
        if scan.file is None:
            return None
        path: Path = settings.uploads_dir / f"{scan.file.sha256}.bin"
        if not path.exists():
            return None
        with path.open("rb") as fh:
            return fh.read(FAST_SAMPLE_BYTES)

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        sample = self._load_sample(scan)
        if sample is None:
            return []
        findings: list[FindingSpec] = []

        # 1) Type detection by magic bytes -> enrich the file record.
        detected_type, mime = detect(sample)
        if detected_type and scan.file:
            scan.file.detected_type = detected_type

        # 2) Extension vs. content mismatch (but OOXML/ODF are legitimate ZIP).
        ext = extension_of(scan.file.filename) if scan.file else ""
        if type_mismatch(ext, detected_type):
            findings.append(
                FindingSpec(
                    type="file_type_mismatch",
                    value=f"extension={ext or '?'} detected={detected_type}",
                    source=self.name,
                    analyzer_version=self.version,
                    severity=Severity.MEDIUM,
                    confidence=0.99,
                    evidence={
                        "filename": scan.file.filename,
                        "extension": ext,
                        "detected_type": detected_type,
                        "detected_mime": mime,
                    },
                    tags=["fast_scan", "mismatch"],
                )
            )

        # 3) Sample entropy (evidence, NOT a verdict).
        h = shannon_entropy(sample)
        findings.append(
            FindingSpec(
                type="entropy_sample",
                value=f"{h:.3f}",
                source=self.name,
                analyzer_version=self.version,
                severity=Severity.INFO,
                confidence=1.0,
                evidence={
                    "entropy_sample": round(h, 3),
                    "entropy_sample_size": len(sample),
                },
                tags=["fast_scan", "entropy"],
            )
        )

        # 4) Cheap plain-text signature breadcrumbs (heuristic only).
        for name, _pat, sev in scan_sample(sample):
            findings.append(
                FindingSpec(
                    type=name,
                    source=self.name,
                    analyzer_version=self.version,
                    severity=sev,
                    confidence=0.3,
                    tags=["fast_scan", "signature", "heuristic"],
                )
            )

        findings.append(
            FindingSpec(
                type="fast_scan",
                value=detected_type or "unknown",
                source=self.name,
                analyzer_version=self.version,
                severity=Severity.INFO,
                confidence=1.0,
                evidence={
                    "detected_type": detected_type,
                    "detected_mime": mime,
                    "sample_bytes_read": len(sample),
                },
            )
        )
        return findings
