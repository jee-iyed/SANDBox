"""M4 bounded structural analysis for documents and archives.

This module reads bytes and metadata only. It never executes scripts, macros or
embedded objects. Archive members are inspected in memory with strict count,
size and depth limits.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.analyzers.static.analysis import FileAnalysis
from app.core.config import settings
from app.db.models import Scan, Severity
from app.findings.schema import FindingSpec


class StructuralAnalyzer(BaseAnalyzer):
    name = "structural_analysis"
    version = settings.ANALYZER_VERSIONS["static"]

    def __init__(self) -> None:
        self._payload: dict | None = None

    def get_payload(self) -> dict | None:
        return self._payload

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        self._payload = None
        if scan.file is None:
            return []
        path = settings.uploads_dir / f"{scan.file.sha256}.bin"
        if not path.is_file():
            return []
        try:
            data = path.read_bytes()[: settings.static_max_scan_bytes]
        except OSError:
            return []

        analysis = FileAnalysis(
            metadata={
                "filename": scan.file.filename,
                "mime_type": scan.file.mime_type,
                "size_bytes": scan.file.size_bytes,
                "bytes_inspected": len(data),
            },
            hashes={"sha256": scan.file.sha256},
            features={"bounded": True},
        )
        findings: list[FindingSpec] = []
        findings.extend(self._pdf(data, analysis))
        findings.extend(self._archive(data, analysis))
        findings.extend(self._office(data, path, analysis))
        self._payload = analysis.to_dict()
        return findings

    def _pdf(self, data: bytes, analysis: FileAnalysis) -> list[FindingSpec]:
        if not data.startswith(b"%PDF"):
            return []
        analysis.structure["format"] = "pdf"
        indicators = []
        for marker in (b"/JavaScript", b"/OpenAction", b"/Launch", b"/EmbeddedFile"):
            offset = data.lower().find(marker.lower())
            if offset >= 0:
                indicators.append(marker.decode("ascii"))
        analysis.structure["pdf"] = {"active_markers": indicators}
        if not indicators:
            return []
        analysis.indicators.extend({"type": "pdf_active_content", "value": x} for x in indicators)
        return [
            FindingSpec(
                type="structural_pdf_active_content",
                value=indicators[0],
                source=self.name,
                analyzer_version=self.version,
                severity=Severity.MEDIUM,
                confidence=0.9,
                location={"byte_offsets": [data.lower().find(x.lower().encode()) for x in indicators]},
                evidence={"format": "pdf", "markers": indicators},
                tags=["m4", "structural", "pdf"],
            )
        ]

    def _archive(self, data: bytes, analysis: FileAnalysis) -> list[FindingSpec]:
        if not data.startswith(b"PK"):
            return []
        try:
            return self._scan_zip(data, analysis, depth=0)
        except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
            analysis.structure["archive"] = {"malformed": True}
            return [
                FindingSpec(
                    type="structural_malformed_archive",
                    source=self.name,
                    analyzer_version=self.version,
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    evidence={"format": "zip", "reason": "invalid_zip"},
                    tags=["m4", "structural", "archive"],
                )
            ]

    def _scan_zip(self, data: bytes, analysis: FileAnalysis, depth: int) -> list[FindingSpec]:
        findings: list[FindingSpec] = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            total_uncompressed = sum(max(0, i.file_size) for i in infos)
            archive_info = {
                "depth": depth,
                "entries": len(infos),
                "uncompressed_bytes": total_uncompressed,
            }
            analysis.structure.setdefault("archives", []).append(archive_info)
            for info in infos[: settings.max_archive_entries]:
                analysis.objects.append({"kind": "archive_entry", "name": info.filename[:512], "size": info.file_size})
                if info.filename.lower().endswith("vbaproject.bin"):
                    analysis.indicators.append({"type": "office_macro", "path": info.filename[:512]})
                if depth < settings.max_archive_depth and info.file_size <= settings.static_max_scan_bytes:
                    try:
                        child = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    if child.startswith(b"PK"):
                        if depth + 1 > settings.max_archive_depth:
                            findings.append(
                                FindingSpec(
                                    type="structural_archive_limit",
                                    value="max_depth",
                                    source=self.name,
                                    analyzer_version=self.version,
                                    severity=Severity.HIGH,
                                    confidence=0.95,
                                    evidence={"depth": depth + 1, "max_depth": settings.max_archive_depth, "entry": info.filename[:512]},
                                    tags=["m4", "structural", "archive", "limit"],
                                )
                            )
                        else:
                            findings.extend(self._scan_zip(child, analysis, depth + 1))

            too_large = total_uncompressed > settings.max_archive_uncompressed_mb * 1024 * 1024
            too_compressed = total_uncompressed > settings.max_archive_ratio * max(1, len(data))
            if len(infos) > settings.max_archive_entries or too_large or too_compressed:
                findings.append(
                    FindingSpec(
                        type="structural_archive_limit",
                        source=self.name,
                        analyzer_version=self.version,
                        severity=Severity.HIGH,
                        confidence=0.95,
                        evidence={"archive": archive_info, "limits": {"max_entries": settings.max_archive_entries, "max_ratio": settings.max_archive_ratio, "max_uncompressed_mb": settings.max_archive_uncompressed_mb}},
                        tags=["m4", "structural", "archive", "limit"],
                    )
                )
            if depth > 0:
                findings.append(
                    FindingSpec(
                        type="structural_nested_archive",
                        value=f"depth={depth}",
                        source=self.name,
                        analyzer_version=self.version,
                        severity=Severity.INFO,
                        confidence=1.0,
                        evidence=archive_info,
                        tags=["m4", "structural", "archive"],
                    )
                )
        return findings

    def _office(self, data: bytes, path: Path, analysis: FileAnalysis) -> list[FindingSpec]:
        if b"vbaProject.bin" not in data and b"VBAProject" not in data and not data.startswith(b"\xd0\xcf\x11\xe0"):
            return []
        analysis.structure["office"] = {"macro_markers": True}
        findings = [
            FindingSpec(
                type="structural_office_macro",
                source=self.name,
                analyzer_version=self.version,
                severity=Severity.MEDIUM,
                confidence=0.85,
                evidence={"markers": ["vbaProject.bin", "VBAProject"], "static_only": True},
                tags=["m4", "structural", "office", "macro"],
            )
        ]
        try:
            from oletools.olevba import VBA_Parser

            parser = VBA_Parser(str(path))
            try:
                if parser.detect_vba_macros():
                    analysis.features["oletools_vba_detected"] = True
            finally:
                parser.close()
        except Exception:
            analysis.features["oletools_vba_detected"] = False
        return findings
