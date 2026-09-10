"""PDF QR analyzer.

QR codes are visual content, so normal text extraction is insufficient.  This
module renders only a small, bounded page set and returns structured evidence.
It intentionally performs no network, reputation, or verdict decision.
"""

from __future__ import annotations

import io
import re
import time
from pathlib import Path

from sqlalchemy.orm import Session

from app.analyzers.base import BaseAnalyzer
from app.core.config import settings
from app.db.models import Scan
from app.findings.schema import FindingSpec

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class QRAnalyzer(BaseAnalyzer):
    name = "qr_analysis"
    version = "1.0.0"

    def __init__(self) -> None:
        self._payload: dict | None = None

    def get_payload(self) -> dict | None:
        return self._payload

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        started = time.monotonic()
        result: dict = {
            "status": "skipped", "detected": False, "count": 0,
            "payloads": [], "urls": [], "reason": None,
            "analyzer_version": self.version,
        }
        self._payload = result
        if not settings.qr_enabled:
            result["reason"] = "disabled_by_configuration"
            return []
        if scan.file is None:
            result.update(status="error", reason="file_metadata_missing")
            return []
        path = Path(settings.uploads_dir) / f"{scan.file.sha256}.bin"
        try:
            with path.open("rb") as source:
                header = source.read(5)
            if header != b"%PDF-":
                result["reason"] = "not_a_pdf"
                return []
            self._decode_pdf(path, result, started)
        except Exception as exc:  # malformed PDFs and unavailable native decoder are controlled
            result.update(status="error", reason="analysis_error", error=str(exc)[:300])
        finally:
            result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return []

    def _decode_pdf(self, path: Path, result: dict, started: float) -> None:
        try:
            import fitz
            from PIL import Image
            from pyzbar.pyzbar import decode
        except ImportError as exc:
            result.update(status="error", reason="decoder_dependency_unavailable", error=str(exc)[:300])
            return

        document = fitz.open(path)
        try:
            page_count = min(document.page_count, settings.qr_max_pages)
            seen: set[str] = set()
            for page_index in range(page_count):
                if time.monotonic() - started > settings.qr_timeout_s:
                    result.update(status="timeout", reason="processing_timeout")
                    return
                page = document.load_page(page_index)
                scale = settings.qr_render_dpi / 72
                pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
                if pixmap.width * pixmap.height > settings.qr_max_pixels:
                    result.update(status="skipped", reason="page_pixel_limit")
                    continue
                image = Image.open(io.BytesIO(pixmap.tobytes("png")))
                for code in decode(image):
                    value = code.data.decode("utf-8", errors="replace").strip()
                    if not value or value in seen:
                        continue
                    seen.add(value)
                    result["payloads"].append(value[:2048])
                    result["urls"].extend(url for url in _URL_RE.findall(value) if url not in result["urls"])
                    if len(result["payloads"]) >= settings.qr_max_codes:
                        result["detected"] = True
                        result["count"] = len(result["payloads"])
                        result.update(status="detected", reason="max_codes_reached")
                        return
            result["count"] = len(result["payloads"])
            result["detected"] = bool(result["payloads"])
            result["status"] = "detected" if result["detected"] else "no_qr"
        finally:
            document.close()
