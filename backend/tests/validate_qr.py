"""Controlled QR decoder validation: PDF -> PyMuPDF -> Pillow -> pyzbar.

Covers the five required cases:
  1. PDF without QR
  2. PDF containing exactly one QR code
  3. PDF containing a QR that encodes a URL
  4. PDF containing multiple QR codes
  5. malformed PDF (must fail closed inside the analyzer, never crash)

The chain is invoked through the real ``QRAnalyzer`` (the exact code path the
M1-M5 pipeline runs); only the DB layer is stubbed out via a scan fixture so
the validation is hermetic and reproducible.
"""
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fitz as fitz_pkg
import qrcode
from app.analyzers.qr.analyzer import QRAnalyzer
from app.core.config import settings

CASES = []


def _case(name, pdf_bytes, expected, must_contain=None, must_urls=None):
    CASES.append((name, pdf_bytes, expected, must_contain or [], must_urls or []))


def _base_pdf(page_count=1):
    doc = fitz_pkg.open()
    for _ in range(page_count):
        doc.new_page()
    return doc


def _emit(doc, payload, page=0, x=72, y=72):
    img = qrcode.make(payload, box_size=6, border=2).convert("RGB")
    import io

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    doc[page].insert_image(fitz_pkg.Rect(x, y, x + 130, y + 130), stream=buffer.read())


# 1. PDF without QR -----------------------------------------------------------
_doc = _base_pdf()
_doc[0].insert_text((72, 72), "Benign report - no QR codes inside.", fontsize=12)
_case("pdf_without_qr", _doc.tobytes(), "no_qr")

# 2. PDF with exactly one QR --------------------------------------------------
_doc = _base_pdf()
_emit(_doc, "SANDBOX-TEST-42")
_case("pdf_single_qr", _doc.tobytes(), "detected", must_contain=["SANDBOX-TEST-42"])

# 3. PDF with a QR encoding a URL ---------------------------------------------
_doc = _base_pdf()
_emit(_doc, "https://example.com/payload?x=1")
_case(
    "pdf_qr_url",
    _doc.tobytes(),
    "detected",
    must_contain=["https://example.com/payload?x=1"],
    must_urls=["https://example.com/payload?x=1"],
)

# 4. PDF with multiple QR codes (three distinct payloads on one page) ---------
_doc = _base_pdf()
_emit(_doc, "A-HUNDRED", x=72, y=72)
_emit(_doc, "https://example.com/deep/first", x=230, y=72)
_emit(_doc, "A-THIRD", x=72, y=260)
_case(
    "pdf_multi_qr",
    _doc.tobytes(),
    "detected",
    must_contain=["A-HUNDRED", "https://example.com/deep/first", "A-THIRD"],
    must_urls=["https://example.com/deep/first"],
)

# 5. malformed PDF (header + truncated junk xref/trailer) ----------------------
_malformed = b"%PDF-1.4\n" + bytes(range(256)) * 40 + b"\n%%EOF"
_case("pdf_malformed_truncated", _malformed, None)  # expect controlled error branch


def _run() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as directory:
        original = settings.storage_dir
        try:
            settings.storage_dir = Path(directory)
            settings.uploads_dir.mkdir(parents=True, exist_ok=True)
            for name, pdf_bytes, expected, contains, urls in CASES:
                sha = name.encode("utf-8").hex().ljust(64, "0")
                (settings.uploads_dir / f"{sha}.bin").write_bytes(pdf_bytes)
                scan = SimpleNamespace(file=SimpleNamespace(sha256=sha))
                analyzer = QRAnalyzer()
                findings = analyzer.analyze(None, scan)
                payload = analyzer.get_payload()
                status = payload.get("status")
                problems = []
                if expected is not None and status != expected:
                    problems.append(f"status={status!r} expected={expected!r}")
                for token in contains:
                    if token not in payload.get("payloads", []):
                        problems.append(f"payload missing {token!r}")
                for u in urls:
                    if u not in payload.get("urls", []):
                        problems.append(f"url missing {u!r}")
                if "" in (name,):
                    pass
                ok = not problems
                failures += 0 if ok else 1
                print(
                    f"[{'PASS' if ok else 'FAIL'}] {name}: "
                    f"status={status} reason={payload.get('reason')} "
                    f"count={payload.get('count')} dur_ms={payload.get('duration_ms')}"
                )
                if problems:
                    for p in problems:
                        print("        " + p)
                    print("        payload=" + str(payload)[:400])
        finally:
            settings.storage_dir = original
    if failures == 0:
        print("\nQR VALIDATION: 5/5 PASS")
    else:
        print(f"\nQR VALIDATION: {failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run())