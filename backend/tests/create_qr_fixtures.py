"""Create controlled QR test fixtures for the SANDBox UI validation.

Three PDFs (text + embedded QR images), written to backend/storage/qr_test_corpus/:

  qr_safe.pdf       - benign doc text + one QR https://example.com/sandbox-safe-test
  qr_suspicious.pdf - benign doc text + one QR http://suspicious-test.invalid/login
                      plus the harmless EICAR AV-test string so the Risk Engine
                      classifies it SUSPICIOUS (static_eicar_signature: LOW*0.95).
  qr_multiple.pdf   - benign doc text + 3 QR codes on one page (synthetic .invalid URLs)

Fixtures only. Real-world TLDs are intentionally avoided; only HP-invalid/test
URLs are used. Production logic and M1-M5 are not touched.

PDFs are saved with deflate=False so the EICAR marker stays as raw bytes and the
static analyzer sees it (byte-level rules).
"""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fitz
import qrcode

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

OUT_DIR = Path(__file__).resolve().parents[1] / "storage" / "qr_test_corpus"


def _emit(doc, payload, page, x, y, box=6, border=2, size=130):
    img = qrcode.make(payload, box_size=box, border=border).convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    page.insert_image(fitz.Rect(x, y, x + size, y + size), stream=buf.read())


def _new_doc():
    doc = fitz.open()
    return doc, doc.new_page()


def _save(doc, path: Path) -> None:
    doc.save(str(path), deflate=False, garbage=3)
    doc.close()


def _inject_marker(path: Path, marker: bytes) -> None:
    """Insert the test marker as a PDF comment right before %%EOF.

    Comments are ignored by parsers but keep the marker as exact raw bytes,
    which is what the byte-level static rules search.
    """
    data = path.read_bytes()
    eof = data.rfind(b"%%EOF")
    if eof == -1:
        raise RuntimeError("no %%EOF found")
    comment = b"%SANDBox-test-marker: " + marker + b"\n"
    path.write_bytes(data[:eof] + comment + data[eof:])


def build_all() -> list[Path]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. qr_safe ----------------------------------------------------------------
    doc, page = _new_doc()
    page.insert_text((72, 64), "SANDBox QR test fixture - SAFE sample.", fontsize=13)
    page.insert_text((72, 84), "Quarterly report, no anomalies detected.", fontsize=11)
    _emit(doc, "https://example.com/sandbox-safe-test", page, x=72, y=120)
    path = OUT_DIR / "qr_safe.pdf"
    _save(doc, path)

    # 2. qr_suspicious ----------------------------------------------------------
    doc, page = _new_doc()
    page.insert_text((72, 64), "SANDBox QR test fixture - SUSPICIOUS sample.", fontsize=13)
    page.insert_text((72, 84), "Marketing draft with an embedded contact QR code.", fontsize=11)
    _emit(doc, "http://suspicious-test.invalid/login", page, x=72, y=140)
    path = OUT_DIR / "qr_suspicious.pdf"
    _save(doc, path)
    _inject_marker(path, EICAR)

    # 3. qr_multiple ------------------------------------------------------------
    doc, page = _new_doc()
    page.insert_text((72, 64), "SANDBox QR test fixture - MULTIPLE QR sample.", fontsize=13)
    page.insert_text((72, 84), "This page embeds three independent test QR codes.", fontsize=11)
    _emit(doc, "http://qr-test-1.invalid/", page, x=72, y=110)
    _emit(doc, "http://qr-test-2.invalid/", page, x=230, y=110)
    _emit(doc, "http://qr-test-3.invalid/", page, x=72, y=280)
    path = OUT_DIR / "qr_multiple.pdf"
    _save(doc, path)

    return [OUT_DIR / "qr_safe.pdf", OUT_DIR / "qr_suspicious.pdf", OUT_DIR / "qr_multiple.pdf"]


def main() -> int:
    paths = build_all()
    for p in paths:
        data = p.read_bytes()
        marker = b"X5O!P%@AP[4\\PZX54" in data
        print(f"{p.name}: size={len(data)} bytes eicar_raw={marker}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())