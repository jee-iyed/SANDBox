"""M4 API corpus: YARA and structural findings coexist in one scan."""

from __future__ import annotations

import io
import sys
import time
import zipfile

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=120)


def upload_wait(name: str, data: bytes) -> dict:
    response = client.post("/api/scans", files={"file": (name, data, "application/octet-stream")})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    deadline = time.time() + 90
    while time.time() < deadline:
        detail = client.get(f"/api/scans/{scan_id}").json()
        if detail["status"] in ("completed", "failed"):
            return detail
        time.sleep(0.5)
    raise AssertionError("scan did not finish")


def main() -> None:
    corpus = b"%PDF-1.7\n/JavaScript /OpenAction\nSANDBOX_M4_YARA_TEST_MARKER\n"
    detail = upload_wait("m4_corpus.pdf", corpus)
    findings = detail["findings"]
    yara = [f for f in findings if f["source"] == "yara"]
    structural = [f for f in findings if f["source"] == "structural_analysis"]
    assert any(f["value"] == "SANDBOX_M4_TEST_MARKER" for f in yara), yara
    assert any(f["type"] == "structural_pdf_active_content" for f in structural), structural
    y = next(f for f in yara if f["value"] == "SANDBOX_M4_TEST_MARKER")
    assert y["analyzer_version"].startswith("yara:4.5.4|ruleset:")
    assert y["evidence"]["ruleset_revision"] == "0f93570194a80d2f2032869055808b0ddcdfb360"
    assert isinstance(y["location"], dict)
    assert any(r["analyzer"] == "yara" and r["payload"] for r in detail["analysis_results"])
    assert any(r["analyzer"] == "structural_analysis" and set(r["payload"]) >= {"metadata", "hashes", "structure", "objects", "indicators", "features"} for r in detail["analysis_results"])
    print("[PASS] YARA + structural findings coexist with payloads")

    clean = upload_wait("m4_clean.txt", b"ordinary clean corpus sample")
    assert not [f for f in clean["findings"] if f["source"] == "yara"]
    print("[PASS] clean corpus has no YARA finding")

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"synthetic safe macro container marker")
    office = upload_wait("m4_macro.docm", archive.getvalue())
    assert any(f["type"] == "structural_office_macro" for f in office["findings"])
    print("[PASS] Office macro structural finding")
    print("M4 YARA E2E PASSED: 3/3")


if __name__ == "__main__":
    main()
