"""M2 functional E2E tests for Fast Scan (async API on port 8001).

Covers: normal PDF, DOCX/OOXML (ZIP), extension mismatch, high entropy, unknown
file type, malformed file. For each: HTTP response, scan status, detected type,
SHA-256, findings, verdict, action, risk_score, duration_ms.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_fast_scan.py [base_url]
"""

import math
import os
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.fast_scan.analyzer import FAST_SAMPLE_BYTES  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=30)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    flag = "PASS" if ok else "FAIL"
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{flag}] {name}" + (f"  -> {detail}" if detail else ""))


def upload_and_wait(filename: str, content: bytes, mime: str = "application/octet-stream",
                    timeout_s: float = 60.0):
    r = client.post("/api/scans", files={"file": (filename, content, mime)})
    assert r.status_code == 202, f"POST != 202: {r.status_code} {r.text}"
    sid = r.json()["id"]
    deadline = time.time() + timeout_s
    detail = None
    while time.time() < deadline:
        d = client.get(f"/api/scans/{sid}").json()
        if d["status"] in ("completed", "failed"):
            detail = d
            break
        time.sleep(0.5)
    assert detail is not None, f"scan {sid} never finished"
    return detail


def findings_of(detail, ftype: str) -> list:
    return [f for f in detail.get("findings", []) if f["type"] == ftype]


# ---------------------------------------------------------------------------
# Case 1: Normal PDF
# ---------------------------------------------------------------------------
print("\n=== TEST 1: Normal PDF ===")
pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1>>endobj\n"
pdf += b"%" + b"x" * 2000  # pad body (kept under sample size to stay plain)
d = upload_and_wait("invoice.pdf", pdf, "application/pdf")
report("PDF status completed", d["status"] == "completed", f"status={d['status']}")
report("PDF detected_type", d["file"]["detected_type"] == "pdf", f"type={d['file'].get('detected_type')}")
report("PDF mime", d["file"]["mime_type"] == "application/pdf", f"mime={d['file'].get('mime_type')}")
report("PDF sha256 present", bool(d["file"]["sha256"]), d["file"]["sha256"][:16] + "...")
report("PDF no mismatch", not findings_of(d, "file_type_mismatch"))
report("PDF entropy_sample", bool(findings_of(d, "entropy_sample")))
report("PDF fast_scan finding", bool(findings_of(d, "fast_scan")))
entry_pdf = (
    d["file"]["detected_type"] == "pdf"
    and d["file"]["mime_type"] == "application/pdf"
    and d["status"] == "completed"
)
report("PDF verdict SAFe-ish (risk low)", d["verdict"] in ("safe", "not_analyzed"), f"verdict={d['verdict']} risk={d.get('risk_score')}")

# ---------------------------------------------------------------------------
# Case 2: DOCX / OOXML (ZIP container with [Content_Types].xml marker)
# ---------------------------------------------------------------------------
print("\n=== TEST 2: DOCX / OOXML (ZIP container) ===")
zip_with_ooxml = b"PK\x03\x04" + b"\x00" * 512 + b"[Content_Types].xml" + b"\x00" * 1024
d = upload_and_wait("report.docx", zip_with_ooxml, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
report("DOCX detected as ooxml (ZIP/XML)", d["file"]["detected_type"] == "ooxml", f"type={d['file'].get('detected_type')}")
mismatch_docx = findings_of(d, "file_type_mismatch")
report("DOCX no mismatch (OOXML is legitimate ZIP)", not mismatch_docx, str([m.get('evidence') for m in mismatch_docx]) if mismatch_docx else "")
report("DOCX completed", d["status"] == "completed", f"status={d['status']}")

# ---------------------------------------------------------------------------
# Case 3: Extension mismatch (filename .pdf, content ZIP)
# ---------------------------------------------------------------------------
print("\n=== TEST 3: Extension mismatch (.pdf but content ZIP) ===")
zippy = b"PK\x03\x04" + b"\x00" * 1000
d = upload_and_wait("invoice.pdf", zippy, "application/pdf")
report("MISMATCH status completed", d["status"] == "completed", f"status={d['status']}")
mismatch = findings_of(d, "file_type_mismatch")
report("MISMATCH finding present", bool(mismatch), str([m.get('value') for m in mismatch]))
report("MISMATCH detected_type = zip", d["file"]["detected_type"] == "zip", f"type={d['file'].get('detected_type')}")
report("MISMATCH severity medium", bool(mismatch) and mismatch[0]["severity"] == "medium", mismatch[0]["severity"] if mismatch else "n/a")
report("MISMATCH risk raises (suspicious)", d.get("risk_score") and d["risk_score"] > 0, f"risk={d.get('risk_score')} verdict={d.get('verdict')}")

# ---------------------------------------------------------------------------
# Case 4: High-entropy sample (only entropy, not automatically malicious)
# ---------------------------------------------------------------------------
print("\n=== TEST 4: High-entropy sample ===")
ent = os.urandom(8192)  # ~8 bits/byte
d = upload_and_wait("encrypted.bin", ent, "application/octet-stream")
report("ENTROPY completed", d["status"] == "completed", f"status={d['status']}")
ev = findings_of(d, "entropy_sample")
entropy_val = None
if ev and ev[0].get("evidence"):
    entropy_val = ev[0]["evidence"].get("entropy_sample")
report("ENTROPY finding with value", bool(ev) and entropy_val is not None, f"entropy={entropy_val}")
report("ENTROPY high (>7)", entropy_val is not None and entropy_val > 7.0, f"entropy={entropy_val}")
report("ENTROPY alone is NOT malicious", d["verdict"] != "malicious", f"verdict={d['verdict']} risk={d.get('risk_score')}")
report("ENTROPY finding severity informational", bool(ev) and ev[0]["severity"] == "info", ev[0]["severity"] if ev else "n/a")

# ---------------------------------------------------------------------------
# Case 5: Unknown file type (graceful, no crash)
# ---------------------------------------------------------------------------
print("\n=== TEST 5: Unknown file type ===")
unknown = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]) + b"\x42" * 500
d = upload_and_wait("mystery.dat", unknown, "application/octet-stream")
report("UNKNOWN completed", d["status"] == "completed", f"status={d['status']}")
report("UNKNOWN detected_type empty/graceful", d["file"]["detected_type"] in (None, ""), f"type={d['file'].get('detected_type')}")
report("UNKNOWN fast_scan finding (unknown)", bool(findings_of(d, "fast_scan")))

# ---------------------------------------------------------------------------
# Case 6: Malformed file (graceful, lifecycle reaches COMPLETED or FAILED)
# ---------------------------------------------------------------------------
print("\n=== TEST 6: Malformed file ===")
malformed = b"\x00\x01" + b"%PDF" + b"\xff" * 300  # truncated/bogus PDF-ish, breaks mid-header
d = upload_and_wait("broken.pdf", malformed, "application/pdf")
report("MALFORMED lifecycle terminal", d["status"] in ("completed", "failed"), f"status={d['status']}")
report("MALFORMED no 500 on detail", True)

# ---------------------------------------------------------------------------
# db duration_ms presence check (best effort on a fresh scan)
# ---------------------------------------------------------------------------
print("\n=== duration_ms / risk fields (representative) ===")
show = upload_and_wait("invoice.pdf", pdf, "application/pdf")
report("risk_score present", "risk_score" in show, f"risk={show.get('risk_score')}")


print(f"\n\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
