"""M4 static-analysis E2E tests (async API on port 8001).

Verifies the StaticAnalyzer runs in the real pipeline (FastScan -> Static -> Sandbox),
emits normalized source=static_analysis findings, and feeds the Risk Engine without
ever executing the sample. All samples are harmless synthetic bytes - no real malware.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_static_analysis.py [base_url]
"""

import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=120)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def upload_and_wait(filename: str, content: bytes, timeout_s: float = 90.0):
    r = client.post("/api/scans", files={"file": (filename, content, "application/octet-stream")})
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


def static_findings(detail) -> list:
    return [f for f in detail.get("findings", []) if f["source"] == "static_analysis"]


# 1) Clean benign file -> no static findings, stays SAFE
d = upload_and_wait("clean.pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nnothing suspicious here\n")
report("benign -> no static findings", not static_findings(d), str([f["type"] for f in static_findings(d)]))
report("benign -> safe", d["verdict"] == "safe", f"verdict={d['verdict']} risk={d.get('risk_score')}")

# 2) Known test signature -> static finding + risk engine derives MALICIOUS
d = upload_and_wait("marker.txt", b"prefix\nDOCSEC_M4_MALWARE_TEST_MARKER\nsuffix\n")
sf = static_findings(d)
report("test signature -> finding", any(f["type"] == "static_test_malware_marker" for f in sf), str([f["type"] for f in sf]))
report("test signature -> risk engine verdict", d["verdict"] == "malicious", f"verdict={d['verdict']} risk={d.get('risk_score')}")

# 3) Suspicious command pattern -> static finding, not safe
d = upload_and_wait("suspicious.txt", b"powershell -enc JABzAD0ATgBlAHcAIAAtAE8AYgBqAGUAYwB0AA==\n")
sf = static_findings(d)
report("suspicious command -> finding", any(f["type"] == "static_powershell_encoded" for f in sf), str([f["type"] for f in sf]))
report("suspicious command -> not safe", d["verdict"] != "safe", f"verdict={d['verdict']} risk={d.get('risk_score')}")

# 4) Unrelated string -> no false positive
d = upload_and_wait("note.txt", b"hello world, this is a plain text note with no indicators\n")
report("unrelated string -> no static FP", not static_findings(d), str([f["type"] for f in static_findings(d)]))

# 5) Binary/random content -> no crash, terminal lifecycle
d = upload_and_wait("random.bin", os.urandom(3000))
report("random binary -> graceful terminal", d["status"] in ("completed", "failed"), f"status={d['status']}")

# 6) Malformed / non-UTF8 input -> graceful
d = upload_and_wait("malformed.bin", b"\x00\x01\xff\xfe\x9d" * 300 + b"\x00")
report("malformed input -> graceful", d["status"] in ("completed", "failed"), f"status={d['status']}")

# 7) Normalized finding schema for static findings
d = upload_and_wait("schema.txt", b"DOCSEC_M4_MALWARE_TEST_MARKER")
f = next((x for x in static_findings(d) if x["type"] == "static_test_malware_marker"), None)
schema_ok = (
    f is not None
    and f["source"] == "static_analysis"
    and bool(f.get("analyzer_version"))
    and f.get("severity") in ("info", "low", "medium", "high", "critical")
    and isinstance(f.get("confidence"), (int, float))
    and isinstance(f.get("evidence"), dict)
    and isinstance(f.get("tags"), list)
)
report("normalized finding schema", schema_ok, f"source={f['source'] if f else 'n/a'}")

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
