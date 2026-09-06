"""M3 E2E behavioral tests for the dynamic sandbox (async API on port 8001).

Verifies that raw runtime behavior observed inside the hardened container is
normalized into source=sandbox findings and feeds risk/verdict:

  - benign script         -> completes, no behavioral findings (safe)
  - child process spawn   -> process_creation finding (source=sandbox)
  - file create/delete    -> file_creation / file_deletion findings
  - network attempt       -> network_attempt finding (blocked), elevated risk/verdict

The sandbox itself only produces evidence; risk/verdict derive from the pipeline.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_sandbox_behavior.py [base_url]
"""

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=60)

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


def upload_and_wait(filename: str, content: bytes, timeout_s: float = 60.0):
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


def sandbox_findings(detail) -> list:
    return [f for f in detail.get("findings", []) if f["source"] == "sandbox"]


BENIGN = b"#!/bin/sh\necho ok\nexit 0\n"
CHILD = b"#!/bin/sh\nsh -c 'echo child'\nexit 0\n"
FILEOP = b"#!/bin/sh\necho data > /tmp/op.txt\nrm /tmp/op.txt\nexit 0\n"
NET = b"#!/usr/local/bin/python3\nimport socket\ns=socket.socket()\ns.settimeout(3)\ntry:\n    s.connect(('203.0.113.9',4444))\nexcept Exception:\n    pass\n"

# --- benign script: completes, no behavioral findings, stays SAFE ------------
d = upload_and_wait("benign.sh", BENIGN)
report("benign lifecycle completed", d["status"] == "completed", d["status"])
sb = sandbox_findings(d)
behav = [f for f in sb if f["type"] not in ("sandbox_info", "sandbox_error")]
report("benign has no sandbox behavioral findings", not behav, [f["type"] for f in behav])

# --- child process spawn -----------------------------------------------------
d = upload_and_wait("child.sh", CHILD)
proc = [f for f in sandbox_findings(d) if f["type"] == "process_creation"]
report("child spawn -> process_creation finding", len(proc) >= 1, [p.get("value") for p in proc])

# --- file create + delete ----------------------------------------------------
d = upload_and_wait("fileop.sh", FILEOP)
created = [f for f in sandbox_findings(d) if f["type"] == "file_creation"]
deleted = [f for f in sandbox_findings(d) if f["type"] == "file_deletion"]
report("file create -> file_creation", len(created) >= 1, [f.get("value") for f in created])
report("file delete -> file_deletion", len(deleted) >= 1, [f.get("value") for f in deleted])

# --- network attempt (blocked) -> elevated risk / not SAFE --------------------
d = upload_and_wait("net.py", NET)
net = [f for f in sandbox_findings(d) if f["type"] == "network_attempt"]
report("network attempt finding", len(net) >= 1, [n.get("value") for n in net])
dest_captured = any(str(n.get("value")) not in (None, "unknown") for n in net)
report("network destination captured", dest_captured, [n.get("value") for n in net])
report("network sample not SAFE", d["verdict"] != "safe", f"{d['verdict']} risk={d.get('risk_score')}")

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
