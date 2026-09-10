"""E2E Secure File Access test against the LIVE backend (default :8001).

Verifies the gateway workflow end-to-end:
  - benign file  -> scan created -> AUTHORIZED -> /content answers (placeholder,
                    never the original bytes) and the scan went through the
                    EXISTING Redis queue.
  - suspicious file -> BLOCKED/QUARANTINED -> /content is DENIED (fail-closed).
  - 404 for unknown access, 501 for external-reference mode, 422 for path
    traversal in the access id, and the original filename is sanitized.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_secure_access.py [base_url]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.queue import service as qservice  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=120)

PASS = 0
FAIL = 0
TERMINAL = ("authorized", "blocked", "quarantined", "failed", "expired")


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def poll_access(access_id, deadline_s=120.0):
    deadline = time.time() + deadline_s
    body = None
    while time.time() < deadline:
        r = client.get(f"/api/secure-access/{access_id}")
        body = r.json()
        if r.status_code != 200:
            return r
        if body["status"] in TERMINAL:
            return r
        time.sleep(1.0)
    return r


def benign_flow():
    demo = REPO_ROOT / "demo_benign.txt"
    r = client.post(
        "/api/secure-access",
        files={"file": (demo.name, demo.read_bytes(), "text/plain")},
        headers={"x-source-token": "mail-platform-1"},
    )
    report("POST secure-access (benign) -> 202", r.status_code == 202, r.text[:200])
    if r.status_code != 202:
        return None
    body = r.json()
    access_id, scan_id = body["id"], body["scan_id"]

    # 1) secure access request created a scan + enqueued via existing Redis queue
    r2 = client.get(f"/api/scans/{scan_id}")
    report("access wraps an existing scan", r2.status_code == 200 and r2.json()["status"] in ("queued", "processing"), r2.text[:120])
    qlen = qservice.queue_len()
    report("queue used (Redis stream non-empty)", qlen >= 1, f"xlen={qlen}")

    # 2) pending/scanning state is never authorized
    if body["status"] in ("queued", "processing"):
        r3 = client.get(f"/api/secure-access/{access_id}")
        report("running access not yet authorized", r3.json().get("status") in ("scanning",), f"{r3.json().get('status')}")

    r4 = poll_access(access_id)
    final = r4.json()
    report("benign -> AUTHORIZED", r4.status_code == 200 and final.get("status") == "authorized", f"{final.get('status')}")
    report("benign verdict==safe, preview available", final.get("verdict") == "safe" and final.get("preview_available") is True, f"verdict={final.get('verdict')} risk={final.get('risk_score')}")
    report("benign original filename preserved as metadata", final.get("original_filename") == "demo_benign.txt", final.get("original_filename"))
    report("benign source identifier recorded", final.get("source_identifier") == "mail-platform-1", str(final.get("source_identifier")))

    # 3) /content authorized => controlled placeholder, never bytes
    r5 = client.get(f"/api/secure-access/{access_id}/content")
    c = r5.json()
    ok_content = (
        r5.status_code == 200
        and c.get("authorized") is True
        and c.get("content_kind") == "placeholder"
        and "preview is not yet configured" in c.get("message", "")
        and "PAYLOAD" not in c.get("message", "")
    )
    report("authorized content = placeholder (no original bytes)", ok_content, r5.text[:120])
    return access_id, scan_id


def suspicious_flow():
    demo = REPO_ROOT / "demo_suspicious.sh"
    r = client.post(
        "/api/secure-access",
        files={"file": ("../../evil.sh", demo.read_bytes(), "application/x-shellscript")},
    )
    report("POST secure-access (suspicious, traversal name) -> 202", r.status_code == 202, r.text[:200])
    if r.status_code != 202:
        return None
    body = r.json()
    access_id = body["id"]
    report("traversal filename sanitized to bare name", body["original_filename"] == "evil.sh", body["original_filename"])

    r4 = poll_access(access_id)
    final = r4.json()
    st = final.get("status")
    report("suspicious -> BLOCKED/QUARANTINED", r4.status_code == 200 and st in ("blocked", "quarantined"), st)
    report("suspicious not authorized", final.get("preview_available") is False, f"preview={final.get('preview_available')}")

    # 4) suspicious file MUST never be reachable through /content (fail-closed)
    r5 = client.get(f"/api/secure-access/{access_id}/content")
    report("suspicious /content DENIED (403)", r5.status_code == 403, r5.text[:160])
    return access_id


def error_cases():
    # 5) unknown access -> 404
    r = client.get("/api/secure-access/00000000-0000-0000-0000-000000000000")
    report("unknown access -> 404", r.status_code == 404, str(r.status_code))

    # 6) path traversal in the access id -> rejected (404 after URL normalization,
    #     or 422 from the UUID validator). Either way no access data is exposed.
    r = client.get("/api/secure-access/../../etc/passwd")
    report("path traversal in access id rejected", r.status_code in (404, 422), str(r.status_code))

    # malformed access id -> 422 (endpoint-level UUID validation)
    r = client.get("/api/secure-access/not-a-uuid")
    report("malformed access id rejected", r.status_code == 422, str(r.status_code))

    # 7) external reference mode -> 501 (not implemented, never blind fetch)
    r = client.post(
        "/api/secure-access",
        json={"source_type": "external_reference", "source_token": "tok", "filename": "invoice.pdf"},
    )
    report("external_reference -> 501 not configured", r.status_code == 501, r.text[:160])

    # 8) empty file -> 400
    r = client.post("/api/secure-access", files={"file": ("empty.txt", b"", "text/plain")})
    report("empty file -> 400", r.status_code == 400, str(r.status_code))


def main():
    benign_flow()
    suspicious_flow()
    error_cases()
    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()