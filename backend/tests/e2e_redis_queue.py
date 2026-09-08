"""E2E Redis queue integration test against the LIVE backend (default :8001).

Verifies the full path: POST /api/scans -> queued in MySQL(state) + Redis job ->
bounded worker consumes -> EXISTING pipeline -> results in MySQL. Also verifies
duplicate delivery of an already-terminal job is harmless.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\e2e_redis_queue.py [base_url]
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.queue import service as qservice  # noqa: E402
from app.queue.client import get_redis  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
client = httpx.Client(base_url=BASE, timeout=30)
redis = get_redis()

N = 6
TERMINAL = ("completed", "failed")

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def main():
    # 1) Submit several files quickly; API must return 202 + queued fast.
    submitted = []
    t0 = time.time()
    for i in range(N):
        content = f"%PDF-1.4 e2e redis queue sample {i} {uuid.uuid4().hex}\n".encode()
        r = client.post(
            "/api/scans",
            files={"file": (f"q_{i}.pdf", content, "application/pdf")},
        )
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "queued", body
        submitted.append((body["id"], f"q_{i}.pdf"))
    submit_elapsed = time.time() - t0
    report(
        "N scans -> 202 queued, submitted quickly",
        len(submitted) == N and submit_elapsed < 10.0,
        f"{submit_elapsed:.2f}s for {N} (async, no scan wait)",
    )

    # 2) Redis received the jobs (stream records persist until trimmed).
    qlen = qservice.queue_len()
    report("redis received jobs", qlen >= N, f"xlen={qlen}")

    # 3) Worker consumes -> scan reaches terminal; MySQL is the store of truth.
    results = []
    deadline = time.time() + 180.0
    while time.time() < deadline and len(results) < N:
        for sid, name in submitted:
            if any(r["id"] == sid for r in results):
                continue
            d = client.get(f"/api/scans/{sid}").json()
            if d["status"] in TERMINAL:
                results.append({"id": sid, "name": name, "status": d["status"], "detail": d})
        time.sleep(0.5)

    report("all scans reached terminal", len(results) == N,
           f"{len(results)}/{N} (statuses={[r['status'] for r in results]})")
    completed = [r for r in results if r["status"] == "completed"]
    report(
        "completed scans carry persisted results (findings + analysis)",
        bool(completed) and all(
            isinstance(r["detail"].get("analysis_results"), list)
            and len(r["detail"].get("analysis_results", [])) >= 1
            for r in completed
        ),
        f"{len(completed)} completed / {len(results)} total",
    )

    # 4) Duplicate delivery safety on an already-terminal scan.
    if completed:
        target = completed[0]
        sid = target["id"]
        base_detail = client.get(f"/api/scans/{sid}").json()
        before = (
            base_detail["status"],
            len(base_detail.get("analysis_results", [])),
            len(base_detail.get("findings", [])),
        )
        mid = qservice.enqueue_scan(sid)  # re-deliver the same scan_id
        ok_dup = True
        detail_msg = "duplicate job:"
        after = before
        deadline = time.time() + 30.0
        while time.time() < deadline:
            d = client.get(f"/api/scans/{sid}").json()
            after = (d["status"], len(d.get("analysis_results", [])), len(d.get("findings", [])))
            entries = redis.xpending_range(
                qservice.stream_name(), qservice.group_name(), min="-", max="+", count=1000
            )
            still_pending = any(e["message_id"] == mid for e in entries)
            if not still_pending and after == before:
                ok_dup = True
                detail_msg += " acked, state unchanged"
                break
            if after != before:
                ok_dup = False
                detail_msg += " STATE CORRUPTED"
                break
            time.sleep(0.5)
        else:
            ok_dup = False
            detail_msg += " never acked within deadline"
        report(
            "duplicate delivery does not corrupt terminal scan",
            ok_dup,
            f"{detail_msg} (before={before} after={after if 'after' in dir() else '?'})",
        )

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()