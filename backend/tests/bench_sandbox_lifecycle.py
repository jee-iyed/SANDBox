"""Sandbox (M3/M5) lifecycle overhead measurement with real Docker runs.

Uploads a handful of executable samples through the full pipeline and measures
wall-clock completion latency per sample. Purpose: quantify how the Docker
sandbox lifecycle dominates end-to-end latency for executables (the documented
pipeline bottleneck), WITHOUT weakening any sandbox security control.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from tests.bench_throughput import (  # noqa: E402
    start_backend,
    stop_backend,
    wait_health,
)

API = "http://127.0.0.1:8001"

SAMPLES = [
    ("benign-sh.sh", "#!/bin/sh\necho hello-sandbox-bench\n"),
    ("loop-sh.sh", "#!/bin/sh\nfor i in 1 2 3 4 5; do echo tick-$i; sleep 1; done\n"),
    ("curl-sh.sh", "#!/bin/sh\ncurl -sS http://example.com/invoke\n"),
    ("dns-sh.sh", "#!/bin/sh\nnslookup bench.example.com || true\n"),
    ("writer-sh.sh", "#!/bin/sh\nmkdir -p /tmp/bench && echo data > /tmp/bench/out.txt\n"),
    ("sleep-medium.sh", "#!/bin/sh\nsleep 8; echo done\n"),
]


def run() -> None:
    proc = start_backend(3, "sandboxbench")
    try:
        if not wait_health():
            print("backend health timeout")
            return
        rows = []
        for name, data in SAMPLES:
            t0 = time.perf_counter()
            r = httpx.post(
                f"{API}/api/scans", files={"file": (name, data, "text/x-sh")},
                timeout=30,
            )
            scan_id = r.json()["id"]
            elapsed = time.perf_counter() - t0
            # poll until terminal
            detail = None
            for _ in range(240):
                detail = httpx.get(f"{API}/api/scans/{scan_id}", timeout=5).json()
                if detail["status"] in ("completed", "failed"):
                    break
                time.sleep(0.25)
            wall_end = time.perf_counter()
            sandbox_res = next(
                (a for a in detail.get("analysis_results", []) if a["analyzer"] == "sandbox"),
                None,
            )
            payload = (sandbox_res or {}).get("payload") or {}
            rows.append(
                {
                    "file": name,
                    "verdict": detail.get("verdict"),
                    "risk": detail.get("risk_score"),
                    "submit_wall_s": round(elapsed, 3),
                    "complete_wall_s": round(wall_end - t0, 3),
                    "sandbox_duration_ms": (sandbox_res or {}).get("duration_ms"),
                    "exec_status": payload.get("exec_status"),
                    "decision": payload.get("decision"),
                    "exit_code": payload.get("exit_code"),
                    "sandbox_id": payload.get("sandbox_id"),
                    "event_count": len(payload.get("events", []) or []),
                }
            )
            print(json.dumps(rows[-1]))
        print("\n=== sandbox lifecycle summary ===")
        total = sum(x["complete_wall_s"] for x in rows)
        print(f"samples={len(rows)} total_wall_s={round(total, 2)} "
              f"avg_per_file_s={round(total / len(rows), 2)}")
    finally:
        stop_backend(proc)


if __name__ == "__main__":
    run()