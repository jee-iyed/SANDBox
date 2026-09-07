"""Run the M6 benchmark against the REAL SANDBox API (no bypass, no fakes).

Submits the 90-file corpus via POST /api/scans (multipart), polls GET
/api/scans/{id} until terminal, records per-file timestamps, findings, verdicts
and payloads. Collects environment info and checks sandbox container cleanup.
"""

import concurrent.futures
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
RESULTS = ROOT / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8001"
SUBMITTERS = 8
POLLERS = 16
DEADLINE = 240.0

MANIFEST = json.loads((ROOT / "corpus_manifest.json").read_text(encoding="utf-8"))


def collect_env() -> dict:
    env = {
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "hostname": platform.node(),
    }
    try:
        env["docker_version"] = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except Exception:
        env["docker_version"] = None
    try:
        env["sandbox_image_id"] = subprocess.run(
            ["docker", "images", "docscan/sandbox-runner", "--format", "{{.ID}}"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except Exception:
        env["sandbox_image_id"] = None
    try:
        import yara  # noqa: PLC0415

        env["yara_version"] = yara.__version__
    except Exception:
        env["yara_version"] = None
    try:
        git = subprocess.run(["git", "log", "--oneline", "-1"], capture_output=True, text=True, timeout=30, cwd=str(ROOT.parents[1]))
        env["git_commit"] = git.stdout.strip()
    except Exception:
        env["git_commit"] = None
    return env


def submit(client, entry):
    name = entry["filename"]
    data = (CORPUS / name).read_bytes()
    try:
        t0 = time.time()
        r = client.post("/api/scans", files={"file": (name, data, "application/octet-stream")})
        if r.status_code != 202:
            return {"filename": name, "error": f"POST {r.status_code}", "t_submit": time.time() - t0}
        return {"filename": name, "id": r.json()["id"], "t_submit": time.time() - t0, "submit_ts": time.time()}
    except Exception as exc:  # noqa: BLE001
        return {"filename": name, "error": f"exception {exc}", "t_submit": None}


def poll(client, job):
    if "error" in job:
        return {**job, "status": "error"}
    sid = job["id"]
    t_start = time.time()
    while time.time() - t_start < DEADLINE:
        try:
            d = client.get(f"/api/scans/{sid}").json()
        except Exception:
            time.sleep(0.5)
            continue
        if d["status"] in ("completed", "failed"):
            return {**job, "status": d["status"], "t_done": time.time(), "detail": d}
        time.sleep(0.5)
    return {**job, "status": "timeout", "t_done": time.time(), "detail": None}


def main():
    env = collect_env()
    health = httpx.get(f"{BASE}/api/health", timeout=10)
    print("health:", health.status_code, health.json())

    client = httpx.Client(base_url=BASE, timeout=300)
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=SUBMITTERS) as pool:
        jobs = list(pool.map(lambda e: submit(client, e), MANIFEST))
    t_submit_done = time.time()
    submit_duration = t_submit_done - t0

    with concurrent.futures.ThreadPoolExecutor(max_workers=POLLERS) as pool:
        results = list(pool.map(lambda j: poll(client, j), jobs))

    t_end = time.time()
    completed = [r for r in results if r.get("status") == "completed"]
    failed = [r for r in results if r.get("status") == "failed"]
    timed_out = [r for r in results if r.get("status") == "timeout"]
    errors = [r for r in results if r.get("status") == "error"]

    submit_ts = [r["submit_ts"] for r in results if r.get("submit_ts")]
    done_ts = [r["t_done"] for r in results if r.get("t_done")]
    total_elapsed = (max(done_ts) - min(submit_ts)) if done_ts and submit_ts else 0.0

    scan_times = sorted(r["t_done"] - r["submit_ts"] for r in results if r.get("t_done") and r.get("submit_ts"))
    pct = lambda p: scan_times[min(len(scan_times) - 1, int(len(scan_times) * p))] if scan_times else 0.0  # noqa: E731

    try:
        orphans = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=sandbox-", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip().splitlines()
    except Exception:
        orphans = ["<docker error>"]

    metrics = {
        "total_files": len(results),
        "completed": len(completed),
        "failed": len(failed),
        "timeouts": len(timed_out),
        "errors": len(errors),
        "submit_duration_s": round(submit_duration, 2),
        "total_elapsed_s": round(total_elapsed, 2),
        "throughput_files_per_second": round(len(completed) / total_elapsed, 3) if total_elapsed else 0,
        "throughput_files_per_minute": round(len(completed) / total_elapsed * 60, 1) if total_elapsed else 0,
        "avg_scan_time_s": round(sum(scan_times) / len(scan_times), 2) if scan_times else 0,
        "median_scan_time_s": round(pct(0.50), 2),
        "p95_scan_time_s": round(pct(0.95), 2),
        "min_scan_time_s": round(min(scan_times), 2) if scan_times else 0,
        "max_scan_time_s": round(max(scan_times), 2) if scan_times else 0,
    }
    print("metrics:", json.dumps(metrics, indent=2))
    print("orphan sandbox containers:", orphans)

    slim = []
    for r in results:
        row = {"filename": r["filename"], "status": r.get("status"), "t_submit": r.get("t_submit")}
        d = r.get("detail")
        if d:
            row.update(
                {
                    "verdict": d["verdict"],
                    "action": d.get("action"),
                    "risk_score": d.get("risk_score"),
                    "findings": [
                        {
                            "type": f["type"],
                            "source": f["source"],
                            "severity": f["severity"],
                            "confidence": f["confidence"],
                            "value": f.get("value"),
                            "rule": (f.get("evidence") or {}).get("rule") if isinstance(f.get("evidence"), dict) else None,
                        }
                        for f in d.get("findings", [])
                    ],
                    "analysis_results": [
                        {
                            "analyzer": a["analyzer"],
                            "status": a["status"],
                            "payload": a.get("payload"),
                        }
                        for a in d.get("analysis_results", [])
                    ],
                }
            )
        slim.append(row)

    out = {"env": env, "metrics": metrics, "scans": slim, "orphan_containers": orphans}
    (RESULTS / "raw_scan_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("wrote results/raw_scan_results.json")


if __name__ == "__main__":
    main()
