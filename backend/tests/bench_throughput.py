"""Controlled throughput benchmark for the SANDBox scan pipeline.

Measures REAL completed scans (M1-M5 + QR) per worker configuration:

    WORKER_MAX_THREADS in {2,3,4,5,6,7}

The same fixed corpus is used for every run. The runner starts the backend on
:8001 with the project's venv interpreter, submits the corpus over the real API,
polls PostgreSQL until every scan reaches a terminal state, then records queue
health (XPENDING) and process CPU/memory.

No security control is disabled or weakened during any run.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psutil
from sqlalchemy import select

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.db.models import Scan, ScanStatus  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.queue.client import get_redis  # noqa: E402

CORPUS_DIR = BACKEND_DIR / "storage" / "bench_corpus"
API = "http://127.0.0.1:8001"
OUT_JSON = BACKEND_DIR / "storage" / "bench_results.json"

TOTAL_FILES = 120
TXT = 60
PDF = 40
QRPDF = 20
SUBMIT_WORKERS = 16
POLL_S = 0.15
DRAIN_TIMEOUT_S = 300
CHECKPOINT = BACKEND_DIR / "storage" / "bench_LAST_PROGRESS.txt"


def progress(msg: str) -> None:
    CHECKPOINT.write_text(f"{datetime.now(timezone.utc).isoformat()} {msg}\n", encoding="utf-8")
    print(msg, flush=True)


def build_corpus() -> list[tuple[str, bytes, int]]:
    """Generate (filename, bytes, kind) deterministically; persists between runs.

    kind: 0=text doc, 1=PDF with QR, 2=plain PDF
    """
    if CORPUS_DIR.exists():
        entries = sorted(CORPUS_DIR.iterdir())
        if entries:
            out = []
            for p in entries:
                kind = 0 if p.suffix == ".txt" else (1 if "qr" in p.name else 2)
                out.append((p.name, p.read_bytes(), kind))
            return out

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    import fitz
    import qrcode

    entries: list = []

    def txt(name: str, seed: int) -> bytes:
        lines = [f"BENCH-REPORT #{seed}", "INVOICE-NO-" + str(seed)]
        for k in range(40):
            lines.append(
                f"line {k:02d} token {seed}-{k} item description "
                f"quantity {k % 9} amount {k * 137 % 10000}.25 EUR VAT {seed % 7}"
            )
        return "\n".join(lines).encode()

    def pdf(name: str, seed: int, qr: bool) -> bytes:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text(
            (72, 72),
            f"Document {seed} - controlled benchmark fixture.",
            fontsize=12,
        )
        if qr:
            import io

            img = qrcode.make(
                f"TT-{seed}: https://example.invalid/q/{seed}", box_size=6, border=2
            ).convert("RGB")
            b = io.BytesIO()
            img.save(b, format="PNG")
            b.seek(0)
            page.insert_image(fitz.Rect(400, 400, 530, 530), stream=b.read())
        data = doc.tobytes()
        doc.close()
        return data

    for i in range(TXT):
        data = txt(f"bench_report_{i:03d}.txt", i)
        (CORPUS_DIR / f"bench_report_{i:03d}.txt").write_bytes(data)
        entries.append((f"bench_report_{i:03d}.txt", data, 0))
    for i in range(PDF):
        data = pdf(f"bench_doc_{i:03d}.pdf", i, False)
        (CORPUS_DIR / f"bench_doc_{i:03d}.pdf").write_bytes(data)
        entries.append((f"bench_doc_{i:03d}.pdf", data, 2))
    for i in range(QRPDF):
        data = pdf(f"bench_qr_{i:03d}.pdf", 1000 + i, True)
        (CORPUS_DIR / f"bench_qr_{i:03d}.pdf").write_bytes(data)
        entries.append((f"bench_qr_{i:03d}.pdf", data, 1))

    entries.sort(key=lambda e: e[0])
    return entries


def start_backend(workers: int, tag: str) -> subprocess.Popen:
    log_out = (BACKEND_DIR / "storage" / f"bench.{tag}.out.log").open("wb")
    log_err = (BACKEND_DIR / "storage" / f"bench.{tag}.err.log").open("wb")
    env = dict(os.environ)
    env["WORKER_MAX_THREADS"] = str(workers)
    env["PYTHONPYCACHEPREFIX"] = str(
        Path(os.environ.get("TEMP", ".")) / "opencode" / "pycache"
    )
    py = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    proc = subprocess.Popen(
        [str(py), "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", "8001"],
        cwd=str(BACKEND_DIR),
        env=env,
        stdout=log_out,
        stderr=log_err,
    )
    return proc


def wait_health(timeout_s=120) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = httpx.get(f"{API}/api/health", timeout=2)
            if r.status_code == 200 and r.json().get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def wait_port_free(timeout_s=30) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with socket.socket() as s:
            try:
                s.connect(("127.0.0.1", 8001))
                time.sleep(0.4)
            except OSError:
                return True
    return False


def stop_backend(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=15)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            proc.kill()
        except Exception:
            pass


def submit_all(files: list[tuple[str, bytes, int]]) -> list[dict]:
    rows: dict = {}
    lock = threading.Lock()

    def submit(item):
        name, data, kind = item
        mime = "application/pdf" if data[:5] == b"%PDF-" else "text/plain"
        t0 = time.perf_counter()
        try:
            r = httpx.post(
                f"{API}/api/scans",
                files={"file": (name, data, mime)},
                timeout=30,
            )
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code == 202:
                rows[name] = {"scan_id": r.json()["id"], "submit_ms": dt,
                              "submit_ok": True, "http": 202}
            else:
                rows[name] = {"scan_id": None, "submit_ms": dt,
                              "submit_ok": False, "http": r.status_code}
        except Exception as exc:  # noqa: BLE001
            rows[name] = {"scan_id": None, "submit_ms": 0.0,
                          "submit_ok": False, "http": str(exc)}

    with ThreadPoolExecutor(max_workers=SUBMIT_WORKERS) as pool:
        list(pool.map(lambda x: submit(x), files))
    return [rows[n] for n in sorted(rows)]


def run_worker_count(workers: int, files: list[tuple[str, bytes, int]]) -> dict:
    tag = f"w{workers}"
    proc = start_backend(workers, tag)
    result: dict = {"workers": workers}
    try:
        progress(f"w{workers}: backend launched")
        if not wait_health():
            result["error"] = "backend health timeout"
            return result
        progress(f"w{workers}: health ok")
        wm = httpx.get(f"{API}/api/system/workers", timeout=5).json()
        if wm.get("configured_workers") != workers:
            result["error"] = f"configured_workers mismatch: {wm}"
            return result
        redis_ping = get_redis().ping()

        t_start = time.perf_counter()
        sub_rows = submit_all(files)
        t_submit_end = time.perf_counter()
        progress(f"w{workers}: submission done, ok={sum(1 for r in sub_rows if r['submit_ok'])}/{len(sub_rows)}")
        submitted = [r for r in sub_rows if r["submit_ok"]]
        submitted_lat = sorted(r["submit_ms"] for r in submitted)
        n_submit_failed = len(sub_rows) - len(submitted)

        scan_ids = [r["scan_id"] for r in submitted]
        remain = set(scan_ids)
        failures = set()
        terminal = {}
        in_flight_series = []
        proc_samples: list[tuple[float, float, float]] = []
        worker_samples: list[tuple[float, int, int, int]] = []
        stop = threading.Event()

        def sample_proc():
            while not stop.is_set():
                try:
                    cpu = psutil.cpu_percent(interval=0.4)
                except psutil.Error:
                    cpu = None
                rss = None
                try:
                    rss = psutil.Process(proc.pid).memory_info().rss / (1024 * 1024)
                except psutil.Error:
                    pass
                proc_samples.append((time.time(), cpu or 0.0, rss))
                time.sleep(0.4)

        def sample_workers():
            while not stop.is_set():
                try:
                    w = httpx.get(f"{API}/api/system/workers", timeout=3).json()
                    worker_samples.append(
                        (time.time(), w.get("active_workers", 0),
                         w.get("queue_depth"), w.get("pending_jobs"))
                    )
                except Exception:
                    pass
                time.sleep(1.0)

        s1 = threading.Thread(target=sample_proc, daemon=True)
        s2 = threading.Thread(target=sample_workers, daemon=True)
        s1.start()
        s2.start()

        deadline = time.time() + DRAIN_TIMEOUT_S
        try:
            while remain and time.time() < deadline:
                time.sleep(POLL_S)
                with SessionLocal() as db:
                    pairs = db.execute(
                        select(Scan.id, Scan.status, Scan.completed_at)
                        .where(Scan.id.in_(list(remain)))
                    ).all()
                in_flight = sum(
                    1 for _, status, _ in pairs if status == ScanStatus.PROCESSING
                )
                in_flight_series.append((time.time(), in_flight))
                status_by_id = {str(r.id): (r.status, r.completed_at) for r in pairs}
                for scan_id in list(remain):
                    status, completed_at = status_by_id.get(scan_id, (None, None))
                    if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                        terminal[scan_id] = (status.value, completed_at)
                        if status == ScanStatus.FAILED:
                            failures.add(scan_id)
                        remain.discard(scan_id)
        finally:
            stop.set()
        s1.join(timeout=2)
        s2.join(timeout=2)
        progress(f"w{workers}: drain finished, terminal={len(terminal)}, incomplete={len(remain)}")

        elapsed = time.perf_counter() - t_start
        drain_phase = max(0.0, time.perf_counter() - t_submit_end)
        submit_phase = max(0.0, t_submit_end - t_start)
        n_completed = len([v for v in terminal.values() if v[0] == ScanStatus.COMPLETED.value])
        n_failed = len(failures)
        files_per_minute = n_completed / elapsed * 60 if elapsed > 0 else 0.0
        files_per_minute_drain = n_completed / drain_phase * 60 if drain_phase > 0 else 0.0

        latencies = []
        with SessionLocal() as db:
            q = select(Scan.created_at, Scan.completed_at).where(Scan.id.in_(scan_ids))
            for created_at, completed_at in db.execute(q):
                if created_at and completed_at:
                    latencies.append((completed_at - created_at).total_seconds() * 1000)
        latencies.sort()
        avg_lat = sum(latencies) / len(latencies) if latencies else None
        p95_lat = (
            latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
            if latencies else None
        )
        p50_lat = latencies[len(latencies) // 2] if latencies else None

        try:
            pend = get_redis().xpending("sandbox:scans", "sandbox:workers")
            xlen = get_redis().xlen("sandbox:scans")
        except Exception as exc:  # noqa: BLE001
            pend, xlen = str(exc), None

        peak_mem = max((r[2] for r in proc_samples if r[2] is not None), default=None)
        avg_cpu = sum(r[1] for r in proc_samples) / len(proc_samples) if proc_samples else None
        peak_inflight = max((x[1] for x in in_flight_series), default=0)
        max_active = max((w[1] for w in worker_samples), default=0)

        result.update(
            files_submitted=len(sub_rows),
            files_submitted_ok=len(submitted),
            submission_failed=n_submit_failed,
            files_completed=n_completed,
            files_failed=n_failed,
            elapsed_s=round(elapsed, 3),
            submit_phase_s=round(submit_phase, 3),
            drain_phase_s=round(drain_phase, 3),
            files_per_minute=round(files_per_minute, 1),
            files_per_minute_drain=round(files_per_minute_drain, 1),
            files_per_second=round(files_per_minute / 60, 3),
            avg_latency_ms=round(avg_lat, 1) if avg_lat is not None else None,
            p50_latency_ms=round(p50_lat, 1) if p50_lat is not None else None,
            p95_latency_ms=round(p95_lat, 1) if p95_lat is not None else None,
            xpending_pending=pend["pending"] if isinstance(pend, dict) else pend,
            xlen=xlen,
            redis_ping=bool(redis_ping),
            peak_concurrent_processing=peak_inflight,
            max_active_workers=max_active,
            peak_mem_mb=round(peak_mem, 1) if peak_mem else None,
            avg_cpu_pct=round(avg_cpu, 1) if avg_cpu is not None else None,
            submit_ms_median=round(
                sorted(submitted_lat)[len(submitted_lat) // 2], 1
            ) if submitted_lat else None,
            incomplete=len(remain),
            run_started_wall=datetime.now(timezone.utc).isoformat(),
            corpus_files=len(files),
            scan_ids=scan_ids,
        )
        progress(f"w{workers}: metrics computed, f/m={result['files_per_minute']}")
        return result
    finally:
        stop_backend(proc)
        wait_port_free()


def main() -> None:
    if len(sys.argv) > 1:
        workers_list = [int(x) for x in sys.argv[1].split(",")]
    else:
        workers_list = [2, 3, 4, 5, 6, 7]

    files = build_corpus()
    progress(f"corpus: {len(files)} files (deterministic, shared across all runs)")
    results: list[dict] = []
    for w in workers_list:
        progress(f"--- run WORKER_MAX_THREADS={w} ---")
        res = run_worker_count(w, files)
        results.append(res)
        print(json.dumps(res, indent=2), flush=True)
    (BACKEND_DIR / "storage").mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    progress(f"results saved to {OUT_JSON}")


if __name__ == "__main__":
    main()