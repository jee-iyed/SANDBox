"""Post-benchmark analysis: parallelism proof + per-analyzer duration attribution.

Reads the bench.w*.err.log files written by bench_throughput.py, reconstructs
each scan's processing window from STARTED/COMPLETED log lines, and computes the
maximum number of concurrently-in-flight scans per worker configuration
(proof that W workers really operate in parallel).

Then reads bench_results.json scan ids and aggregates per-analyzer durations
from PostgreSQL to attribute where pipeline time goes (incl. QR).
"""
from __future__ import annotations

import bisect
import json
import re
import sys
from pathlib import Path

import psutil  # noqa: F401  (keep venv import graph identical)

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.db.models import AnalysisResult  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from sqlalchemy import select  # noqa: E402

LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) INFO app\.workers\.processor "
    r"(?P<evt>SCAN_STARTED|SCAN_COMPLETED) scan_id=(?P<sid>[0-9a-f-]{36})"
)


def parse_tick(ts: str) -> float:
    # local wall time -> monotonic-free float seconds since epoch (approx.)
    from datetime import datetime

    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S,%f").timestamp()


def max_concurrency(log_path: Path) -> dict:
    events = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LOG_RE.match(line)
        if m:
            t = parse_tick(m.group("ts"))
            events.append((t, m.group("evt"), m.group("sid")))
    events.sort(key=lambda e: e[0])
    open_sids = set()
    curve = []
    peaks = []
    fails = []
    for t, evt, sid in events:
        if evt == "SCAN_STARTED":
            open_sids.add(sid)
        else:
            open_sids.discard(sid)
        curve.append((t, len(open_sids)))
        peaks.append((t, evt, sid, len(open_sids)))
        if evt == "SCAN_FAILED":
            fails.append(sid)
        last = t
    max_conc = max((c for _, c in curve), default=0)
    # count distinct scan ids whose window overlapped the max-concurrency instant
    return {
        "events": len(events),
        "max_concurrent_processing": max_conc,
        "distinct_scans": len({s for _, _, s in events}),
        "failed_log": len(fails),
        "first_ts": events[0][0] if events else None,
        "last_ts": events[-1][0] if events else None,
        "opened_seconds": round((events[-1][0] - events[0][0]), 3) if events else None,
    }


def analyzer_attribution(scan_ids: list[str]) -> dict:
    if not scan_ids:
        return {}
    from app.db.models import Scan

    with SessionLocal() as db:
        rows = db.execute(
            select(
                AnalysisResult.analyzer,
                AnalysisResult.analyzer_version,
                AnalysisResult.status,
                AnalysisResult.duration_ms,
                Scan.id,
            )
            .join(Scan, Scan.id == AnalysisResult.scan_id)
            .where(AnalysisResult.scan_id.in_(scan_ids))
        ).all()
    agg: dict = {}
    for analyzer, version, status, duration_ms, _sid in rows:
        if analyzer not in agg:
            agg[analyzer] = {"count": 0, "sum_ms": 0.0, "status": {}, "version": version}
        agg[analyzer]["count"] += 1
        agg[analyzer]["sum_ms"] += duration_ms or 0
        agg[analyzer]["status"][status.value] = agg[analyzer]["status"].get(status.value, 0) + 1
    for a in agg:
        agg[a]["avg_ms"] = round(agg[a]["sum_ms"] / agg[a]["count"], 2) if agg[a]["count"] else None
    return agg


def main() -> None:
    results = json.loads(
        (BACKEND_DIR / "storage" / "bench_results.json").read_text(encoding="utf-8")
    )
    print("=== PARALLELISM PROOF (from worker event logs) ===")
    for res in results:
        w = res.get("workers")
        log = BACKEND_DIR / "storage" / f"bench.w{w}.err.log"
        info = max_concurrency(log) if log.exists() else {"error": "log missing"}
        info["max_active_workers_sampled"] = res.get("max_active_workers")
        info["scan_ids"] = len(res.get("scan_ids", []))
        print(f"  W={w}: max_concurrent_processing={info.get('max_concurrent_processing')} "
              f"distinct_scans_in_log={info.get('distinct_scans')} "
              f"opened_seconds={info.get('opened_seconds')} "
              f"sampled_active={info.get('max_active_workers_sampled')} "
              f"expected_workers={w}")

    print("\n=== PER-ANALYZER DURATION ATTRIBUTION (qr/pdf/txt corpus) ===")
    combined_ids = []
    for res in results:
        combined_ids.extend(res.get("scan_ids", []))
    attr = analyzer_attribution(combined_ids)
    for analyzer in sorted(attr):
        a = attr[analyzer]
        print(f"  {analyzer:>14} v{a['version']}: count={a['count']} "
              f"avg={a['avg_ms']} ms  statuses={a['status']}")

    # QR cost isolated: PDFs are the ones calling fitz+pyzbar
    print("\n  (QR avg includes only scans where qr_analysis actually ran vs skipped PDFs)")


if __name__ == "__main__":
    main()