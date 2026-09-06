"""Micro-benchmark for the Static/Signature analyzer (M4).

Measures the bounded static-analysis path (pure-Python byte/regex rules, no
execution, no network) over representative synthetic file sizes, reporting
mean / median / p95 / p99 in milliseconds.

Two measurements per size:
  A) PURE ANALYSIS : bytes already in memory -> run all rules once
  B) READ + ANALYSIS: bounded disk read of {sha256}.bin -> run all rules

Because the analyzer reads at most settings.static_max_scan_bytes, the read path
cost is flat beyond that limit - the desirable bounded-behavior result.

Run:
    .\\.venv\\Scripts\\python.exe scripts\\bench_static.py
"""

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analyzers.static.analyzer import StaticAnalyzer  # noqa: E402
from app.analyzers.static.rule import match_rule  # noqa: E402
from app.analyzers.static.rules import RULES  # noqa: E402
from app.core.config import settings  # noqa: E402

SIZES_BYTES = [4 * 1024, 100 * 1024, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024]
ITERS = 50


def make_content(size: int) -> bytes:
    pad = (b"abcdEFGH1234+/xz-." * ((size // 18) + 1))[:size]
    return pad


def _measure_analysis(data: bytes) -> None:
    for rule in RULES:
        match_rule(rule, data)


class _fake_scan:
    def __init__(self, sha256: str):
        self.file = type("F", (), {"sha256": sha256, "filename": "bench.bin"})()


def fmt(ms_list: list[float]) -> str:
    d = sorted(ms_list)
    return (
        f"mean {statistics.mean(d):8.3f} | median {statistics.median(d):8.3f} | "
        f"p95 {d[int(len(d) * 0.95)]:8.3f} | p99 {d[int(len(d) * 0.99)]:8.3f} | "
        f"max {max(d):8.3f}"
    )


def main() -> None:
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    analyzer = StaticAnalyzer()

    print(f"{'size':>9} | {'A pure analysis (ms)':<64} | B read+analysis (ms)")
    print("-" * 140)

    for size in SIZES_BYTES:
        data = make_content(size)
        bounded = data[: settings.static_max_scan_bytes]
        path = settings.uploads_dir / f"bench_static_{size}.bin"
        path.write_bytes(data)

        for _ in range(10):
            _measure_analysis(bounded)
        a_ms: list[float] = []
        for _ in range(ITERS):
            t0 = time.perf_counter()
            _measure_analysis(bounded)
            a_ms.append((time.perf_counter() - t0) * 1000.0)

        fs = _fake_scan(f"bench_static_{size}")
        for _ in range(10):
            analyzer._load_sample(fs)
        b_ms: list[float] = []
        for _ in range(ITERS):
            t0 = time.perf_counter()
            sample = analyzer._load_sample(fs)
            _measure_analysis(sample)
            b_ms.append((time.perf_counter() - t0) * 1000.0)

        label = f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.0f} MB"
        print(f"{label:>9} | {fmt(a_ms):<64} | {fmt(b_ms)}", flush=True)

    print("-" * 140, flush=True)


if __name__ == "__main__":
    main()
