"""Micro-benchmark for the Fast Scan analyzer (M2).

Goal: show whether the fast-scan byte path stays around the <20ms TARGET (the
brief names <20ms as a benchmark target, not a hard guarantee - see DECISIONS.md).

Two measurements on several file sizes:
  A) PURE ANALYSIS : bytes already in memory -> magic + entropy + signatures
  B) READ + ANALYSIS: disk read of {sha256}.bin -> same computation path

Because the analyzer reads a bounded sample (FAST_SAMPLE_BYTES), B's cost should
stay flat whatever the file size - that is the expected/desirable result.

Run:
    .\\.venv\\Scripts\\python.exe scripts\\benchmark_fast_scan.py
"""

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analyzers.fast_scan.analyzer import FastScanAnalyzer  # noqa: E402
from app.analyzers.fast_scan.entropy import shannon_entropy  # noqa: E402
from app.analyzers.fast_scan.magic import detect  # noqa: E402
from app.analyzers.fast_scan.signatures import scan_sample  # noqa: E402
from app.core.config import settings  # noqa: E402

TARGET_MS = 20.0
SIZES_BYTES = [4 * 1024, 100 * 1024, 1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024]
ITERS = 200
_SAMPLE_BYTES = 8192  # must match FastScanAnalyzer.FAST_SAMPLE_BYTES

_PDF_HEAD = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n"
_ZIP_HEAD = b"\x50\x4b\x03\x04" + b"\x00" * 64


def make_content(size: int) -> bytes:
    """Deterministic content mixing a binary header + repeating payload."""
    pad = (b"abcdef0123456789" * ((size // 16) + 1))[: size - len(_PDF_HEAD)]
    return _PDF_HEAD + pad


def _measure_analysis(data: bytes) -> None:
    detect(data)
    shannon_entropy(data)
    scan_sample(data)


def fmt(ms_list: list[float]) -> str:
    d = sorted(ms_list)
    mean = statistics.mean(d)
    return (
        f"mean {mean:7.2f} | median {statistics.median(d):7.2f} | "
        f"p95 {d[int(len(d)*0.95)]:7.2f} | p99 {d[int(len(d)*0.99)]:7.2f} | "
        f"max {max(d):7.2f}"
    )


def main() -> None:
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    analyzer = FastScanAnalyzer()

    print(f"{'size':>10} | {'A pure analysis (ms)':<58} | B read+analysis (ms)")
    print("-" * 130)

    all_b_ok = True
    for size in SIZES_BYTES:
        data = make_content(size)
        path = settings.uploads_dir / f"bench_{size}.bin"
        path.write_bytes(data)

        # The real fast scan only ever works on a bounded sample (FAST_SAMPLE_BYTES).
        sample_bounded = data[: _SAMPLE_BYTES]

        # A) PURE ANALYSIS (in-memory, bounded sample) - the real fast-scan compute
        for _ in range(30):
            _measure_analysis(sample_bounded)
        a_ms: list[float] = []
        for _ in range(ITERS):
            t0 = time.perf_counter()
            _measure_analysis(sample_bounded)
            a_ms.append((time.perf_counter() - t0) * 1000.0)

        # B) read (bounded) + full analyzer path on the real file
        fs = _fake_scan(f"bench_{size}", "invoice.pdf")
        for _ in range(50):
            analyzer._load_sample(fs)
        b_ms: list[float] = []
        for _ in range(ITERS):
            t0 = time.perf_counter()
            sample = analyzer._load_sample(fs)
            _measure_analysis(sample)
            b_ms.append((time.perf_counter() - t0) * 1000.0)

        label = f"{size/1024:.0f} KB" if size < 1024 * 1024 else f"{size/(1024*1024):.0f} MB"
        print(f"{label:>10} | {fmt(a_ms):<58} | {fmt(b_ms)}", flush=True)
        if statistics.mean(b_ms) > TARGET_MS:
            all_b_ok = False

    print("-" * 130, flush=True)
    print(
        f"TARGET: < {TARGET_MS:.0f} ms (benchmark target, not a guarantee). "
        f"{'PASS' if all_b_ok else 'OVER TARGET'} on mean read+analysis.",
        flush=True,
    )


class _fake_scan:
    """Minimal stand-in exposing .file.sha256 / .file.filename for the benchmark."""

    def __init__(self, sha256: str, filename: str):
        self.file = type("F", (), {"sha256": sha256, "filename": filename})()


if __name__ == "__main__":
    main()
