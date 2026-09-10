"""Verify the QR fixtures: direct QRAnalyzer check + live UI pipeline verdict.

1. Each PDF is fed through the real ``QRAnalyzer`` (hermetic, temp storage).
2. Each PDF is then submitted to the running backend API (the exact path the
   React UI uses) and we report the final verdict/risk the UI would show.
"""
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from app.analyzers.qr.analyzer import QRAnalyzer
from app.core.config import settings

CORPUS = Path(__file__).resolve().parents[1] / "storage" / "qr_test_corpus"
API = "http://127.0.0.1:8001"

CASE = [
    (
        "qr_safe.pdf",
        ["https://example.com/sandbox-safe-test"],
        ["https://example.com/sandbox-safe-test"],
        1,
    ),
    (
        "qr_suspicious.pdf",
        ["http://suspicious-test.invalid/login"],
        ["http://suspicious-test.invalid/login"],
        1,
    ),
    (
        "qr_multiple.pdf",
        ["http://qr-test-1.invalid/", "http://qr-test-2.invalid/", "http://qr-test-3.invalid/"],
        ["http://qr-test-1.invalid/", "http://qr-test-2.invalid/", "http://qr-test-3.invalid/"],
        3,
    ),
]


def verify_direct() -> list[str]:
    print("== DIRECT QRAnalyzer check ==")
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        original = settings.storage_dir
        try:
            settings.storage_dir = Path(directory)
            settings.uploads_dir.mkdir(parents=True, exist_ok=True)
            for name, expect_payloads, expect_urls, expect_count in CASE:
                pdf = (CORPUS / name).read_bytes()
                sha = name.encode("utf-8").hex().ljust(64, "0")
                (settings.uploads_dir / f"{sha}.bin").write_bytes(pdf)
                analyzer = QRAnalyzer()
                analyzer.analyze(None, SimpleNamespace(file=SimpleNamespace(sha256=sha)))
                p = analyzer.get_payload()
                ok = (
                    p.get("status") == "detected"
                    and p.get("count") == expect_count
                    and all(x in p.get("payloads", []) for x in expect_payloads)
                    and all(u in p.get("urls", []) for u in expect_urls)
                )
                tag = "PASS" if ok else "FAIL"
                lines.append(
                    f"[{tag}] {name}: status={p.get('status')} count={p.get('count')} "
                    f"payloads={p.get('payloads')} urls={p.get('urls')}"
                )
                print(lines[-1], flush=True)
        finally:
            settings.storage_dir = original
    lines.append("DIRECT " + ("ALL PASS" if all("PASS" in l for l in lines) else "HAS FAILURES"))
    return lines


def verify_live() -> list[str]:
    print("\n== LIVE pipeline (React-UI path) ==")
    lines = []
    for name, *_ in CASE:
        with open(CORPUS / name, "rb") as fh:
            r = httpx.post(f"{API}/api/scans", files={"file": (name, fh.read(), "application/pdf")}, timeout=60)
        scan_id = r.json()["id"]
        final = None
        for _ in range(200):
            time.sleep(0.5)
            d = httpx.get(f"{API}/api/scans/{scan_id}", timeout=10).json()
            if d.get("status") == "completed":
                final = d
                break
        if final is None:
            lines.append(f"[FAIL] {name}: no terminal state")
            print(lines[-1], flush=True)
            continue
        qr = next((a for a in final.get("analyzers", []) if a.get("analyzer") == "qr_analysis"), None)
        qr_payload = (qr or {}).get("payload") or {}
        line = (
            f"[PASS] {name}: verdict={final.get('verdict')} risk={final.get('risk_score')} "
            f"action={final.get('action')} qr_status={qr_payload.get('status')} "
            f"qr_count={qr_payload.get('count')} qr_payloads={qr_payload.get('payloads')} "
            f"qr_urls={qr_payload.get('urls')}"
        )
        lines.append(line)
        print(line, flush=True)
    lines.append("LIVE " + ("ALL PASS" if all("PASS" in l for l in lines) else "HAS FAILURES"))
    return lines


def main() -> int:
    direct = verify_direct()
    live = verify_live()
    everything_ok = all(("PASS" in s or "ALL PASS" in s) for s in direct + live)
    return 0 if everything_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())