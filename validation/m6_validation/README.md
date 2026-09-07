# M6 Validation — 90-file synthetic corpus

Validation-only area for the SANDBox M1-M5 scan engine. Nothing in `backend/` is
modified by these scripts.

## Layout

- `generate_corpus.py` — builds `corpus/` (90 inert synthetic files) + `corpus_manifest.json`
- `run_benchmark.py` — submits the corpus to the REAL API (`POST /api/scans`) and records timings, findings, verdicts, payloads
- `run_regression.py` — runs the EXISTING M1-M5 test suites unmodified
- `analyze_results.py` — detection matrix, TP/FN/FP, `results/` artifacts
- `corpus/` — generated samples (benign 30 / YARA 20 / structural 20 / dynamic 10 / mixed 10)
- `results/` — `raw_scan_results.json`, `detection_matrix.csv`, `benchmark_results.json`, `regression.json`, `M6_VALIDATION_REPORT.md`## Usage

```powershell
cd "D:\SANDBox project\validation\m6_validation"
# 1) backend up (port 8001), docker + db + redis up, sandbox image built
..\..\backend\.venv\Scripts\python.exe generate_corpus.py
..\..\backend\.venv\Scripts\python.exe run_benchmark.py
..\..\backend\.venv\Scripts\python.exe run_regression.py
..\..\backend\.venv\Scripts\python.exe analyze_results.py
```

## Rules

- No real malware. All samples are inert synthetic fixtures.
- No new detection rules; only existing YARA/static/structural/M5 rules are triggered.
- M1-M5 implementation, tests, Docker configuration and rules are NOT modified.
- `corpus/supervisor_test.sh` is an extra convenience sample (inert `curl | sh` pattern) not part of
  the 90-file manifest; it exercises the M5 `suspicious_command` detection.
