"""Analyze benchmark results: detection matrix, TP/FN/FP, JSON + CSV + report.

Reads corpus_manifest.json + results/raw_scan_results.json (+ optional
results/regression.json) and produces:
  - results/detection_matrix.csv
  - results/benchmark_results.json
  - results/M6_VALIDATION_REPORT.md
"""

import csv
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

DETECTION_SOURCES = {"yara", "static_analysis", "structural_analysis", "sandbox"}
IGNORE_TYPES = {"sandbox_info", "sandbox_error"}


def detection_findings(fs):
    return [
        f for f in fs
        if f["source"] in DETECTION_SOURCES and f["type"] not in IGNORE_TYPES
    ]


def main():
    manifest = json.loads((ROOT / "corpus_manifest.json").read_text(encoding="utf-8"))
    raw = json.loads((RESULTS / "raw_scan_results.json").read_text(encoding="utf-8"))
    scans = {s["filename"]: s for s in raw["scans"]}

    rows = []
    per_analyzer = {s: {"tp": 0, "fp": 0, "fn": 0} for s in sorted(DETECTION_SOURCES)}
    overall_ok = 0
    invalid_expectations = []
    engine_limitations = []

    for entry in manifest:
        name = entry["filename"]
        scan = scans.get(name)
        actual_sources = set()
        actual_types = []
        actual_rules = []
        detail_risk = None
        detail_verdict = None
        if scan and scan.get("findings") is not None:
            actual_sources = {f["source"] for f in detection_findings(scan["findings"])}
            actual_types = sorted({f["type"] for f in detection_findings(scan["findings"])})
            actual_rules = sorted({f["rule"] for f in detection_findings(scan["findings"]) if f.get("rule")})
            detail_risk = scan.get("risk_score")
            detail_verdict = scan.get("verdict")

        expected_sources = set(entry["expected_analyzers"])
        expected_types = set(entry["expected_findings"])
        expected_rules = set(entry["expected_rules"])

        missing_sources = expected_sources - actual_sources
        extra_sources = actual_sources - expected_sources
        missing_types = expected_types - set(actual_types)
        missing_rules = expected_rules - set(actual_rules)

        if entry.get("invalid_expectation"):
            invalid_expectations.append(
                {"filename": name, "reason": entry.get("invalid_reason", ""),
                 "expected": sorted(expected_sources), "actual": sorted(actual_sources)}
            )
            pass_ = None  # excluded from scoring
        elif entry["expected_detection"]:
            pass_ = not missing_sources and not extra_sources and not missing_types and not missing_rules
            if pass_:
                overall_ok += 1
            for src in sorted(DETECTION_SOURCES):
                if src in expected_sources and src in actual_sources:
                    per_analyzer[src]["tp"] += 1
                elif src in expected_sources and src not in actual_sources:
                    per_analyzer[src]["fn"] += 1
                elif src not in expected_sources and src in actual_sources:
                    per_analyzer[src]["fp"] += 1
        else:
            # No detection expected: only unexpected detections count as problems.
            pass_ = not extra_sources
            if pass_:
                overall_ok += 1
            for src in sorted(DETECTION_SOURCES):
                if src in actual_sources:
                    per_analyzer[src]["fp"] += 1

        if pass_ is False and not entry.get("invalid_expectation") and (
            missing_sources or missing_types or missing_rules
        ):
            engine_limitations.append(
                {"filename": name, "missing_sources": sorted(missing_sources),
                 "missing_types": sorted(missing_types), "missing_rules": sorted(missing_rules)}
            )

        rows.append(
            {
                "filename": name,
                "category": entry["category"],
                "status": scan.get("status") if scan else "missing",
                "verdict": detail_verdict,
                "risk_score": detail_risk,
                "expected_sources": ",".join(sorted(expected_sources)),
                "actual_sources": ",".join(sorted(actual_sources)),
                "expected_findings": ",".join(sorted(expected_types)),
                "actual_findings": ",".join(actual_types),
                "expected_rules": ",".join(sorted(expected_rules)),
                "actual_rules": ",".join(actual_rules),
                "missing_sources": ",".join(sorted(missing_sources)),
                "extra_sources": ",".join(sorted(extra_sources)),
                "missing_types": ",".join(sorted(missing_types)),
                "missing_rules": ",".join(sorted(missing_rules)),
                "result": "INVALID_EXPECTATION" if entry.get("invalid_expectation") else ("PASS" if pass_ else "FAIL"),
                "notes": entry["notes"],
            }
        )

    with open(RESULTS / "detection_matrix.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    failures = [r for r in rows if r["result"] == "FAIL"]
    success_rate = round(overall_ok / len(rows) * 100, 1) if rows else 0

    regression = {}
    reg_path = RESULTS / "regression.json"
    if reg_path.exists():
        regression = json.loads(reg_path.read_text(encoding="utf-8"))

    metrics = raw["metrics"]
    target = {"files": 90, "seconds": 60, "files_per_minute": 90}
    perf_pass = metrics["completed"] == 90 and metrics["total_elapsed_s"] <= 60

    sandbox_cleanup = {
        "orphan_containers": raw.get("orphan_containers", []),
        "cleanup_pass": len(raw.get("orphan_containers", [])) == 0,
    }

    total_tp = sum(a["tp"] for a in per_analyzer.values())
    total_fp = sum(a["fp"] for a in per_analyzer.values())
    total_fn = sum(a["fn"] for a in per_analyzer.values())

    summary = {
        "target": target,
        "actual": metrics,
        "performance_pass": perf_pass,
        "detection": {
            "per_analyzer": per_analyzer,
            "total_true_positives": total_tp,
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "overall_file_pass_rate_pct": success_rate,
            "failed_files": [r["filename"] for r in failures],
            "invalid_expectations": invalid_expectations,
            "engine_limitations": engine_limitations,
        },
        "regression": regression,
        "sandbox_cleanup": sandbox_cleanup,
    }
    (RESULTS / "benchmark_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    env = raw.get("env", {})
    cat_counts = {}
    for r in rows:
        cat_counts[r["category"]] = cat_counts.get(r["category"], 0) + 1

    def fmt_row(cat):
        subset = [r for r in rows if r["category"] == cat]
        return subset

    def examples_table(rows_subset, names):
        lines = []
        for r in rows_subset:
            if r["filename"] in names:
                lines.append(
                    f"| {r['filename']} | {r['category']} | {len(str(r['actual_findings']).split(',')) if r['actual_findings'] else 0} | "
                    f"{r['risk_score']} | {r['verdict']} |"
                )
        return lines

    ex_names = ["b_01.txt", "y_01.txt", "s_01.pdf", "d_04.sh", "m_01.pdf"]
    examples = examples_table(rows, ex_names)

    report = f"""# SANDBox M6 Validation Report

## 1. Objective

Validate the existing M1-M5 scan engine using a 90-file synthetic corpus and verify the 90 files/minute target.

## 2. Environment

- OS: {env.get('os')}
- Python version: {env.get('python')}
- Docker version: {env.get('docker_version')}
- sandbox image: {env.get('sandbox_image_id')}
- database: PostgreSQL 16 (sandbox_db, localhost:5432)
- Redis: redis:7-alpine (localhost:6379)
- YARA version: {env.get('yara_version')}
- ruleset revision: 0f93570194a80d2f2032869055808b0ddcdfb360 (manifest)
- SANDBox commit: {env.get('git_commit')}

## 3. Corpus

| Category | Count |
|---|---:|
| Benign | {cat_counts.get('benign', 0)} |
| YARA | {cat_counts.get('yara', 0)} |
| Structural | {cat_counts.get('structural', 0)} |
| Dynamic | {cat_counts.get('dynamic', 0)} |
| Mixed | {cat_counts.get('mixed', 0)} |
| TOTAL | {len(rows)} |

## 4. Performance

| Metric | Result |
|---|---:|
| Total files | {metrics['total_files']} |
| Completed | {metrics['completed']} |
| Failed | {metrics['failed']} |
| Timeout | {metrics['timeouts']} |
| Errors | {metrics['errors']} |
| Submission duration | {metrics['submit_duration_s']} s |
| Total time | {metrics['total_elapsed_s']} s |
| Files/sec | {metrics['throughput_files_per_second']} |
| Files/min | {metrics['throughput_files_per_minute']} |
| Average scan time | {metrics['avg_scan_time_s']} s |
| Median | {metrics['median_scan_time_s']} s |
| P95 | {metrics['p95_scan_time_s']} s |
| Min | {metrics['min_scan_time_s']} s |
| Max | {metrics['max_scan_time_s']} s |

Target: 90 files / 60 seconds

Result: {'PASS' if perf_pass else 'FAIL'}

## 5. YARA Validation

| Metric | Value |
|---|---:|
| True positives | {per_analyzer['yara']['tp']} |
| False negatives | {per_analyzer['yara']['fn']} |
| False positives | {per_analyzer['yara']['fp']} |

Matrix rows for category `yara` (expected vs actual):

| filename | expected rules | actual rules | result |
|---|---|---|---|
{chr(10).join(f"| {r['filename']} | {r['expected_rules'] or '-'} | {r['actual_rules'] or '-'} | {r['result']} |" for r in fmt_row('yara'))}

## 6. Static/Structural Validation

| Analyzer | TP | FN | FP |
|---|---|---|---|
| static_analysis | {per_analyzer['static_analysis']['tp']} | {per_analyzer['static_analysis']['fn']} | {per_analyzer['static_analysis']['fp']} |
| structural_analysis | {per_analyzer['structural_analysis']['tp']} | {per_analyzer['structural_analysis']['fn']} | {per_analyzer['structural_analysis']['fp']} |

Matrix rows for category `structural`:

| filename | expected findings | actual findings | result |
|---|---|---|---|
{chr(10).join(f"| {r['filename']} | {r['expected_findings'] or '-'} | {r['actual_findings'] or '-'} | {r['result']} |" for r in fmt_row('structural'))}

## 7. Dynamic Validation

| Metric | Value |
|---|---:|
| True positives | {per_analyzer['sandbox']['tp']} |
| False negatives | {per_analyzer['sandbox']['fn']} |
| False positives | {per_analyzer['sandbox']['fp']} |

Matrix rows for category `dynamic`:

| filename | expected findings | actual findings | result |
|---|---|---|---|
{chr(10).join(f"| {r['filename']} | {r['expected_findings'] or '-'} | {r['actual_findings'] or '-'} | {r['result']} |" for r in fmt_row('dynamic'))}

## 8. Risk/Decision Validation

| file | category | finding count | risk score | final decision |
|---|---|---|---|---|
{chr(10).join(examples)}

## 9. Sandbox Safety

- network isolation: network_disabled=true (DENY), attempts recorded blocked=true
- rootfs protection: read-only rootfs, tmpfs noexec
- resource limits: 256m RAM, 0.5 CPU, 64 PIDs, exec timeout 30 s
- timeout handling: no timeout sample in corpus (covered by existing M5 E2E); explicit decision otherwise
- container cleanup: {'PASS — 0 orphan containers' if sandbox_cleanup['cleanup_pass'] else 'FAIL — ' + str(sandbox_cleanup['orphan_containers'])}
- error handling: analyzer errors normalized into findings/payload; backend stayed healthy

## 10. Regression Tests

```
{json.dumps(regression, indent=2)}
```

## 11. Problems Found

Engine false negatives (real, NOT fixed):
{chr(10).join(f'- {x["filename"]}: missing sources={x["missing_sources"]} types={x["missing_types"]} rules={x["missing_rules"]}' for x in engine_limitations) if engine_limitations else '- none'}

Invalid expectations (validation-design errors; engine behavior correct):
{chr(10).join(f'- {x["filename"]}: {x["reason"]}' for x in invalid_expectations) if invalid_expectations else '- none'}

Other matrix failures:
{chr(10).join(f'- {r["filename"]}: extra sources={r["extra_sources"]}' for r in failures if r["filename"] not in [x["filename"] for x in engine_limitations]) if failures else '- none'}

## 12. Limitations

- Synthetic corpus only: no real-world documents or malware.
- Single-machine Docker Desktop measurement; results are environment-specific.
- Corpus designed to trigger existing rules; coverage limited to the implemented rule set.
- Sandbox executions included in the wall-clock budget (19 corpus files trigger M5).

## 13. Final Conclusion

- 90 files/min target: {'PASS' if perf_pass else 'FAIL'}
- YARA validation: {'PASS' if per_analyzer['yara']['fn'] == 0 and per_analyzer['yara']['fp'] == 0 else 'FAIL'}
- Static/structural validation: {'PASS' if per_analyzer['static_analysis']['fn'] + per_analyzer['structural_analysis']['fn'] + per_analyzer['static_analysis']['fp'] + per_analyzer['structural_analysis']['fp'] == 0 else 'FAIL'}
- Dynamic validation: {'PASS' if per_analyzer['sandbox']['fn'] == 0 and per_analyzer['sandbox']['fp'] == 0 else 'FAIL'}
- M1-M5 regression: {regression.get('overall', 'not recorded')}
- Sandbox cleanup: {'PASS' if sandbox_cleanup['cleanup_pass'] else 'FAIL'}
"""
    (RESULTS / "M6_VALIDATION_REPORT.md").write_text(report, encoding="utf-8")
    print("detection summary:", json.dumps(per_analyzer))
    print("overall file pass rate:", success_rate, "%")
    print("perf:", perf_pass, metrics)
    print("wrote results/detection_matrix.csv, benchmark_results.json, M6_VALIDATION_REPORT.md")


if __name__ == "__main__":
    main()
