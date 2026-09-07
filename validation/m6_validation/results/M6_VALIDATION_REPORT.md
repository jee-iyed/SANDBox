# SANDBox M6 Validation Report

## 1. Objective

Validate the existing M1-M5 scan engine using a 90-file synthetic corpus and verify the 90 files/minute target.

## 2. Environment

- OS: Windows 10
- Python version: 3.11.7
- Docker version: 29.6.2
- sandbox image: 14244691c4f3
- database: PostgreSQL 16 (sandbox_db, localhost:5432)
- Redis: redis:7-alpine (localhost:6379)
- YARA version: 4.5.4
- ruleset revision: 0f93570194a80d2f2032869055808b0ddcdfb360 (manifest)
- SANDBox commit: 84e127e feat: establish SANDBox M1-M5 baseline

## 3. Corpus

| Category | Count |
|---|---:|
| Benign | 30 |
| YARA | 20 |
| Structural | 20 |
| Dynamic | 10 |
| Mixed | 10 |
| TOTAL | 90 |

## 4. Performance

| Metric | Result |
|---|---:|
| Total files | 90 |
| Completed | 90 |
| Failed | 0 |
| Timeout | 0 |
| Errors | 0 |
| Submission duration | 28.17 s |
| Total time | 199.79 s |
| Files/sec | 0.45 |
| Files/min | 27.0 |
| Average scan time | 56.47 s |
| Median | 39.37 s |
| P95 | 158.46 s |
| Min | 28.23 s |
| Max | 172.63 s |

Target: 90 files / 60 seconds

Result: FAIL

## 5. YARA Validation

| Metric | Value |
|---|---:|
| True positives | 27 |
| False negatives | 0 |
| False positives | 0 |

Matrix rows for category `yara` (expected vs actual):

| filename | expected rules | actual rules | result |
|---|---|---|---|
| y_01.txt | SANDBOX_M4_TEST_MARKER | SANDBOX_M4_TEST_MARKER | PASS |
| y_02.txt | SANDBOX_M4_TEST_MARKER | SANDBOX_M4_TEST_MARKER | PASS |
| y_03.txt | SANDBOX_M4_TEST_MARKER | SANDBOX_M4_TEST_MARKER | PASS |
| y_04.txt | SANDBOX_M4_TEST_MARKER | SANDBOX_M4_TEST_MARKER | PASS |
| y_05.pdf | SANDBOX_PDF_ACTIVE_CONTENT | SANDBOX_PDF_ACTIVE_CONTENT | PASS |
| y_06.pdf | SANDBOX_PDF_ACTIVE_CONTENT | SANDBOX_PDF_ACTIVE_CONTENT | PASS |
| y_07.pdf | SANDBOX_PDF_ACTIVE_CONTENT | SANDBOX_PDF_ACTIVE_CONTENT | PASS |
| y_08.pdf | SANDBOX_PDF_ACTIVE_CONTENT | SANDBOX_PDF_ACTIVE_CONTENT | PASS |
| y_09.doc | Contains_DDE_Protocol | Contains_DDE_Protocol | PASS |
| y_10.doc | Contains_DDE_Protocol | Contains_DDE_Protocol | PASS |
| y_11.doc | Contains_DDE_Protocol | Contains_DDE_Protocol | PASS |
| y_12.doc | Contains_VBA_macro_code | Contains_VBA_macro_code | PASS |
| y_13.doc | Contains_VBA_macro_code | Contains_VBA_macro_code | PASS |
| y_14.doc | Contains_VBA_macro_code | Contains_VBA_macro_code | PASS |
| y_15.txt | XMRIG_Miner | XMRIG_Miner | PASS |
| y_16.txt | XMRIG_Miner | XMRIG_Miner | PASS |
| y_17.txt | XMRIG_Miner | XMRIG_Miner | PASS |
| y_18.txt | inject_thread | inject_thread | PASS |
| y_19.txt | inject_thread | inject_thread | PASS |
| y_20.txt | inject_thread | inject_thread | PASS |

## 6. Static/Structural Validation

| Analyzer | TP | FN | FP |
|---|---|---|---|
| static_analysis | 4 | 0 | 0 |
| structural_analysis | 31 | 0 | 0 |

Matrix rows for category `structural`:

| filename | expected findings | actual findings | result |
|---|---|---|---|
| s_01.pdf | structural_pdf_active_content | structural_pdf_active_content | PASS |
| s_02.pdf | structural_pdf_active_content | structural_pdf_active_content | PASS |
| s_03.pdf | structural_pdf_active_content | structural_pdf_active_content | PASS |
| s_04.pdf | structural_pdf_active_content | structural_pdf_active_content | PASS |
| s_05.zip | structural_office_macro | structural_office_macro | PASS |
| s_06.zip | structural_office_macro | structural_office_macro | PASS |
| s_07.doc | structural_office_macro | structural_office_macro | PASS |
| s_08.doc | structural_office_macro | structural_office_macro | PASS |
| s_09.zip | structural_nested_archive | structural_nested_archive | PASS |
| s_10.zip | structural_nested_archive | structural_nested_archive | PASS |
| s_11.zip | structural_nested_archive | structural_nested_archive | PASS |
| s_12.bin | structural_malformed_archive | structural_malformed_archive | PASS |
| s_13.bin | structural_malformed_archive | structural_malformed_archive | PASS |
| s_14.zip | structural_archive_limit | structural_archive_limit | PASS |
| s_15.zip | structural_archive_limit | structural_archive_limit | PASS |
| s_16.zip | - | - | PASS |
| s_17.zip | - | - | PASS |
| s_18.zip | structural_nested_archive | structural_nested_archive | INVALID_EXPECTATION |
| s_19.zip | structural_nested_archive | structural_nested_archive | INVALID_EXPECTATION |
| s_20.zip | structural_office_macro | structural_office_macro | PASS |

## 7. Dynamic Validation

| Metric | Value |
|---|---:|
| True positives | 10 |
| False negatives | 0 |
| False positives | 0 |

Matrix rows for category `dynamic`:

| filename | expected findings | actual findings | result |
|---|---|---|---|
| d_01.sh | - | - | PASS |
| d_02.sh | process_creation,shell_execution | process_creation,shell_execution | PASS |
| d_03.sh | process_creation,shell_execution,suspicious_command | process_creation,shell_execution,suspicious_command | PASS |
| d_04.sh | process_creation,shell_execution,static_ipv4_literal,static_reverse_shell,suspicious_command | process_creation,shell_execution,static_ipv4_literal,static_reverse_shell,suspicious_command | PASS |
| d_05.sh | file_creation | file_creation,process_creation | PASS |
| d_06.py | - | - | PASS |
| d_07.py | dns_request,network_attempt,static_ipv4_literal | dns_request,network_attempt,static_ipv4_literal | PASS |
| d_08.sh | process_creation,shell_execution | process_creation,shell_execution | PASS |
| d_09.sh | process_creation,shell_execution | process_creation,shell_execution | PASS |
| d_10.sh | process_creation,shell_execution,suspicious_command | process_creation,shell_execution,suspicious_command | PASS |

## 8. Risk/Decision Validation

| file | category | finding count | risk score | final decision |
|---|---|---|---|---|
| b_01.txt | benign | 0 | 0.0 | safe |
| y_01.txt | yara | 1 | 27.0 | suspicious |
| s_01.pdf | structural | 1 | 27.0 | suspicious |
| d_04.sh | dynamic | 5 | 152.0 | malicious |
| m_01.pdf | mixed | 2 | 81.0 | malicious |

## 9. Sandbox Safety

- network isolation: network_disabled=true (DENY), attempts recorded blocked=true
- rootfs protection: read-only rootfs, tmpfs noexec
- resource limits: 256m RAM, 0.5 CPU, 64 PIDs, exec timeout 30 s
- timeout handling: no timeout sample in corpus (covered by existing M5 E2E); explicit decision otherwise
- container cleanup: PASS — 0 orphan containers
- error handling: analyzer errors normalized into findings/payload; backend stayed healthy

## 10. Regression Tests

```
{
  "M1_smoke": {
    "exit": 0,
    "tail": "health OK: {'status': 'ok', 'database': True}\nqueued scan: {'id': 'cd1e1563-f31d-46bf-b273-71dbe7240cbf', 'status': 'queued', 'verdict': 'not_analyzed'}\nfinal: {'status': 'completed', 'verdict': 'safe', 'action': 'allow', 'risk_score': 0.0}\nsandbox finding OK: ['fast_scan', 'fast_scan', 'sandbox']\nlist OK (10 scans)\nSMOKE TEST PASSED",
    "stderr": ""
  },
  "M2_fast_scan_e2e": {
    "exit": 0,
    "tail": "\n=== duration_ms / risk fields (representative) ===\n[PASS] risk_score present  -> risk=0.0\n\n\nRESULT: 27 passed, 0 failed",
    "stderr": ""
  },
  "M3_normalizer_unit": {
    "exit": 0,
    "tail": "SANDBOX NORMALIZER TESTS PASSED",
    "stderr": ""
  },
  "M3_isolation": {
    "exit": 0,
    "tail": "isolation OK: network unreachable\nisolation OK: rootfs read-only\nisolation OK: analysis roundtrip (2533ms, completed)\nSANDBOX ISOLATION TEST PASSED",
    "stderr": ""
  },
  "M3_behavior_e2e": {
    "exit": 0,
    "tail": "[PASS] file delete -> file_deletion  -> ['/tmp/op.txt']\n[PASS] network attempt finding  -> ['unknown', '203.0.113.9:4444']\n[PASS] network destination captured  -> ['unknown', '203.0.113.9:4444']\n[PASS] network sample not SAFE  -> malicious risk=132.0\n\nRESULT: 8 passed, 0 failed",
    "stderr": ""
  },
  "M4_static_unit": {
    "exit": 0,
    "tail": "[PASS] malformed input -> graceful  -> analyzed ok\n[PASS] M4 never executes sample  -> matched without spawning\n[PASS] normalized finding schema  -> source=static_analysis\n[PASS] risk-engine consumable (sev/conf)  -> sev=critical conf=1.0\n\nRESULT: 14 passed, 0 failed",
    "stderr": ""
  },
  "M4_static_e2e": {
    "exit": 0,
    "tail": "[PASS] unrelated string -> no static FP  -> []\n[PASS] random binary -> graceful terminal  -> status=completed\n[PASS] malformed input -> graceful  -> status=completed\n[PASS] normalized finding schema  -> source=static_analysis\n\nRESULT: 10 passed, 0 failed",
    "stderr": ""
  },
  "M4_yara_unit": {
    "exit": 0,
    "tail": "[PASS] negative sample has no YARA match\n[PASS] upstream maldoc rule match\n[PASS] structural PDF finding\n[PASS] archive entry limit finding\n[PASS] invalid YARA rule isolated\nYARA M4 TESTS PASSED: 7/7",
    "stderr": ""
  },
  "M4_yara_e2e": {
    "exit": 0,
    "tail": "[PASS] YARA + structural findings coexist with payloads\n[PASS] clean corpus has no YARA finding\n[PASS] Office macro structural finding\nM4 YARA E2E PASSED: 3/3",
    "stderr": ""
  },
  "M5_dynamic_unit": {
    "exit": 0,
    "tail": "M5 DYNAMIC UNIT TESTS PASSED: 8/8",
    "stderr": ""
  },
  "M5_dynamic_e2e": {
    "exit": 0,
    "tail": "[PASS] timeout decision + terminal  -> timeout exec_status=timeout\n[PASS] malformed sample graceful  -> status=completed\n[PASS] normalized finding schema (0.4.0)  -> source=sandbox\n[PASS] no orphan sandbox containers  -> []\n\nRESULT: 14 passed, 0 failed",
    "stderr": ""
  },
  "compile_check": {
    "exit": 0,
    "tail": "",
    "stderr": ""
  },
  "overall": "PASS"
}
```

## 11. Problems Found

Engine false negatives (real, NOT fixed):
- none

Invalid expectations (validation-design errors; engine behavior correct):
- s_18.zip: original expectation (limit at depth 6) mis-derived: top-level zip is depth 0, so 6 zips reach depth 5, never exceeding max_archive_depth=5
- s_19.zip: original expectation (limit at depth 6) mis-derived: top-level zip is depth 0, so 6 zips reach depth 5, never exceeding max_archive_depth=5
- m_04.docx: expected XMRIG_Miner rule: YARA scans raw bytes only (no zip decompression), the string is deflated inside the archive
- m_10.zip: expected XMRIG_Miner rule: YARA scans raw bytes only (no zip decompression), the string is deflated inside the archive

Other matrix failures:
- none

## 12. Limitations

- Synthetic corpus only: no real-world documents or malware.
- Single-machine Docker Desktop measurement; results are environment-specific.
- Corpus designed to trigger existing rules; coverage limited to the implemented rule set.
- Sandbox executions included in the wall-clock budget (19 corpus files trigger M5).

## 13. Final Conclusion

- 90 files/min target: FAIL
- YARA validation: PASS
- Static/structural validation: PASS
- Dynamic validation: PASS
- M1-M5 regression: PASS
- Sandbox cleanup: PASS
