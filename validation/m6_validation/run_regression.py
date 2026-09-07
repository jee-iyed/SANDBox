"""Run the EXISTING M1-M5 regression suites without modifying them.

Runs each suite as a subprocess with the backend venv python, records exit code
and output tail into results/regression.json (read by analyze_results.py).
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parents[1] / "backend"
PY = str(BACKEND / ".venv" / "Scripts" / "python.exe")
BASE = "http://127.0.0.1:8001"

SUITES = [
    ("M1_smoke", ["tests/smoke_test.py", BASE]),
    ("M2_fast_scan_e2e", ["tests/e2e_fast_scan.py", BASE]),
    ("M3_normalizer_unit", ["tests/test_sandbox_normalizer.py"]),
    ("M3_isolation", ["tests/test_sandbox_isolation.py"]),
    ("M3_behavior_e2e", ["tests/e2e_sandbox_behavior.py", BASE]),
    ("M4_static_unit", ["tests/test_static_analyzer.py"]),
    ("M4_static_e2e", ["tests/e2e_static_analysis.py", BASE]),
    ("M4_yara_unit", ["tests/test_yara_m4.py"]),
    ("M4_yara_e2e", ["tests/e2e_m4_yara.py", BASE]),
    ("M5_dynamic_unit", ["tests/test_dynamic_m5.py"]),
    ("M5_dynamic_e2e", ["tests/e2e_dynamic_m5.py", BASE]),
    ("compile_check", ["-m", "compileall", "-q", "app"]),
]


def run(cmd: list[str], timeout: int = 900) -> dict:
    try:
        proc = subprocess.run(
            [PY, *cmd], capture_output=True, text=True, timeout=timeout, cwd=str(BACKEND)
        )
        tail = "\n".join((proc.stdout or "").splitlines()[-6:])
        return {"exit": proc.returncode, "tail": tail[-1200:], "stderr": (proc.stderr or "")[-400:]}
    except subprocess.TimeoutExpired:
        return {"exit": -1, "tail": "TIMEOUT", "stderr": "suite exceeded time limit"}
    except Exception as exc:  # noqa: BLE001
        return {"exit": -1, "tail": "", "stderr": str(exc)}


def main():
    results = {}
    for name, cmd in SUITES:
        print(f"--- {name} ---", flush=True)
        out = run(cmd)
        results[name] = out
        print(f"exit={out['exit']}")
        print(out["tail"])
        if out["stderr"] and out["exit"] != 0:
            print("stderr:", out["stderr"])
    results["overall"] = "PASS" if all(v["exit"] == 0 for v in results.values()) else "FAIL"
    (ROOT / "results" / "regression.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("regression overall:", results["overall"])
    sys.exit(0 if results["overall"] == "PASS" else 1)


if __name__ == "__main__":
    main()
