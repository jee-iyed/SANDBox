"""M4 static-analysis unit tests (no Docker, no server, no execution).

Verifies the StaticAnalyzer detects controlled patterns, emits only normalized
findings (source=static_analysis), never executes the sample, and stays bounded.
All samples are harmless synthetic bytes - no real malware.
"""

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.static.analyzer import StaticAnalyzer  # noqa: E402
from app.core.config import settings  # noqa: E402

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


class _FakeFile:
    sha256 = ""


class _FakeScan:
    file = _FakeFile()


def run(data: bytes) -> list:
    sha = hashlib.sha256(data).hexdigest()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    path = settings.uploads_dir / f"{sha}.bin"
    path.write_bytes(data)
    try:
        scan = _FakeScan()
        scan.file.sha256 = sha
        return StaticAnalyzer().analyze(None, scan)  # type: ignore[arg-type]
    finally:
        if path.exists():
            os.remove(path)


def types(fs) -> set:
    return {f.type for f in fs}


# 1) Clean benign file -> no static findings
fs = run(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nhello world\n")
report("benign clean -> no static findings", len(fs) == 0, str(types(fs)))

# 2) Known test signature -> detected (synthetic marker, safe on-disk)
fs = run(b"DOCSEC_M4_MALWARE_TEST_MARKER")
report(
    "known test signature -> finding",
    "static_test_malware_marker" in types(fs),
    str(types(fs)),
)

# 2b) EICAR rule matches in-memory (no disk write -> avoids host AV quarantine)
from app.analyzers.static.rule import match_rule  # noqa: E402
from app.analyzers.static.rules import RULES  # noqa: E402

eicar_rule = next(r for r in RULES if r.id == "static_eicar_signature")
eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
report(
    "EICAR signature matches in-memory",
    len(match_rule(eicar_rule, eicar_bytes)) >= 1,
    "matcher-level",
)

# 3) Suspicious script/command pattern -> detected
fs = run(b"powershell.exe -enc JABzAD0ATgBlAHcAIAAtAE8AYgBqAGUAYwB0AA==\n")
report(
    "encoded powershell -> finding",
    "static_powershell_encoded" in types(fs),
    str(types(fs)),
)
fs = run(b"<script>eval(unescape('%41'))</script>")
report(
    "obfuscated script -> finding",
    "static_obfuscated_script" in types(fs),
    str(types(fs)),
)

# 4) Unrelated string -> no false positive
fs = run(b"this is a normal invoice with no suspicious content whatsoever")
report("unrelated string -> no false positive", len(fs) == 0, str(types(fs)))

# 4b) Long single-char run (e.g. PDF padding) -> NOT a base64 blob (FP guard)
fs = run(b"%PDF-1.4\n" + b"x" * 2000)
report(
    "single-char padding -> no base64 FP",
    "static_base64_blob" not in types(fs),
    str(types(fs)),
)

# 4c) Real base64 blob (mixed upper/lower/digit) -> detected
import base64  # noqa: E402

real_b64 = base64.b64encode(b"base64 test payload 0123456789 ABCDEFGH" * 6)
fs = run(real_b64)
report(
    "real base64 blob -> finding",
    "static_base64_blob" in types(fs),
    str(types(fs)),
)

# 5) Binary/random content -> no crash
fs = run(os.urandom(4096))
report("random binary -> no crash", isinstance(fs, list), "analyzed ok")

# 6) Large file -> bounded read (sample_bytes_read <= limit)
big = b"A" * (settings.static_max_scan_bytes + 1000)
fs = run(big)
read = max((f.evidence.get("sample_bytes_read", 0) for f in fs), default=0)
report(
    "large file -> bounded read",
    read <= settings.static_max_scan_bytes and read < len(big),
    f"read={read} file={len(big)}",
)

# 7) Malformed / non-UTF8 input -> graceful, no crash
fs = run(b"\xff\xfe\x00\x9d" * 512 + b"\x00\x01\x02")
report("malformed input -> graceful", isinstance(fs, list), "analyzed ok")

# 8) M4 never executes the sample (no subprocess / os.system / exec)
import subprocess  # noqa: E402


def _boom(*a, **k):
    raise AssertionError("M4 must never spawn a process")


orig_popen = subprocess.Popen
orig_run = subprocess.run
orig_system = os.system
try:
    subprocess.Popen = _boom
    subprocess.run = _boom
    os.system = _boom
    fs = run(b"DOCSEC_M4_MALWARE_TEST_MARKER")
    ok = "static_test_malware_marker" in types(fs)
finally:
    subprocess.Popen = orig_popen
    subprocess.run = orig_run
    os.system = orig_system
report("M4 never executes sample", ok, "matched without spawning")

# 9) Normalized finding schema (all required fields, correct source)
fs = run(b"DOCSEC_M4_MALWARE_TEST_MARKER")
f = fs[0]
schema_ok = all(
    (
        f.type,
        f.source == "static_analysis",
        f.analyzer_version == settings.ANALYZER_VERSIONS["static"],
        f.severity is not None,
        isinstance(f.confidence, float),
        f.evidence is not None,
        isinstance(f.tags, list),
    )
)
report("normalized finding schema", schema_ok, f"source={f.source}")

# 10) Findings carry evidence the Risk Engine can consume (severity+confidence)
report(
    "risk-engine consumable (sev/conf)",
    f.severity.value in ("info", "low", "medium", "high", "critical") and 0.0 <= f.confidence <= 1.0,
    f"sev={f.severity.value} conf={f.confidence}",
)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
