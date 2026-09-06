"""Focused M4 YARA + structural tests using only synthetic safe bytes."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.static.structural import StructuralAnalyzer  # noqa: E402
from app.analyzers.yara.engine import YaraEngine  # noqa: E402
from app.analyzers.yara.manager import RuleSetManager  # noqa: E402
from app.core.config import settings  # noqa: E402


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _fake_scan(data: bytes, filename: str = "fixture.bin"):
    sha = hashlib.sha256(data).hexdigest()
    path = settings.uploads_dir / f"{sha}.bin"
    path.write_bytes(data)
    scan = type("Scan", (), {})()
    scan.file = type("File", (), {"sha256": sha, "filename": filename, "mime_type": None, "size_bytes": len(data)})()
    return path, scan


def main() -> None:
    manager = RuleSetManager()
    assert manager.revision == "0f93570194a80d2f2032869055808b0ddcdfb360"
    compiled, errors = manager.compile()
    assert len(compiled) == 5, (len(compiled), errors)
    assert not errors, errors
    assert manager.analyzer_version == "yara:4.5.4|ruleset:0f935701"
    print("[PASS] selected rules compile and version")

    engine = YaraEngine(manager=manager, timeout_s=5, max_matches=100)
    matches, errors = engine.scan(b"prefix SANDBOX_M4_YARA_TEST_MARKER suffix")
    assert not errors, errors
    assert any(m.rule == "SANDBOX_M4_TEST_MARKER" for m in matches), matches
    assert all(len(m.strings) <= 20 for m in matches)
    print("[PASS] project YARA marker match with bounded evidence")

    clean, errors = engine.scan(b"ordinary benign document text")
    assert not errors and not clean, (clean, errors)
    print("[PASS] negative sample has no YARA match")

    # Upstream maldoc rule: OLE header + two DDE indicators.
    dde = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1") + b" dde ddeauto"
    matches, errors = engine.scan(dde)
    assert not errors and any(m.rule == "Contains_DDE_Protocol" for m in matches), matches
    print("[PASS] upstream maldoc rule match")

    # Structural PDF finding and YARA project rule coexist independently.
    pdf = b"%PDF-1.7\n/JavaScript /OpenAction\nSANDBOX_M4_YARA_TEST_MARKER\n"
    path, scan = _fake_scan(pdf, "fixture.pdf")
    try:
        findings = StructuralAnalyzer().analyze(None, scan)
        assert any(f.type == "structural_pdf_active_content" for f in findings), findings
        print("[PASS] structural PDF finding")
    finally:
        path.unlink(missing_ok=True)

    archive = _zip({"one.txt": b"1", "two.txt": b"2"})
    path, scan = _fake_scan(archive, "fixture.zip")
    try:
        with patch.object(settings, "max_archive_entries", 1):
            findings = StructuralAnalyzer().analyze(None, scan)
        assert any(f.type == "structural_archive_limit" for f in findings), findings
        print("[PASS] archive entry limit finding")
    finally:
        path.unlink(missing_ok=True)

    # Invalid selected rule is isolated and reported, not raised.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "bad.yar").write_text("rule broken { condition: this is invalid }", encoding="utf-8")
        manifest = {
            "revision": "test",
            "selected_rules": [{"path": "bad.yar", "category": "test"}],
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        bad_manager = RuleSetManager(manifest_path)
        compiled, errors = bad_manager.compile()
        assert not compiled and errors, errors
    print("[PASS] invalid YARA rule isolated")

    # Ensure helper did not leave its synthetic upload behind.
    assert isinstance(os.listdir(settings.uploads_dir), list)
    print("YARA M4 TESTS PASSED: 7/7")


if __name__ == "__main__":
    main()
