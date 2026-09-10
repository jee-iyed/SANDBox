"""Secure File Access gateway - unit tests (no live Redis / PostgreSQL needed).

Covers the state machine (fail-closed), filename sanitization, storage path
safety (generated ids, no traversal), the oversize guard, client-source
validation and content-service behavior.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\test_secure_access.py
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402
from app.core.security import safe_join  # noqa: E402
from app.secure_access.client_sources import (  # noqa: E402
    EXTERNAL_REFERENCE_SOURCE,
    parse_source,
)
from app.secure_access.content import SecureContentService  # noqa: E402
from app.secure_access.service import (  # noqa: E402
    deny_reason,
    raise_if_oversized,
    resolve_status,
    sanitize_filename,
)
from app.secure_access.storage import SecureAccessStorage  # noqa: E402

PASS = 0
FAIL = 0

NOW = datetime.now(timezone.utc)
FUTURE = NOW + timedelta(minutes=30)
PAST = NOW - timedelta(minutes=30)


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def run_state_tests():
    # 1) running states -> SCANNING
    for st in ("queued", "processing"):
        status, action = resolve_status(
            scan_status=st, verdict="not_analyzed", action=None,
            expires_at=FUTURE, now=NOW,
        )
        report(f"scan {st} -> SCANNING", status.value == "scanning" and action is None, status.value)

    # 2) failed scan -> FAILED
    status, _ = resolve_status(
        scan_status="failed", verdict="not_analyzed", action=None, expires_at=FUTURE, now=NOW
    )
    report("failed scan -> FAILED", status.value == "failed", status.value)

    # 3) SAFE -> AUTHORIZED (policy allow)
    status, action = resolve_status(
        scan_status="completed", verdict="safe", action="allow",
        expires_at=FUTURE, now=NOW,
    )
    report("SAFE -> AUTHORIZED", status.value == "authorized" and action == "allow", f"{status.value}/{action}")

    # 4) SANITIZED -> AUTHORIZED (policy sanitize)
    status, action = resolve_status(
        scan_status="completed", verdict="sanitized", action="sanitize",
        expires_at=FUTURE, now=NOW,
    )
    report("SANITIZED -> AUTHORIZED", status.value == "authorized" and action == "sanitize", f"{status.value}/{action}")

    # 5) SUSPICIOUS -> BLOCKED
    status, _ = resolve_status(
        scan_status="completed", verdict="suspicious", action="quarantine",
        expires_at=FUTURE, now=NOW,
    )
    report("SUSPICIOUS -> BLOCKED", status.value == "blocked", status.value)

    # 6) MALICIOUS -> QUARANTINED
    status, _ = resolve_status(
        scan_status="completed", verdict="malicious", action="reject",
        expires_at=FUTURE, now=NOW,
    )
    report("MALICIOUS -> QUARANTINED", status.value == "quarantined", status.value)

    # 7) unknown verdict on completed -> BLOCKED (fail closed, NEVER allow)
    status, _ = resolve_status(
        scan_status="completed", verdict="not_analyzed", action=None,
        expires_at=FUTURE, now=NOW,
    )
    report("unknown verdict -> BLOCKED", status.value == "blocked", status.value)

    # 8) expired even when safe -> EXPIRED
    status, _ = resolve_status(
        scan_status="completed", verdict="safe", action="allow",
        expires_at=PAST, now=NOW,
    )
    report("expired SAFE -> EXPIRED", status.value == "expired", status.value)

    # 9) content unavailable + safe -> BLOCKED (fail closed)
    status, _ = resolve_status(
        scan_status="completed", verdict="safe", action="allow",
        expires_at=FUTURE, now=NOW, content_available=False,
    )
    report("content unavailable -> BLOCKED", status.value == "blocked", status.value)

    # 10) missing scan row -> FAILED
    status, _ = resolve_status(
        scan_status=None, verdict=None, action=None, expires_at=FUTURE, now=NOW
    )
    report("missing scan -> FAILED", status.value == "failed", status.value)

    # 11) deny reasons map every non-authorized state (never empty)
    for state in ("scanning", "blocked", "quarantined", "failed", "expired", "requested"):
        report(f"deny_reason({state}) fail-closed", deny_reason(state).startswith("Access denied"), deny_reason(state))


def run_filename_tests():
    pairs = [
        ("../../evil.sh", "evil.sh"),
        (r"..\..\x.txt", "x.txt"),
        (r"C:\fakepath\report.pdf", "report.pdf"),
        ("../a/b/c/ledger.xlsx", "ledger.xlsx"),
        ("normal.pdf", "normal.pdf"),
        (None, "unnamed"),
        ("", "unnamed"),
        ("..", "unnamed"),
    ]
    for raw, expected in pairs:
        got = sanitize_filename(raw)
        report(f"sanitize_filename({raw!r})", got == expected, got)

    long = "x" * 600
    got = sanitize_filename(long)
    report("sanitize_filename caps at 512", len(got) == 512, str(len(got)))

    ctrl = "a\x00b\x01c.pdf"
    got = sanitize_filename(ctrl)
    report("sanitize_filename strips control chars", "\x00" not in got and "\x01" not in got, got)


def run_storage_tests():
    with tempfile.TemporaryDirectory() as tmp:
        st = SecureAccessStorage(root=Path(tmp))
        access_id = uuid.uuid4()

        # 12) writes use the generated id only; user filename never in path
        ref = st.write_pending(access_id, b"PASS-DATA")
        expected = Path(tmp) / "pending" / f"{access_id}.bin"
        file_ok = ref == f"pending/{access_id}.bin" and expected.exists() and expected.read_bytes() == b"PASS-DATA"
        report("pending write uses generated id", file_ok, ref)

        # 13) transition pending -> authorized moves the file
        ref2 = st.apply_transition(access_id, ref, "authorized")
        dest = Path(tmp) / "authorized" / f"{access_id}.bin"
        report(
            "transition -> authorized",
            ref2 == f"authorized/{access_id}.bin" and dest.exists() and not expected.exists(),
            ref2,
        )

        # 14) transition -> quarantine isolates the file
        ref3 = st.apply_transition(access_id, ref2, "quarantined")
        q = Path(tmp) / "quarantine" / f"{access_id}.bin"
        report(
            "transition -> quarantine",
            ref3 == f"quarantine/{access_id}.bin" and q.exists() and not dest.exists(),
            ref3,
        )

        # 15) transition failed/expired removes the file
        ref4 = st.apply_transition(access_id, ref3, "expired")
        report("transition expired removes file", ref4 == ref3 and not q.exists(), ref4)

        # 16) path traversal in a stored reference is rejected
        traversal_ok = False
        try:
            st._abs("pending/../../../etc/passwd")
        except ValueError:
            traversal_ok = True
        report("stored path traversal rejected", traversal_ok)

        # 17) safe_join standalone rejects traversal too
        try:
            safe_join(Path(tmp), "pending", "..", "..", "win.ini")
            traversal2 = False
        except ValueError:
            traversal2 = True
        report("safe_join traversal rejected", traversal2)


def run_oversize_tests():
    prev = settings.max_upload_mb
    settings.max_upload_mb = 1
    try:
        oversize_ok = False
        try:
            raise_if_oversized(2 * 1024 * 1024 + 1)
        except ValueError:
            oversize_ok = True
        report("oversized file rejected", oversize_ok)

        ok_small = True
        try:
            raise_if_oversized(512 * 1024)
        except ValueError:
            ok_small = False
        report("small file accepted", ok_small)
    finally:
        settings.max_upload_mb = prev


def run_source_tests():
    src = parse_source(source_type="upload")
    report("upload source parsed", src.source_type == "upload" and src.source_identifier is None)

    src = parse_source(source_type=EXTERNAL_REFERENCE_SOURCE, source_token="tok-abc")
    report(
        "external_reference source parsed",
        src.source_type == EXTERNAL_REFERENCE_SOURCE,
        src.source_type,
    )

    bad_type = False
    try:
        parse_source(source_type="ftp", source_token="x")
    except ValueError:
        bad_type = True
    report("unsupported source_type rejected", bad_type)

    missing_token = False
    try:
        parse_source(source_type=EXTERNAL_REFERENCE_SOURCE, source_token=None)
    except ValueError:
        missing_token = True
    report("external_reference without token rejected", missing_token)


def run_content_tests():
    svc = SecureContentService()
    delivery = svc.delivery_response("authorized")
    report(
        "content service is a controlled placeholder",
        delivery["authorized"] is True
        and delivery["content_kind"] == "placeholder"
        and "preview is not yet configured" in delivery["message"],
        delivery["message"],
    )


def main():
    run_state_tests()
    run_filename_tests()
    run_storage_tests()
    run_oversize_tests()
    run_source_tests()
    run_content_tests()
    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()