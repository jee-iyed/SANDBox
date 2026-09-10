"""Secure File Access state machine (pure, deterministic, fail-closed).

Authorized states are ONLY reachable from a completed scan carrying an
allowable verdict, within the access TTL. Every unknown, failing, running or
expired situation resolves to a non-authorized state:

    REQUESTED -> SCANNING -> {AUTHORIZED | BLOCKED | QUARANTINED | FAILED}
    ANY -> EXPIRED (past expires_at)
    UNKNOWN / ERROR / TIMEOUT -> BLOCKED (never ALLOW)
"""

from __future__ import annotations

from datetime import datetime

from app.db.models import SecureAccessStatus


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def resolve_status(
    *,
    scan_status: str | None,
    verdict: str | None,
    action: str | None,
    expires_at: datetime,
    now: datetime,
    content_available: bool = True,
) -> tuple[SecureAccessStatus, str | None]:
    """Map the current scan state to a secure-access state + policy action.

    ``scan_status`` / ``verdict`` are the raw values of the Scan row
    (``ScanStatus.value`` / ``Verdict.value``). ``action`` is the backend's
    deterministic action value. Pure: no I/O, deliberately testable.
    """
    if now >= _as_utc(expires_at):
        return SecureAccessStatus.EXPIRED, None

    if scan_status in ("queued", "processing"):
        return SecureAccessStatus.SCANNING, None
    if scan_status == "failed":
        return SecureAccessStatus.FAILED, None
    if scan_status == "completed":
        if verdict == "safe":
            if not content_available:
                return SecureAccessStatus.BLOCKED, None
            return SecureAccessStatus.AUTHORIZED, action or "allow"
        if verdict == "sanitized":
            if not content_available:
                return SecureAccessStatus.BLOCKED, None
            return SecureAccessStatus.AUTHORIZED, action or "sanitize"
        if verdict == "suspicious":
            return SecureAccessStatus.BLOCKED, action or "quarantine"
        if verdict == "malicious":
            return SecureAccessStatus.QUARANTINED, action or "reject"
        # not_analyzed / unknown verdict on a completed scan -> fail closed
        return SecureAccessStatus.BLOCKED, action
    # scan row missing or in an unexpected state -> fail closed
    return SecureAccessStatus.FAILED, None


def user_facing_state(status: SecureAccessStatus) -> str:
    """Compact display label used by the frontend content endpoint."""
    return status.value